"""Interactive MCP STDIO client for manually testing Walled AI MCP Guard end-to-end.

Spawns the real `app.proxy.stdio_proxy --use-desktop-guard` wrapping the safe
local `tests.test_mcp_server` inside a temporary sandbox directory, discovers
tools, and invokes an MCP tool call that triggers the live PySide6 approval popup.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError


async def run_demo(
    *,
    tool_name: str,
    arguments: dict,
    sandbox_dir: Path,
    broker_file: str | None = None,
) -> int:
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = sandbox_dir / "_demo_servers.json"
    cfg_path.write_text(
        json.dumps(
            {
                "default_server": "safe-test-server",
                "approval_timeout_seconds": 120,
                "servers": {
                    "safe-test-server": {
                        "description": "Safe local test MCP server",
                        "transport": "stdio",
                        "command": sys.executable,
                        "args": [
                            "-m",
                            "tests.test_mcp_server",
                            "--sandbox-dir",
                            str(sandbox_dir),
                        ],
                        "enabled": True,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    proxy_args = [
        "-m",
        "app.proxy.stdio_proxy",
        "--config",
        str(cfg_path),
        "--server",
        "safe-test-server",
        "--use-desktop-guard",
    ]
    if broker_file:
        proxy_args.extend(["--broker-file", broker_file])

    params = StdioServerParameters(command=sys.executable, args=proxy_args)
    print(f"[Demo Client] Sandbox directory: {sandbox_dir}")
    print("[Demo Client] Connecting to StdioMCPProxy -> safe-test-server...")

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_res = await session.initialize()
            print(f"[Demo Client] Connected to proxy: {init_res.server_info.name}")

            tools_res = await session.list_tools()
            print(
                "[Demo Client] Discovered tools:",
                ", ".join(t.name for t in tools_res.tools),
            )

            print(
                f"[Demo Client] Calling tool '{tool_name}' with args={arguments} ..."
            )
            print(
                "[Demo Client] Waiting for your decision in the Walled AI MCP Guard popup..."
            )
            try:
                result = await session.call_tool(tool_name, arguments)
                text = result.content[0].text if result.content else ""
                print(f"[Demo Client] ALLOWED & EXECUTED (is_error={result.is_error}): {text}")
                return 0
            except MCPError as exc:
                print(
                    f"[Demo Client] DENIED/ERROR (code={exc.error.code}): {exc.error.message}"
                )
                return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Send a real MCP STDIO tool call through Walled AI MCP Guard."
    )
    parser.add_argument(
        "--tool",
        default="create_test_file",
        choices=[
            "get_current_time",
            "create_test_file",
            "read_test_file",
            "list_test_directory",
        ],
        help="Safe test tool to invoke.",
    )
    parser.add_argument(
        "--filename",
        default="approved_demo.txt",
        help="Filename argument for create_test_file / read_test_file.",
    )
    parser.add_argument(
        "--content",
        default="Created after explicit user approval in Walled AI MCP Guard.",
        help="File content for create_test_file.",
    )
    parser.add_argument(
        "--sandbox-dir",
        default=str(Path(tempfile.gettempdir()) / "walled_ai_mcp_guard_demo"),
        help="Isolated temporary sandbox directory.",
    )
    parser.add_argument(
        "--broker-file",
        default=None,
        help="Optional explicit broker runtime file path.",
    )
    args = parser.parse_args(argv)

    tool_args: dict = {}
    if args.tool == "create_test_file":
        tool_args = {"filename": args.filename, "content": args.content}
    elif args.tool == "read_test_file":
        tool_args = {"filename": args.filename}
    elif args.tool == "list_test_directory":
        tool_args = {"subpath": ""}

    return asyncio.run(
        run_demo(
            tool_name=args.tool,
            arguments=tool_args,
            sandbox_dir=Path(args.sandbox_dir),
            broker_file=args.broker_file,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
