"""Safe local test MCP server built with official MCP Python SDK 2.3.0.

All filesystem operations are strictly confined to a configured sandbox directory.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from mcp.server import MCPServer

from app.config import resolve_sandbox_path


def create_safe_test_server(sandbox_dir: str | Path) -> MCPServer:
    """Create an MCPServer instance whose file tools are restricted to sandbox_dir."""
    sandbox_root = Path(sandbox_dir).resolve()
    sandbox_root.mkdir(parents=True, exist_ok=True)

    server = MCPServer(
        name="walled-ai-safe-test-server",
        version="1.0.0",
        instructions="Safe local MCP test server restricted strictly to its sandbox directory.",
    )

    @server.tool(
        name="get_current_time",
        description="Return the current UTC date and time in ISO-8601 format.",
    )
    def get_current_time() -> str:
        return datetime.now(timezone.utc).isoformat()

    @server.tool(
        name="read_test_file",
        description="Read a UTF-8 text file located inside the configured sandbox directory.",
    )
    def read_test_file(filename: str) -> str:
        target = resolve_sandbox_path(sandbox_root, filename)
        if not target.exists():
            raise FileNotFoundError(f"Sandbox file does not exist: {filename}")
        if not target.is_file():
            raise IsADirectoryError(f"Sandbox path is not a file: {filename}")
        return target.read_text(encoding="utf-8")

    @server.tool(
        name="create_test_file",
        description="Create or overwrite a UTF-8 text file inside the configured sandbox directory.",
    )
    def create_test_file(filename: str, content: str) -> str:
        if not filename or not filename.strip():
            raise ValueError("filename must be non-empty.")
        target = resolve_sandbox_path(sandbox_root, filename)
        if target == sandbox_root:
            raise ValueError("Cannot overwrite sandbox root directory as a file.")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        rel = target.relative_to(sandbox_root).as_posix()
        return json.dumps(
            {
                "status": "created",
                "filename": rel,
                "bytes_written": len(content.encode("utf-8")),
            }
        )

    @server.tool(
        name="list_test_directory",
        description="List files and subdirectories inside the configured sandbox directory.",
    )
    def list_test_directory(subpath: str = "") -> str:
        target = resolve_sandbox_path(sandbox_root, subpath)
        if not target.exists():
            raise FileNotFoundError(f"Sandbox directory does not exist: {subpath}")
        if not target.is_dir():
            raise NotADirectoryError(f"Sandbox path is not a directory: {subpath}")
        entries = sorted(
            [
                {
                    "name": item.name,
                    "type": "dir" if item.is_dir() else "file",
                }
                for item in target.iterdir()
            ],
            key=lambda e: e["name"],
        )
        return json.dumps({"directory": subpath or ".", "entries": entries})

    @server.resource(
        "sandbox://info",
        name="sandbox_info",
        description="Metadata describing the active test sandbox.",
        mime_type="application/json",
    )
    def sandbox_info() -> str:
        return json.dumps(
            {
                "server": "walled-ai-safe-test-server",
                "sandbox_active": True,
            }
        )

    @server.prompt(
        name="sandbox_summary",
        description="Generate a safe prompt template summarizing sandbox status.",
    )
    def sandbox_summary(topic: str = "files") -> str:
        return f"Summarize the current safe test sandbox state for topic: {topic}."

    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Walled AI Safe Local Test MCP Server")
    parser.add_argument(
        "--sandbox-dir",
        default=os.environ.get("MCP_GUARD_TEST_SANDBOX_DIR"),
        help="Explicit sandbox directory for file operations.",
    )
    args = parser.parse_args(argv)

    sandbox_dir = args.sandbox_dir or tempfile.mkdtemp(prefix="mcp_guard_sandbox_")
    server = create_safe_test_server(sandbox_dir)
    # Run over official MCP STDIO transport (stdout reserved strictly for JSON-RPC)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
