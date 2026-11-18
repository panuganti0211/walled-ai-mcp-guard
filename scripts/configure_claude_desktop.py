"""Safe backup-first Claude Desktop Windows configuration helper for Walled AI MCP Guard.

Detects Claude Desktop's configuration path on Windows (both standard Roaming AppData
and Microsoft Store / MSIX package paths), backs up any existing config file before
writing, preserves all unrelated `mcpServers` entries, creates the explicit sandbox
directory, and configures Walled AI MCP Guard with absolute paths and zero secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.config import load_config


def detect_claude_desktop_config_path() -> tuple[Path, bool]:
    """Detect Claude Desktop's Windows config path and whether Claude Desktop appears installed.

    Returns:
        (config_path, claude_installed_flag)
    """
    local_app_data = Path(os.environ.get("LOCALAPPDATA", ""))
    app_data = Path(os.environ.get("APPDATA", ""))

    # 1. Check Microsoft Store / MSIX package location (Windows 11)
    packages_dir = local_app_data / "Packages"
    if packages_dir.is_dir():
        for pkg in sorted(packages_dir.glob("Claude_*")):
            msix_cfg = pkg / "LocalCache" / "Roaming" / "Claude" / "claude_desktop_config.json"
            if msix_cfg.parent.exists() or pkg.exists():
                return msix_cfg, True

    # 2. Check standard Anthropic Claude Desktop Windows installer paths
    classic_app = local_app_data / "AnthropicClaude"
    classic_cfg = app_data / "Claude" / "claude_desktop_config.json"
    installed = classic_app.exists() or classic_cfg.parent.exists()
    return classic_cfg, installed


def build_local_guard_servers_config(
    *,
    project_root: Path,
    python_exe: Path,
    sandbox_dir: Path,
    default_server: str = "filesystem-sandbox",
) -> dict[str, Any]:
    """Build a validated local config/servers.json payload confined strictly to sandbox_dir."""
    resolved_root = project_root.resolve()
    resolved_python = python_exe.resolve()
    resolved_sandbox = sandbox_dir.resolve()

    return {
        "default_server": default_server,
        "approval_timeout_seconds": 120,
        "audit_log_path": str(resolved_root / "logs" / "audit.jsonl"),
        "servers": {
            "filesystem-sandbox": {
                "description": (
                    "Scoped filesystem MCP server restricted strictly to the explicit sandbox directory"
                ),
                "transport": "stdio",
                "command": "npx",
                "args": [
                    "-y",
                    "@modelcontextprotocol/server-filesystem",
                    str(resolved_sandbox),
                ],
                "sandbox_dir": str(resolved_sandbox),
                "env": {},
                "enabled": True,
            },
            "safe-test-server": {
                "description": (
                    "Built-in local safe test MCP server restricted strictly to the sandbox directory"
                ),
                "transport": "stdio",
                "command": str(resolved_python),
                "args": [
                    "-m",
                    "tests.test_mcp_server",
                    "--sandbox-dir",
                    str(resolved_sandbox),
                ],
                "cwd": str(resolved_root),
                "sandbox_dir": str(resolved_sandbox),
                "env": {},
                "enabled": True,
            },
        },
    }


def build_claude_mcp_server_entry(
    *,
    project_root: Path,
    python_exe: Path,
    guard_config_path: Path,
    upstream_server_name: str = "filesystem-sandbox",
    broker_file: Path | None = None,
) -> dict[str, Any]:
    """Build the `mcpServers` entry for Claude Desktop pointing at StdioMCPProxy."""
    args = [
        "-m",
        "app.proxy.stdio_proxy",
        "--config",
        str(guard_config_path.resolve()),
        "--server",
        upstream_server_name,
        "--use-desktop-guard",
    ]
    if broker_file is not None:
        args.extend(["--broker-file", str(broker_file.resolve())])

    return {
        "command": str(python_exe.resolve()),
        "args": args,
        "env": {
            "PYTHONPATH": str(project_root.resolve()),
            "PYTHONUTF8": "1",
        },
    }


def backup_and_update_claude_config(
    *,
    claude_config_path: Path,
    entry_name: str,
    server_entry: dict[str, Any],
) -> tuple[Path | None, dict[str, Any]]:
    """Safely back up any existing Claude Desktop config and merge our mcpServers entry.

    Preserves all unrelated top-level keys and unrelated `mcpServers` entries.
    """
    backup_path: Path | None = None
    existing_data: dict[str, Any] = {}

    if claude_config_path.is_file():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = claude_config_path.with_name(
            f"{claude_config_path.name}.bak.{stamp}"
        )
        shutil.copy2(claude_config_path, backup_path)

        raw = json.loads(claude_config_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(
                f"Existing Claude Desktop config must be a JSON object: {claude_config_path}"
            )
        existing_data = raw

    mcp_servers = existing_data.get("mcpServers")
    if mcp_servers is None:
        mcp_servers = {}
    elif not isinstance(mcp_servers, dict):
        raise ValueError("Existing 'mcpServers' field must be a JSON object.")

    updated_servers = dict(mcp_servers)
    updated_servers[entry_name] = server_entry
    updated_data = dict(existing_data)
    updated_data["mcpServers"] = updated_servers

    claude_config_path.parent.mkdir(parents=True, exist_ok=True)
    claude_config_path.write_text(
        json.dumps(updated_data, indent=2) + "\n", encoding="utf-8"
    )
    return backup_path, updated_data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Configure Claude Desktop on Windows to route MCP calls through Walled AI MCP Guard."
    )
    parser.add_argument(
        "--server",
        default="filesystem-sandbox",
        choices=["filesystem-sandbox", "safe-test-server"],
        help="Upstream MCP server configured in config/servers.json (default: filesystem-sandbox).",
    )
    parser.add_argument(
        "--entry-name",
        default="walled-ai-mcp-guard",
        help="Server name registered under Claude Desktop's mcpServers (default: walled-ai-mcp-guard).",
    )
    parser.add_argument(
        "--sandbox-dir",
        default=str(ROOT_DIR / "sandbox_files"),
        help="Explicit sandbox directory exposed to the upstream filesystem server.",
    )
    parser.add_argument(
        "--claude-config",
        default=None,
        help="Optional explicit path to claude_desktop_config.json (auto-detected if omitted).",
    )
    parser.add_argument(
        "--guard-config",
        default=str(ROOT_DIR / "config" / "servers.json"),
        help="Path to write validated local Guard server config (default: config/servers.json).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated configurations without writing files.",
    )
    args = parser.parse_args(argv)

    python_exe = ROOT_DIR / ".venv" / "Scripts" / "python.exe"
    if not python_exe.is_file():
        python_exe = Path(sys.executable)

    sandbox_dir = Path(args.sandbox_dir).resolve()
    guard_config_path = Path(args.guard_config).resolve()

    if args.claude_config:
        claude_config_path = Path(args.claude_config).resolve()
        claude_installed = claude_config_path.parent.exists()
    else:
        claude_config_path, claude_installed = detect_claude_desktop_config_path()

    servers_payload = build_local_guard_servers_config(
        project_root=ROOT_DIR,
        python_exe=python_exe,
        sandbox_dir=sandbox_dir,
        default_server=args.server,
    )
    claude_entry = build_claude_mcp_server_entry(
        project_root=ROOT_DIR,
        python_exe=python_exe,
        guard_config_path=guard_config_path,
        upstream_server_name=args.server,
    )

    if args.dry_run:
        print("Detected Claude Desktop installed:", claude_installed)
        print("Target claude_desktop_config.json:", claude_config_path)
        print("\n--- Generated config/servers.json ---")
        print(json.dumps(servers_payload, indent=2))
        print("\n--- Generated mcpServers entry ---")
        print(json.dumps({args.entry_name: claude_entry}, indent=2))
        return 0

    sandbox_dir.mkdir(parents=True, exist_ok=True)
    guard_config_path.parent.mkdir(parents=True, exist_ok=True)
    guard_config_path.write_text(
        json.dumps(servers_payload, indent=2) + "\n", encoding="utf-8"
    )
    # Validate written Guard config strictly via Pydantic loader
    load_config(guard_config_path)

    backup_path, _ = backup_and_update_claude_config(
        claude_config_path=claude_config_path,
        entry_name=args.entry_name,
        server_entry=claude_entry,
    )

    print(f"Sandbox directory ready:     {sandbox_dir}")
    print(f"Guard config written:        {guard_config_path}")
    print(f"Claude Desktop config saved: {claude_config_path}")
    if backup_path is not None:
        print(f"Previous config backed up:   {backup_path}")
    if not claude_installed:
        print(
            "\nNOTE: Claude Desktop installation was not detected automatically on this machine.\n"
            "Install Claude Desktop from https://claude.ai/download, then restart Claude Desktop\n"
            "after starting Walled AI MCP Guard (run.py)."
        )
    else:
        print(
            "\nNext steps:\n"
            "  1. Start Walled AI MCP Guard: D:\\walled-ai-mcp-guard\\.venv\\Scripts\\python.exe run.py\n"
            "  2. Fully quit Claude Desktop (including the system tray icon) and relaunch it."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
