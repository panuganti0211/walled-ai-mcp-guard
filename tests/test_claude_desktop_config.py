"""Phase 6 tests for Claude Desktop Windows configuration safety and launch compatibility.

Note: These automated tests verify configuration backup/merge safety and simulate
Claude Desktop's exact STDIO launch environment (command, args, env, foreign cwd).
Live manual verification inside the actual Claude Desktop GUI is documented in README.md.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError
from PySide6.QtWidgets import QApplication

from app.config import load_config
from app.main import GuardController
from app.models.request import (
    ERR_AUTHORIZATION_DENIED,
    ERR_AUTHORIZATION_SYSTEM_FAILURE,
)
from app.ui.main_window import MainWindow
from scripts.configure_claude_desktop import (
    backup_and_update_claude_config,
    build_claude_mcp_server_entry,
    build_local_guard_servers_config,
)


def test_backup_and_update_preserves_unrelated_mcp_servers_and_keys(
    tmp_path: Path,
) -> None:
    """Updating claude_desktop_config.json creates a backup and preserves unrelated entries."""
    claude_cfg = tmp_path / "Claude" / "claude_desktop_config.json"
    claude_cfg.parent.mkdir(parents=True)

    original = {
        "globalShortcut": "Ctrl+Space",
        "mcpServers": {
            "existing-unrelated-server": {
                "command": "node",
                "args": ["C:\\tools\\other_server.js"],
            }
        },
    }
    original_text = json.dumps(original, indent=2)
    claude_cfg.write_text(original_text, encoding="utf-8")

    sandbox_dir = tmp_path / "sandbox_files"
    guard_cfg = tmp_path / "servers.json"
    guard_payload = build_local_guard_servers_config(
        project_root=Path.cwd(),
        python_exe=Path(sys.executable),
        sandbox_dir=sandbox_dir,
        default_server="filesystem-sandbox",
    )
    guard_cfg.write_text(json.dumps(guard_payload, indent=2), encoding="utf-8")
    # Confirm generated Guard config passes strict Pydantic security validation
    loaded = load_config(guard_cfg)
    assert loaded.default_server == "filesystem-sandbox"
    assert loaded.servers["filesystem-sandbox"].sandbox_dir == str(sandbox_dir.resolve())

    entry = build_claude_mcp_server_entry(
        project_root=Path.cwd(),
        python_exe=Path(sys.executable),
        guard_config_path=guard_cfg,
        upstream_server_name="filesystem-sandbox",
    )

    backup_path, updated = backup_and_update_claude_config(
        claude_config_path=claude_cfg,
        entry_name="walled-ai-mcp-guard",
        server_entry=entry,
    )

    # Backup must exist with exact original contents
    assert backup_path is not None and backup_path.is_file()
    assert backup_path.read_text(encoding="utf-8") == original_text

    # Unrelated keys and unrelated MCP servers MUST be preserved
    assert updated["globalShortcut"] == "Ctrl+Space"
    assert "existing-unrelated-server" in updated["mcpServers"]
    assert updated["mcpServers"]["existing-unrelated-server"] == original["mcpServers"]["existing-unrelated-server"]

    # New entry uses absolute paths, --use-desktop-guard, PYTHONPATH, and zero secrets
    guard_entry = updated["mcpServers"]["walled-ai-mcp-guard"]
    assert Path(guard_entry["command"]).is_absolute()
    assert "--use-desktop-guard" in guard_entry["args"]
    assert "PYTHONPATH" in guard_entry["env"]
    assert "token" not in json.dumps(guard_entry).lower()
    assert "secret" not in json.dumps(guard_entry).lower()


def test_claude_desktop_launch_env_from_foreign_cwd_scenarios_a_through_e(
    tmp_path: Path,
) -> None:
    """Verify exact Claude Desktop config launch from a foreign cwd (Tests A-E)."""
    app = QApplication.instance() or QApplication(["claude-desktop-compat-test"])
    sandbox_dir = tmp_path / "sandbox_files"
    sandbox_dir.mkdir()
    foreign_cwd = tmp_path / "SimulatedAnthropicClaudeAppDir"
    foreign_cwd.mkdir()

    broker_file = tmp_path / "broker.json"
    guard_cfg = tmp_path / "servers.json"
    guard_payload = build_local_guard_servers_config(
        project_root=Path.cwd(),
        python_exe=Path(sys.executable),
        sandbox_dir=sandbox_dir,
        default_server="safe-test-server",
    )
    guard_cfg.write_text(json.dumps(guard_payload, indent=2), encoding="utf-8")

    entry = build_claude_mcp_server_entry(
        project_root=Path.cwd(),
        python_exe=Path(sys.executable),
        guard_config_path=guard_cfg,
        upstream_server_name="safe-test-server",
        broker_file=broker_file,
    )

    controller = GuardController(
        audit_log_path=tmp_path / "audit_claude_compat.jsonl",
        timeout_seconds=30.0,
        configured_server_summary="Configured default: safe-test-server",
        broker_runtime_file=broker_file,
    )
    window = MainWindow(controller=controller, minimize_to_tray=False)

    stage_e_ready = threading.Event()
    proceed_to_stage_e = threading.Event()
    outcomes: dict[str, Any] = {}

    def _run_simulated_claude_client() -> None:
        async def _inner() -> None:
            # Launch with EXACT Claude Desktop config fields from a foreign cwd!
            params = StdioServerParameters(
                command=entry["command"],
                args=entry["args"],
                env=entry["env"],
                cwd=str(foreign_cwd),
            )
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as session:
                    # TEST A: Initialization & Tool Discovery
                    init = await session.initialize()
                    tools = await session.list_tools()
                    outcomes["server_name"] = init.server_info.name
                    outcomes["tools"] = {
                        t.name: (bool(t.description), bool(t.input_schema))
                        for t in tools.tools
                    }

                    # TEST B: Allow
                    r_allow = await session.call_tool(
                        "create_test_file",
                        {"filename": "claude_allowed.txt", "content": "Approved via popup"},
                    )
                    outcomes["allow_is_error"] = r_allow.is_error

                    # TEST C: Block
                    try:
                        await session.call_tool(
                            "create_test_file",
                            {"filename": "claude_blocked.txt", "content": "MUST_NOT_EXIST"},
                        )
                        outcomes["block_code"] = 0
                    except MCPError as exc:
                        outcomes["block_code"] = exc.error.code

                    # TEST D: Multiple simultaneous requests
                    t1 = asyncio.create_task(
                        session.call_tool(
                            "create_test_file",
                            {"filename": "claude_multi_allow.txt", "content": "ok-multi"},
                        )
                    )
                    t2 = asyncio.create_task(
                        session.call_tool(
                            "create_test_file",
                            {"filename": "claude_multi_block.txt", "content": "no-multi"},
                        )
                    )
                    m_res1, m_res2 = await asyncio.gather(t1, t2, return_exceptions=True)
                    outcomes["multi_allow_ok"] = (
                        not isinstance(m_res1, Exception) and not m_res1.is_error
                    )
                    outcomes["multi_block_code"] = (
                        m_res2.error.code if isinstance(m_res2, MCPError) else 0
                    )

                    # Signal main thread to shut down Walled AI before TEST E
                    stage_e_ready.set()
                    while not proceed_to_stage_e.is_set():
                        await asyncio.sleep(0.02)

                    # TEST E: Walled AI closed -> MUST fail closed
                    try:
                        await session.call_tool(
                            "create_test_file",
                            {"filename": "claude_after_shutdown.txt", "content": "nope"},
                        )
                        outcomes["shutdown_code"] = 0
                    except MCPError as exc:
                        outcomes["shutdown_code"] = exc.error.code

        asyncio.run(_inner())

    def _pump_until(pred, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            app.processEvents()
            if pred():
                return
            time.sleep(0.02)
        app.processEvents()
        assert pred(), "Timed out waiting for Qt UI state."

    client_thread = threading.Thread(target=_run_simulated_claude_client, daemon=True)
    try:
        controller.start_monitoring_sync(timeout=5.0)
        client_thread.start()

        # TEST B: Allow popup
        _pump_until(lambda: len(window.active_popups) == 1)
        p_allow = next(iter(window.active_popups.values()))
        assert "claude_allowed.txt" in p_allow.parameters_box.toPlainText()
        p_allow.allow_button.click()
        _pump_until(lambda: p_allow.internal_id not in window.active_popups)

        # TEST C: Block popup
        _pump_until(lambda: len(window.active_popups) == 1)
        p_block = next(iter(window.active_popups.values()))
        assert "claude_blocked.txt" in p_block.parameters_box.toPlainText()
        p_block.block_button.click()
        _pump_until(lambda: p_block.internal_id not in window.active_popups)

        # TEST D: 2 simultaneous popups
        _pump_until(lambda: len(window.active_popups) == 2)
        popups = list(window.active_popups.values())
        pm_allow = next(p for p in popups if "claude_multi_allow.txt" in p.parameters_box.toPlainText())
        pm_block = next(p for p in popups if "claude_multi_block.txt" in p.parameters_box.toPlainText())
        pm_block.block_button.click()
        pm_allow.allow_button.click()
        _pump_until(lambda: stage_e_ready.is_set())

        # TEST E: Shut down Walled AI desktop app while proxy stays connected
        window.prepare_for_exit()
        controller.shutdown_sync(timeout=5.0)
        proceed_to_stage_e.set()

        client_thread.join(timeout=15.0)
        assert not client_thread.is_alive()

        # Assert all 5 scenarios
        assert "walled-ai-mcp-guard" in outcomes["server_name"]
        assert "create_test_file" in outcomes["tools"]
        assert outcomes["tools"]["create_test_file"] == (True, True)
        assert outcomes["allow_is_error"] is False
        assert outcomes["block_code"] == ERR_AUTHORIZATION_DENIED
        assert outcomes["multi_allow_ok"] is True
        assert outcomes["multi_block_code"] == ERR_AUTHORIZATION_DENIED
        assert outcomes["shutdown_code"] == ERR_AUTHORIZATION_SYSTEM_FAILURE

        # Disk proofs
        assert (sandbox_dir / "claude_allowed.txt").read_text(encoding="utf-8") == "Approved via popup"
        assert not (sandbox_dir / "claude_blocked.txt").exists()
        assert (sandbox_dir / "claude_multi_allow.txt").read_text(encoding="utf-8") == "ok-multi"
        assert not (sandbox_dir / "claude_multi_block.txt").exists()
        assert not (sandbox_dir / "claude_after_shutdown.txt").exists()
    finally:
        window.close()
        controller.shutdown_sync()
