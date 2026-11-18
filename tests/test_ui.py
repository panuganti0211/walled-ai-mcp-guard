"""Phase 4 automated PySide6 GUI, asyncio bridge, and real end-to-end MCP tests."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

# Use offscreen Qt platform during automated pytest runs so tests stay headless and deterministic.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import httpx
import mcp.types as types
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError
from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent, QKeyEvent
from PySide6.QtWidgets import QApplication

from app.main import GuardController
from app.models.request import (
    ERR_AUTHORIZATION_CANCELLED,
    ERR_AUTHORIZATION_DENIED,
    InterceptedRequest,
    RequestStatus,
)
from app.ui.approval_popup import ApprovalPopup
from app.ui.main_window import MainWindow
from app.ui.system_tray import GuardSystemTray


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication(["walled-ai-mcp-guard-tests"])
    return app  # type: ignore[return-value]


def _pump_qt_until(
    qapp: QApplication,
    predicate,
    *,
    timeout: float = 10.0,
    interval: float = 0.02,
) -> None:
    """Process Qt events without blocking until predicate() becomes truthy."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        qapp.processEvents()
        if predicate():
            return
        time.sleep(interval)
    qapp.processEvents()
    assert predicate(), f"Timed out after {timeout}s waiting for Qt condition."


def _write_proxy_config(tmp_path: Path, sandbox: Path) -> Path:
    sandbox.mkdir(parents=True, exist_ok=True)
    cfg = tmp_path / "servers.json"
    cfg.write_text(
        json.dumps(
            {
                "default_server": "safe-test-server",
                "approval_timeout_seconds": 30,
                "servers": {
                    "safe-test-server": {
                        "description": "Safe local test MCP server",
                        "transport": "stdio",
                        "command": sys.executable,
                        "args": [
                            "-m",
                            "tests.test_mcp_server",
                            "--sandbox-dir",
                            str(sandbox),
                        ],
                        "enabled": True,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return cfg


def _make_stdio_proxy_params(cfg_path: Path, broker_file: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "app.proxy.stdio_proxy",
            "--config",
            str(cfg_path),
            "--server",
            "safe-test-server",
            "--use-desktop-guard",
            "--broker-file",
            str(broker_file),
        ],
    )


# ======================================================================
# 1. Dashboard Initialization & System Tray
# ======================================================================


def test_dashboard_initialization_and_monitoring_controls(
    qapp: QApplication, tmp_path: Path
) -> None:
    controller = GuardController(
        audit_log_path=tmp_path / "audit.jsonl",
        timeout_seconds=30.0,
        configured_server_summary="Configured default: safe-test-server",
        broker_runtime_file=tmp_path / "broker.json",
    )
    window = MainWindow(controller=controller, minimize_to_tray=False)
    try:
        assert window.windowTitle() == "Walled AI MCP Guard"
        assert window.total_count_label.text() == "0"
        assert window.approved_count_label.text() == "0"
        assert window.blocked_count_label.text() == "0"
        assert window.pending_count_label.text() == "0"
        assert window.protection_badge.text() == "STOPPED"
        assert window.history_table.rowCount() == 0

        # Start monitoring via controller and verify UI transitions to PROTECTED
        endpoint = controller.start_monitoring_sync(timeout=5.0)
        assert endpoint.startswith("http://127.0.0.1:")
        _pump_qt_until(qapp, lambda: window.protection_badge.text() == "PROTECTED")
        assert window.start_button.isEnabled() is False
        assert window.stop_button.isEnabled() is True

        # Stop monitoring and verify UI transitions back to STOPPED
        controller.stop_monitoring().result(timeout=5.0)
        _pump_qt_until(qapp, lambda: window.protection_badge.text() == "STOPPED")
        assert window.start_button.isEnabled() is True
        assert window.stop_button.isEnabled() is False
    finally:
        window.prepare_for_exit()
        window.close()
        controller.shutdown_sync()


def test_system_tray_initialization_and_actions(qapp: QApplication) -> None:
    events: list[str] = []
    tray = GuardSystemTray(
        on_open_dashboard=lambda: events.append("open"),
        on_start_monitoring=lambda: events.append("start"),
        on_stop_monitoring=lambda: events.append("stop"),
        on_exit=lambda: events.append("exit"),
    )

    assert tray.open_action.text() == "Open Dashboard"
    assert tray.start_action.text() == "Start Monitoring"
    assert tray.stop_action.text() == "Stop Monitoring"
    assert "Exit" in tray.exit_action.text()
    assert not tray.icon().isNull()

    # Stopped state: Start is enabled, Stop is disabled
    assert tray.start_action.isEnabled() is True
    assert tray.stop_action.isEnabled() is False
    tray.start_action.trigger()

    # Protected state: Start is disabled, Stop is enabled
    tray.update_state(is_protected=True, pending_count=0)
    assert tray.start_action.isEnabled() is False
    assert tray.stop_action.isEnabled() is True
    assert "Protected" in tray.toolTip()

    # Protected with pending requests
    tray.update_state(is_protected=True, pending_count=2)
    assert "2 pending approvals" in tray.toolTip()

    tray.open_action.trigger()
    tray.stop_action.trigger()
    tray.exit_action.trigger()
    assert events == ["start", "open", "stop", "exit"]


# ======================================================================
# 2. Approval Popup Safe Rendering & Close Protection
# ======================================================================


def test_approval_popup_safe_rendering_redaction_and_close_protection(
    qapp: QApplication,
) -> None:
    decisions: list[tuple[str, str]] = []
    req = InterceptedRequest(
        server_name="<b>untrusted-server</b>",
        tool_name="<script>alert(1)</script>_tool",
        tool_description="<img src=x onerror=alert(1)> Untrusted tool info",
        jsonrpc_request_id=77,
        arguments={
            "filename": "notes.txt",
            "password": "MySecretPassword99!",
            "api_key": "sk-live-secret-token-123456",
            "content": "Private sensitive file body",
        },
    )

    popup = ApprovalPopup(
        request=req,
        timeout_seconds=60.0,
        on_allow=lambda iid: decisions.append(("allow", iid)),
        on_block=lambda iid: decisions.append(("block", iid)),
    )
    try:
        # Always-on-top flag set
        assert bool(popup.windowFlags() & Qt.WindowType.WindowStaysOnTopHint)

        # PlainText format enforced on untrusted labels (no RichText/HTML rendering)
        assert popup.server_label.textFormat() == Qt.TextFormat.PlainText
        assert popup.tool_label.textFormat() == Qt.TextFormat.PlainText
        assert popup.server_label.text() == "<b>untrusted-server</b>"
        assert popup.tool_label.text() == "<script>alert(1)</script>_tool"
        assert "#77" in popup.request_id_label.text()
        assert req.internal_id[:12] in popup.request_id_label.text()

        # Sensitive values and raw file content MUST be redacted in parameters view
        rendered_params = popup.parameters_box.toPlainText()
        assert "notes.txt" in rendered_params
        assert "MySecretPassword99!" not in rendered_params
        assert "sk-live-secret-token-123456" not in rendered_params
        assert "Private sensitive file body" not in rendered_params
        assert "[REDACTED]" in rendered_params
        assert "[REDACTED_CONTENT" in rendered_params

        # Attempting Escape or window close while pending MUST NOT close or approve
        esc_event = QKeyEvent(
            QKeyEvent.Type.KeyPress, Qt.Key.Key_Escape, Qt.KeyboardModifier.NoModifier
        )
        popup.keyPressEvent(esc_event)
        assert not popup.is_decided

        close_ev = QCloseEvent()
        popup.closeEvent(close_ev)
        assert not close_ev.isAccepted()
        assert decisions == []

        # Clicking Block disables buttons and fires callback exactly once
        popup.block_button.click()
        assert popup.is_decided
        assert not popup.allow_button.isEnabled()
        assert not popup.block_button.isEnabled()
        # Second click has no effect
        popup.allow_button.click()
        assert decisions == [("block", req.internal_id)]
    finally:
        popup.deleteLater()


# ======================================================================
# 3. GUI & Asyncio Thread Interaction + Broker Security
# ======================================================================


def test_gui_and_asyncio_worker_thread_separation_and_broker_auth(
    qapp: QApplication, tmp_path: Path
) -> None:
    controller = GuardController(
        audit_log_path=tmp_path / "audit.jsonl",
        timeout_seconds=10.0,
        broker_runtime_file=tmp_path / "broker.json",
    )
    try:
        main_tid = threading.get_ident()
        endpoint = controller.start_monitoring_sync(timeout=5.0)

        async def _worker_tid() -> int:
            return threading.get_ident()

        worker_tid = controller.worker.submit(_worker_tid()).result(timeout=5.0)
        assert worker_tid != main_tid, "Asyncio worker must run on a dedicated thread!"

        # Unauthorized client without bearer token must be rejected with HTTP 401
        resp_no_auth = httpx.get(f"{endpoint}/health", timeout=3.0)
        assert resp_no_auth.status_code == 401

        resp_bad_auth = httpx.get(
            f"{endpoint}/health",
            headers={"Authorization": "Bearer wrong-token"},
            timeout=3.0,
        )
        assert resp_bad_auth.status_code == 401

        info = controller.broker.runtime_info
        assert info is not None
        resp_ok = httpx.get(
            f"{endpoint}/health",
            headers={"Authorization": f"Bearer {info.token}"},
            timeout=3.0,
        )
        assert resp_ok.status_code == 200
        assert resp_ok.json()["status"] == "protected"
    finally:
        controller.shutdown_sync()


# ======================================================================
# 4. Real End-to-End MCP Proxy -> Broker -> PySide6 Popup -> Allow & Block
# ======================================================================


def test_real_end_to_end_allow_block_dashboard_counters_and_history(
    qapp: QApplication, tmp_path: Path
) -> None:
    sandbox = tmp_path / "sandbox"
    broker_file = tmp_path / "broker.json"
    audit_file = tmp_path / "audit.jsonl"
    cfg_path = _write_proxy_config(tmp_path, sandbox)

    controller = GuardController(
        audit_log_path=audit_file,
        timeout_seconds=30.0,
        configured_server_summary="Configured default: safe-test-server",
        broker_runtime_file=broker_file,
    )
    window = MainWindow(controller=controller, minimize_to_tray=False)
    try:
        controller.start_monitoring_sync(timeout=5.0)
        _pump_qt_until(qapp, lambda: window.protection_badge.text() == "PROTECTED")

        # Run real 3-process MCP STDIO client -> StdioMCPProxy -> test_mcp_server in worker loop
        async def _drive_mcp_session() -> dict[str, Any]:
            results: dict[str, Any] = {}
            params = _make_stdio_proxy_params(cfg_path, broker_file)
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    results["tools"] = [t.name for t in tools.tools]

                    # 1. Request that user will ALLOW
                    res_allow = await session.call_tool(
                        "create_test_file",
                        {
                            "filename": "gui_approved.txt",
                            "content": "Sensitive body must stay out of UI history",
                        },
                    )
                    results["allow_is_error"] = res_allow.is_error

                    # 2. Request that user will BLOCK
                    try:
                        await session.call_tool(
                            "create_test_file",
                            {
                                "filename": "gui_blocked_marker.txt",
                                "content": "MUST_NOT_EXIST",
                            },
                        )
                        results["block_error_code"] = None
                    except MCPError as exc:
                        results["block_error_code"] = exc.error.code
            return results

        client_future = controller.worker.submit(_drive_mcp_session())

        # Wait for first popup (Allow) and verify dashboard proxy status connected
        _pump_qt_until(qapp, lambda: len(window.active_popups) == 1, timeout=15.0)
        popup_allow = next(iter(window.active_popups.values()))
        assert popup_allow.tool_label.text() == "create_test_file"
        assert "gui_approved.txt" in popup_allow.parameters_box.toPlainText()
        assert window.pending_count_label.text() == "1"
        assert "Connected" in window.proxy_status_value.text()

        # Click Allow in the actual PySide6 popup
        popup_allow.allow_button.click()
        _pump_qt_until(
            qapp, lambda: popup_allow.internal_id not in window.active_popups, timeout=5.0
        )

        # Wait for second popup (Block)
        _pump_qt_until(qapp, lambda: len(window.active_popups) == 1, timeout=15.0)
        popup_block = next(iter(window.active_popups.values()))
        assert "gui_blocked_marker.txt" in popup_block.parameters_box.toPlainText()

        # Click Block in the actual PySide6 popup
        popup_block.block_button.click()
        _pump_qt_until(qapp, lambda: client_future.done(), timeout=15.0)

        results = client_future.result(timeout=5.0)
        assert "create_test_file" in results["tools"]
        assert results["allow_is_error"] is False
        assert results["block_error_code"] == ERR_AUTHORIZATION_DENIED

        # Verify actual upstream filesystem effect & marker-file non-creation
        assert (sandbox / "gui_approved.txt").read_text(encoding="utf-8") == (
            "Sensitive body must stay out of UI history"
        )
        assert not (sandbox / "gui_blocked_marker.txt").exists()

        # Verify live dashboard KPI counters & history table updated accurately
        _pump_qt_until(
            qapp,
            lambda: (
                window.total_count_label.text() == "2"
                and window.approved_count_label.text() == "1"
                and window.blocked_count_label.text() == "1"
                and window.pending_count_label.text() == "0"
                and window.history_table.rowCount() == 2
            ),
            timeout=5.0,
        )

        # Verify table rows contain expected columns and zero leaked file content
        table_text = " ".join(
            window.history_table.item(r, c).text()
            for r in range(window.history_table.rowCount())
            for c in range(window.history_table.columnCount())
        )
        assert "create_test_file" in table_text
        assert "safe-test-server" in table_text
        assert "ALLOW" in table_text
        assert "BLOCK" in table_text
        assert "Sensitive body must stay out of UI history" not in table_text
    finally:
        window.prepare_for_exit()
        window.close()
        controller.shutdown_sync()


# ======================================================================
# 5. Multiple Simultaneous Popups & Exact Request ID Mapping
# ======================================================================


def test_multiple_simultaneous_popups_and_exact_request_id_mapping(
    qapp: QApplication, tmp_path: Path
) -> None:
    sandbox = tmp_path / "sandbox"
    broker_file = tmp_path / "broker.json"
    cfg_path = _write_proxy_config(tmp_path, sandbox)

    controller = GuardController(
        audit_log_path=tmp_path / "audit_multi.jsonl",
        timeout_seconds=30.0,
        broker_runtime_file=broker_file,
    )
    window = MainWindow(controller=controller, minimize_to_tray=False)
    try:
        controller.start_monitoring_sync(timeout=5.0)

        async def _send_two_concurrent() -> tuple[Any, Any]:
            params = _make_stdio_proxy_params(cfg_path, broker_file)
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    t1 = asyncio.create_task(
                        session.call_tool(
                            "create_test_file",
                            {"filename": "multi_allow.txt", "content": "allowed-data"},
                        )
                    )
                    t2 = asyncio.create_task(
                        session.call_tool(
                            "create_test_file",
                            {"filename": "multi_block.txt", "content": "blocked-data"},
                        )
                    )
                    return await asyncio.gather(t1, t2, return_exceptions=True)

        fut = controller.worker.submit(_send_two_concurrent())

        # Both popups must be open simultaneously
        _pump_qt_until(qapp, lambda: len(window.active_popups) == 2, timeout=15.0)
        assert window.pending_count_label.text() == "2"

        popups = list(window.active_popups.values())
        assert popups[0].internal_id != popups[1].internal_id
        assert popups[0].request_id_label.text() != popups[1].request_id_label.text()

        # Identify each popup by its exact rendered parameters and decide independently
        allow_popup = next(
            p for p in popups if "multi_allow.txt" in p.parameters_box.toPlainText()
        )
        block_popup = next(
            p for p in popups if "multi_block.txt" in p.parameters_box.toPlainText()
        )

        # Block second request first, then Allow first request
        block_popup.block_button.click()
        allow_popup.allow_button.click()

        _pump_qt_until(qapp, lambda: fut.done(), timeout=15.0)
        res_allow, res_block = fut.result(timeout=5.0)

        assert not isinstance(res_allow, Exception)
        assert not res_allow.is_error
        assert isinstance(res_block, MCPError)
        assert res_block.error.code == ERR_AUTHORIZATION_DENIED

        assert (sandbox / "multi_allow.txt").read_text(encoding="utf-8") == "allowed-data"
        assert not (sandbox / "multi_block.txt").exists()
        _pump_qt_until(qapp, lambda: len(window.active_popups) == 0, timeout=5.0)
    finally:
        window.prepare_for_exit()
        window.close()
        controller.shutdown_sync()


# ======================================================================
# 6. Timeout Popup Handling & Safe Shutdown with Pending Requests
# ======================================================================


def test_timeout_closes_popup_and_prevents_upstream_execution(
    qapp: QApplication, tmp_path: Path
) -> None:
    sandbox = tmp_path / "sandbox"
    broker_file = tmp_path / "broker.json"
    cfg_path = _write_proxy_config(tmp_path, sandbox)

    controller = GuardController(
        audit_log_path=tmp_path / "audit_timeout.jsonl",
        timeout_seconds=0.6,
        broker_runtime_file=broker_file,
    )
    window = MainWindow(controller=controller, minimize_to_tray=False)
    try:
        controller.start_monitoring_sync(timeout=5.0)

        async def _call_and_expect_timeout() -> int:
            params = _make_stdio_proxy_params(cfg_path, broker_file)
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    try:
                        await session.call_tool(
                            "create_test_file",
                            {"filename": "gui_timeout_marker.txt", "content": "nope"},
                        )
                        return 0
                    except MCPError as exc:
                        return exc.error.code

        fut = controller.worker.submit(_call_and_expect_timeout())

        # Popup opens for the pending request
        _pump_qt_until(qapp, lambda: len(window.active_popups) == 1, timeout=15.0)
        # Do NOT click Allow or Block; wait for timeout to resolve and close popup
        _pump_qt_until(
            qapp,
            lambda: fut.done() and len(window.active_popups) == 0,
            timeout=10.0,
        )

        error_code = fut.result(timeout=5.0)
        assert error_code == types.REQUEST_TIMEOUT
        assert not (sandbox / "gui_timeout_marker.txt").exists()
        assert window.blocked_count_label.text() == "1"
        assert window.pending_count_label.text() == "0"
    finally:
        window.prepare_for_exit()
        window.close()
        controller.shutdown_sync()


def test_safe_shutdown_cancels_pending_requests_and_closes_popups(
    qapp: QApplication, tmp_path: Path
) -> None:
    controller = GuardController(
        audit_log_path=tmp_path / "audit_shutdown.jsonl",
        timeout_seconds=30.0,
        broker_runtime_file=tmp_path / "broker.json",
        enable_local_broker=False,
    )
    window = MainWindow(controller=controller, minimize_to_tray=False)
    try:
        controller.start_monitoring_sync(timeout=5.0)
        req = InterceptedRequest(
            server_name="safe-test-server",
            tool_name="create_test_file",
            arguments={"filename": "shutdown_ui_marker.txt", "content": "nope"},
            jsonrpc_request_id=900,
        )
        auth_fut = controller.worker.submit(controller.approval_manager.authorize(req))

        _pump_qt_until(qapp, lambda: len(window.active_popups) == 1, timeout=5.0)

        # Explicit Exit / shutdown cancels pending requests cleanly without deadlock
        window.prepare_for_exit()
        controller.shutdown_sync(timeout=5.0)

        decision = auth_fut.result(timeout=5.0)
        assert not decision.is_allowed
        assert req.status is RequestStatus.CANCELLED
        assert len(window.active_popups) == 0
        assert not controller.worker.is_running
    finally:
        window.close()
        controller.shutdown_sync()
