"""Phase 8 automated tests for the Authenticated Remote MCP Streamable HTTP Gateway.

Uses the real official MCP SDK 2.3.0 Streamable HTTP client (`streamable_http_client` +
`create_mcp_http_client`) against a live FastAPI/Uvicorn `RemoteMCPGateway` wrapping
the real `tests.test_mcp_server` subprocess.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path
from typing import Any

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import httpx
import mcp.types as types
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
from mcp.shared.exceptions import MCPError
from PySide6.QtWidgets import QApplication

from app.authorization.approval_manager import ApprovalManager
from app.authorization.ipc_broker import RemoteBrokerAuthorizer
from app.config import UpstreamServerConfig
from app.main import GuardController
from app.models.request import (
    ERR_AUTHORIZATION_DENIED,
    ERR_AUTHORIZATION_SYSTEM_FAILURE,
    InterceptedRequest,
)
from app.monitoring.audit_logger import AuditLogger
from app.proxy.http_gateway import (
    ENV_GATEWAY_TOKEN,
    GatewayConfigError,
    RemoteMCPGateway,
    main as gateway_cli_main,
)
from app.ui.main_window import MainWindow


def _test_server_cfg(sandbox: Path) -> UpstreamServerConfig:
    sandbox.mkdir(parents=True, exist_ok=True)
    return UpstreamServerConfig(
        description="Safe local test MCP server",
        transport="stdio",
        command=sys.executable,
        args=["-m", "tests.test_mcp_server", "--sandbox-dir", str(sandbox)],
        sandbox_dir=str(sandbox),
        enabled=True,
    )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ======================================================================
# 1. Fail-Closed Startup & Missing/Invalid Bearer Token Checks
# ======================================================================


def test_missing_or_short_gateway_token_fails_closed(tmp_path: Path, monkeypatch) -> None:
    cfg = _test_server_cfg(tmp_path / "sandbox")

    with pytest.raises(GatewayConfigError):
        RemoteMCPGateway(server_name="safe-test-server", server_config=cfg, bearer_token=None)

    with pytest.raises(GatewayConfigError):
        RemoteMCPGateway(server_name="safe-test-server", server_config=cfg, bearer_token="")

    with pytest.raises(GatewayConfigError):
        RemoteMCPGateway(
            server_name="safe-test-server", server_config=cfg, bearer_token="too-short"
        )

    # CLI entrypoint must fail closed with non-zero exit code when env var is missing
    monkeypatch.delenv(ENV_GATEWAY_TOKEN, raising=False)
    cfg_file = tmp_path / "servers.json"
    cfg_file.write_text(
        json.dumps(
            {
                "default_server": "safe-test-server",
                "servers": {
                    "safe-test-server": {
                        "command": sys.executable,
                        "args": ["-m", "tests.test_mcp_server"],
                        "enabled": True,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    assert gateway_cli_main(["--config", str(cfg_file)]) == 2


@pytest.mark.asyncio
async def test_unauthenticated_invalid_token_dns_rebinding_and_oversized_body_rejected(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    token = secrets.token_urlsafe(32)
    audit = AuditLogger(tmp_path / "audit_auth.jsonl")
    manager = ApprovalManager(audit_logger=audit, timeout_seconds=5.0)
    gateway = RemoteMCPGateway(
        server_name="safe-test-server",
        server_config=_test_server_cfg(sandbox),
        bearer_token=token,
        authorizer=manager,
        max_request_body_size=4096,
    )
    info = await gateway.start()

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # 1. Unauthenticated client rejected with 401 + WWW-Authenticate
            r_no_auth_mcp = await client.post(info.mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            assert r_no_auth_mcp.status_code == 401
            assert "Bearer" in r_no_auth_mcp.headers.get("www-authenticate", "")

            r_no_auth_health = await client.get(f"{info.base_url}/health")
            assert r_no_auth_health.status_code == 401

            # 2. Invalid bearer token rejected with 401
            bad_headers = {"Authorization": f"Bearer wrong-{secrets.token_urlsafe(24)}"}
            r_bad_mcp = await client.post(
                info.mcp_url,
                headers=bad_headers,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            )
            assert r_bad_mcp.status_code == 401

            r_bad_health = await client.get(f"{info.base_url}/health", headers=bad_headers)
            assert r_bad_health.status_code == 401

            # 3. Valid token succeeds on /health
            good_headers = {"Authorization": f"Bearer {token}"}
            r_ok = await client.get(f"{info.base_url}/health", headers=good_headers)
            assert r_ok.status_code == 200
            assert r_ok.json()["transport"] == "streamable-http"

            # 4. Oversized payload rejected with 413
            r_big = await client.post(
                info.mcp_url,
                headers=good_headers,
                content=b"x" * 5000,
            )
            assert r_big.status_code == 413

            # 5. DNS-rebinding Host header rejected by TransportSecuritySettings (421)
            r_rebind = await client.post(
                info.mcp_url,
                headers={**good_headers, "Host": "evil.example"},
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            )
            assert r_rebind.status_code in (403, 421)
    finally:
        await gateway.stop()
        audit.close()


# ======================================================================
# 2. Real Streamable HTTP: Initialize, Discovery, Allow, Block, Redacted Audit
# ======================================================================


@pytest.mark.asyncio
async def test_streamable_http_initialize_discovery_allow_block_and_redacted_audit(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    log_path = tmp_path / "audit_http.jsonl"
    token = secrets.token_urlsafe(32)
    audit = AuditLogger(log_path)

    def on_pending(req: InterceptedRequest) -> None:
        fname = req.arguments.get("filename", "")
        if fname == "http_blocked_marker.txt":
            manager.block(req.internal_id, reason="Blocked remote file write")
        else:
            manager.approve(req.internal_id, reason="Approved remote call")

    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=15.0,
        on_pending_request=on_pending,
    )
    gateway = RemoteMCPGateway(
        server_name="safe-test-server",
        server_config=_test_server_cfg(sandbox),
        bearer_token=token,
        authorizer=manager,
    )
    info = await gateway.start()

    try:
        http_client = create_mcp_http_client(
            headers={"Authorization": f"Bearer {token}"}
        )
        async with http_client:
            async with streamable_http_client(
                info.mcp_url, http_client=http_client
            ) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    # Initialize & discover tools
                    init_res = await session.initialize()
                    assert "walled-ai-mcp-guard-gateway" in init_res.server_info.name

                    tools_res = await session.list_tools()
                    assert {t.name for t in tools_res.tools} == {
                        "get_current_time",
                        "read_test_file",
                        "create_test_file",
                        "list_test_directory",
                    }

                    # Non-tool resource & prompt forwarding over Streamable HTTP
                    res = await session.read_resource("sandbox://info")
                    assert json.loads(res.contents[0].text)["sandbox_active"] is True

                    prompt = await session.get_prompt("sandbox_summary", {"topic": "remote"})
                    assert "remote" in prompt.messages[0].content.text

                    # Approved tools/call executes upstream
                    ok_call = await session.call_tool(
                        "create_test_file",
                        {
                            "filename": "http_allowed.txt",
                            "content": "TOP_SECRET_REMOTE_BODY_12345",
                        },
                    )
                    assert not ok_call.is_error
                    assert (sandbox / "http_allowed.txt").read_text(encoding="utf-8") == (
                        "TOP_SECRET_REMOTE_BODY_12345"
                    )

                    # Blocked tools/call denied and NEVER creates marker file
                    with pytest.raises(MCPError) as blocked_exc:
                        await session.call_tool(
                            "create_test_file",
                            {
                                "filename": "http_blocked_marker.txt",
                                "content": "MUST_NOT_EXIST",
                            },
                        )
                    assert blocked_exc.value.error.code == ERR_AUTHORIZATION_DENIED
                    assert not (sandbox / "http_blocked_marker.txt").exists()
    finally:
        await gateway.stop()
        audit.close()

    # Audit log verification: redacted, no raw file body leaked
    raw_log = log_path.read_text(encoding="utf-8")
    assert "TOP_SECRET_REMOTE_BODY_12345" not in raw_log
    assert "MUST_NOT_EXIST" not in raw_log

    records = _read_jsonl(log_path)
    events = {r["event_type"] for r in records}
    assert {
        "REQUEST_RECEIVED",
        "DECISION_APPROVED",
        "EXECUTION_STARTED",
        "EXECUTION_COMPLETED",
        "DECISION_BLOCKED",
    }.issubset(events)


# ======================================================================
# 3. Timeout & Concurrent Streamable HTTP Requests
# ======================================================================


@pytest.mark.asyncio
async def test_streamable_http_timeout_fails_closed_and_never_executes(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    token = secrets.token_urlsafe(32)
    audit = AuditLogger(tmp_path / "audit_http_timeout.jsonl")
    manager = ApprovalManager(audit_logger=audit, timeout_seconds=0.4)
    gateway = RemoteMCPGateway(
        server_name="safe-test-server",
        server_config=_test_server_cfg(sandbox),
        bearer_token=token,
        authorizer=manager,
    )
    info = await gateway.start()

    try:
        http_client = create_mcp_http_client(
            headers={"Authorization": f"Bearer {token}"}
        )
        async with http_client:
            async with streamable_http_client(
                info.mcp_url, http_client=http_client
            ) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    with pytest.raises(MCPError) as exc:
                        await session.call_tool(
                            "create_test_file",
                            {"filename": "http_timeout_marker.txt", "content": "nope"},
                        )
                    assert exc.value.error.code == types.REQUEST_TIMEOUT
                    assert not (sandbox / "http_timeout_marker.txt").exists()
    finally:
        await gateway.stop()
        audit.close()


@pytest.mark.asyncio
async def test_streamable_http_concurrent_requests_independent_decisions(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    token = secrets.token_urlsafe(32)
    audit = AuditLogger(tmp_path / "audit_http_concurrent.jsonl")

    all_four = asyncio.Event()
    by_file: dict[str, InterceptedRequest] = {}

    def on_pending(req: InterceptedRequest) -> None:
        by_file[req.arguments["filename"]] = req
        if len(by_file) == 4:
            all_four.set()

    manager = ApprovalManager(
        audit_logger=audit, timeout_seconds=20.0, on_pending_request=on_pending
    )
    gateway = RemoteMCPGateway(
        server_name="safe-test-server",
        server_config=_test_server_cfg(sandbox),
        bearer_token=token,
        authorizer=manager,
    )
    info = await gateway.start()

    try:
        http_client = create_mcp_http_client(
            headers={"Authorization": f"Bearer {token}"}
        )
        async with http_client:
            async with streamable_http_client(
                info.mcp_url, http_client=http_client
            ) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    t_a1 = asyncio.create_task(
                        session.call_tool(
                            "create_test_file",
                            {"filename": "http_c_allow_1.txt", "content": "c1"},
                        )
                    )
                    t_b1 = asyncio.create_task(
                        session.call_tool(
                            "create_test_file",
                            {"filename": "http_c_block_1.txt", "content": "no1"},
                        )
                    )
                    t_a2 = asyncio.create_task(
                        session.call_tool(
                            "create_test_file",
                            {"filename": "http_c_allow_2.txt", "content": "c2"},
                        )
                    )
                    t_b2 = asyncio.create_task(
                        session.call_tool(
                            "create_test_file",
                            {"filename": "http_c_block_2.txt", "content": "no2"},
                        )
                    )

                    await asyncio.wait_for(all_four.wait(), timeout=15.0)
                    assert len({req.internal_id for req in by_file.values()}) == 4
                    assert len({req.jsonrpc_request_id for req in by_file.values()}) == 4

                    # Resolve out of order
                    manager.block(by_file["http_c_block_2.txt"].internal_id)
                    manager.approve(by_file["http_c_allow_2.txt"].internal_id)
                    manager.block(by_file["http_c_block_1.txt"].internal_id)
                    manager.approve(by_file["http_c_allow_1.txt"].internal_id)

                    r_a1, r_b1, r_a2, r_b2 = await asyncio.wait_for(
                        asyncio.gather(t_a1, t_b1, t_a2, t_b2, return_exceptions=True),
                        timeout=15.0,
                    )

                    assert not isinstance(r_a1, Exception) and not r_a1.is_error
                    assert not isinstance(r_a2, Exception) and not r_a2.is_error
                    assert isinstance(r_b1, MCPError) and r_b1.error.code == ERR_AUTHORIZATION_DENIED
                    assert isinstance(r_b2, MCPError) and r_b2.error.code == ERR_AUTHORIZATION_DENIED

                    assert (sandbox / "http_c_allow_1.txt").read_text(encoding="utf-8") == "c1"
                    assert (sandbox / "http_c_allow_2.txt").read_text(encoding="utf-8") == "c2"
                    assert not (sandbox / "http_c_block_1.txt").exists()
                    assert not (sandbox / "http_c_block_2.txt").exists()
    finally:
        await gateway.stop()
        audit.close()


# ======================================================================
# 4. End-to-End Remote Streamable HTTP Gateway -> Desktop Broker -> PySide6 Popup
# ======================================================================


def test_remote_gateway_connected_to_desktop_broker_triggers_real_pyside6_popup(
    tmp_path: Path,
) -> None:
    """Remote MCP Streamable HTTP tool calls trigger the exact desktop PySide6 approval popup."""
    app = QApplication.instance() or QApplication(["http-gateway-desktop-test"])
    sandbox = tmp_path / "sandbox"
    broker_file = tmp_path / "desktop_broker.json"
    token = secrets.token_urlsafe(32)

    controller = GuardController(
        audit_log_path=tmp_path / "audit_remote_desktop.jsonl",
        timeout_seconds=30.0,
        configured_server_summary="Remote Gateway -> safe-test-server",
        broker_runtime_file=broker_file,
    )
    window = MainWindow(controller=controller, minimize_to_tray=False)
    results: dict[str, Any] = {}

    def _run_gateway_and_remote_client() -> None:
        async def _inner() -> None:
            broker_authorizer = RemoteBrokerAuthorizer(
                broker_file=broker_file,
                request_timeout_seconds=30.0,
            )
            gateway = RemoteMCPGateway(
                server_name="safe-test-server",
                server_config=_test_server_cfg(sandbox),
                bearer_token=token,
                authorizer=broker_authorizer,
            )
            info = await gateway.start()
            try:
                http_client = create_mcp_http_client(
                    headers={"Authorization": f"Bearer {token}"}
                )
                async with http_client:
                    async with streamable_http_client(
                        info.mcp_url, http_client=http_client
                    ) as (r, w):
                        async with ClientSession(r, w) as session:
                            await session.initialize()
                            await session.list_tools()

                            # 1. Remote call ALLOWED in desktop popup
                            res_ok = await session.call_tool(
                                "create_test_file",
                                {"filename": "remote_gui_allow.txt", "content": "from-remote"},
                            )
                            results["allow_is_error"] = res_ok.is_error

                            # 2. Remote call BLOCKED in desktop popup
                            try:
                                await session.call_tool(
                                    "create_test_file",
                                    {"filename": "remote_gui_block.txt", "content": "nope"},
                                )
                                results["block_code"] = 0
                            except MCPError as exc:
                                results["block_code"] = exc.error.code
            finally:
                await gateway.stop()

        asyncio.run(_inner())

    def _pump_until(pred, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            app.processEvents()
            if pred():
                return
            time.sleep(0.02)
        app.processEvents()
        assert pred(), "Timed out waiting for desktop popup."

    worker_thread = threading.Thread(target=_run_gateway_and_remote_client, daemon=True)
    try:
        controller.start_monitoring_sync(timeout=5.0)
        worker_thread.start()

        # First popup -> Allow
        _pump_until(lambda: len(window.active_popups) == 1)
        p1 = next(iter(window.active_popups.values()))
        assert "remote_gui_allow.txt" in p1.parameters_box.toPlainText()
        p1.allow_button.click()
        _pump_until(lambda: p1.internal_id not in window.active_popups)

        # Second popup -> Block
        _pump_until(lambda: len(window.active_popups) == 1)
        p2 = next(iter(window.active_popups.values()))
        assert "remote_gui_block.txt" in p2.parameters_box.toPlainText()
        p2.block_button.click()

        worker_thread.join(timeout=20.0)
        assert not worker_thread.is_alive()

        assert results["allow_is_error"] is False
        assert results["block_code"] == ERR_AUTHORIZATION_DENIED
        assert (sandbox / "remote_gui_allow.txt").read_text(encoding="utf-8") == "from-remote"
        assert not (sandbox / "remote_gui_block.txt").exists()

        _pump_until(
            lambda: window.total_count_label.text() == "2"
            and window.approved_count_label.text() == "1"
            and window.blocked_count_label.text() == "1"
        )
    finally:
        window.prepare_for_exit()
        window.close()
        controller.shutdown_sync()
