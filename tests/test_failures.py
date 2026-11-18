"""Phase 5 failure handling and fault-resilience tests."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import anyio
import httpx
import mcp.types as types
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError
from mcp.shared.memory import create_client_server_memory_streams
from mcp.shared.message import SessionMessage
from PySide6.QtWidgets import QApplication

from app.authorization.approval_manager import ApprovalManager
from app.authorization.ipc_broker import LocalAuthorizationBroker, RemoteBrokerAuthorizer
from app.config import UpstreamServerConfig
from app.main import GuardController
from app.models.request import (
    ERR_AUTHORIZATION_CANCELLED,
    ERR_AUTHORIZATION_DENIED,
    ERR_AUTHORIZATION_SYSTEM_FAILURE,
    InterceptedRequest,
    RequestStatus,
)
from app.monitoring.audit_logger import AuditLogger
from app.proxy.stdio_proxy import StdioMCPProxy
from app.ui.main_window import MainWindow


def _write_crashing_upstream_server(script_path: Path) -> None:
    """Create a real MCP STDIO server with a tool that crashes hard (`os._exit(1)`) on execution."""
    script_path.write_text(
        '''import os
from mcp.server import MCPServer

srv = MCPServer("crashing-test-server", version="1.0.0")

@srv.tool(name="ping_tool", description="Safe echo tool")
def ping_tool(msg: str) -> str:
    return f"pong:{msg}"

@srv.tool(name="crash_now", description="Immediately terminates the upstream server process")
def crash_now() -> str:
    os._exit(1)

if __name__ == "__main__":
    srv.run(transport="stdio")
''',
        encoding="utf-8",
    )


@asynccontextmanager
async def _proxy_to_server_cfg(
    server_cfg: UpstreamServerConfig, authorizer: Any
) -> AsyncIterator[tuple[ClientSession, StdioMCPProxy]]:
    proxy = StdioMCPProxy(
        server_name="failure-test-server",
        server_config=server_cfg,
        authorizer=authorizer,
    )
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        c_read, c_write = client_streams
        s_read, s_write = server_streams
        async with anyio.create_task_group() as tg:
            tg.start_soon(proxy.run_streams, s_read, s_write)
            try:
                async with ClientSession(c_read, c_write) as session:
                    yield session, proxy
            finally:
                await c_write.aclose()
                await c_read.aclose()


# ======================================================================
# 1. Upstream MCP Server Crash & Mid-Execution Disconnect
# ======================================================================


@pytest.mark.asyncio
async def test_upstream_server_crash_on_startup_fails_cleanly(tmp_path: Path) -> None:
    """An upstream server that exits immediately on startup raises cleanly without hanging."""
    bad_script = tmp_path / "immediate_crash.py"
    bad_script.write_text("import sys; sys.exit(2)\n", encoding="utf-8")

    cfg = UpstreamServerConfig(
        command=sys.executable,
        args=[str(bad_script)],
        enabled=True,
    )
    proxy = StdioMCPProxy(server_name="bad-upstream", server_config=cfg)

    async with create_client_server_memory_streams() as (_, server_streams):
        s_read, s_write = server_streams
        with pytest.raises(Exception):
            await asyncio.wait_for(proxy.run_streams(s_read, s_write), timeout=10.0)


@pytest.mark.asyncio
async def test_upstream_disconnect_mid_execution_and_blocked_crash_protection(
    tmp_path: Path,
) -> None:
    """Blocked crash tool leaves server alive; approved crash tool records FAILED cleanly."""
    crash_script = tmp_path / "crashing_server.py"
    _write_crashing_upstream_server(crash_script)

    cfg = UpstreamServerConfig(
        command=sys.executable,
        args=[str(crash_script)],
        enabled=True,
    )
    audit = AuditLogger(tmp_path / "audit_crash.jsonl")

    crash_attempts = 0

    def on_pending(req: InterceptedRequest) -> None:
        nonlocal crash_attempts
        if req.tool_name == "ping_tool":
            manager.approve(req.internal_id)
        elif req.tool_name == "crash_now":
            crash_attempts += 1
            if crash_attempts == 1:
                manager.block(req.internal_id, reason="Block first crash attempt")
            else:
                manager.approve(req.internal_id, reason="Allow crash to test recovery")

    manager = ApprovalManager(
        audit_logger=audit, timeout_seconds=10.0, on_pending_request=on_pending
    )

    async with _proxy_to_server_cfg(cfg, manager) as (session, _):
        await session.initialize()

        # 1. Block crash_now -> upstream MUST NOT crash!
        with pytest.raises(MCPError) as blocked_exc:
            await session.call_tool("crash_now", {})
        assert blocked_exc.value.error.code == ERR_AUTHORIZATION_DENIED

        # Prove upstream server is STILL ALIVE after crash_now was blocked
        pong = await session.call_tool("ping_tool", {"msg": "still-alive"})
        assert not pong.is_error
        assert pong.content[0].text == "pong:still-alive"

        # 2. Approve crash_now -> upstream dies mid-execution -> clean MCPError & FAILED status
        with pytest.raises(MCPError):
            await asyncio.wait_for(session.call_tool("crash_now", {}), timeout=10.0)

    stats = manager.request_manager.get_stats()
    assert stats["total"] == 3
    assert stats["blocked"] == 1
    assert stats["completed"] == 1
    assert stats["failed"] == 1
    assert stats["approved_total"] == 2
    assert stats["blocked_total"] == 1
    audit.close()


# ======================================================================
# 2. Invalid JSON-RPC & Malformed Tool Arguments
# ======================================================================


@pytest.mark.asyncio
async def test_invalid_jsonrpc_and_malformed_tool_arguments(tmp_path: Path) -> None:
    """Malformed JSON-RPC and invalid tool arguments never trigger authorization or upstream."""
    sandbox = tmp_path / "sandbox"
    cfg = UpstreamServerConfig(
        command=sys.executable,
        args=["-m", "tests.test_mcp_server", "--sandbox-dir", str(sandbox)],
        enabled=True,
    )
    audit = AuditLogger(tmp_path / "audit_invalid.jsonl")
    seen_pending: list[InterceptedRequest] = []
    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=5.0,
        on_pending_request=lambda r: (seen_pending.append(r), manager.block(r.internal_id)),
    )

    # Part A: Unknown JSON-RPC method & empty/null-byte tool arguments via real session
    async with _proxy_to_server_cfg(cfg, manager) as (session, _):
        await session.initialize()

        # Empty tool name rejected with INVALID_PARAMS BEFORE authorization
        with pytest.raises(MCPError) as empty_exc:
            await session.call_tool("   ", {})
        assert empty_exc.value.error.code == types.INVALID_PARAMS

        # Null-byte argument key rejected BEFORE authorization
        with pytest.raises(MCPError) as null_key_exc:
            await session.call_tool("create_test_file", {"bad\x00key": "val"})
        assert null_key_exc.value.error.code == types.INVALID_PARAMS

        # Overlong tool name (>256 chars) rejected BEFORE authorization
        with pytest.raises(MCPError) as long_name_exc:
            await session.call_tool("x" * 300, {})
        assert long_name_exc.value.error.code == types.INVALID_PARAMS

        assert seen_pending == [], "Malformed arguments must fail BEFORE hitting ApprovalManager!"

    # Also verify non-finite floats (NaN/Inf) and non-dict arguments fail strict JSON validation directly
    from app.models.request import validate_and_clone_arguments

    with pytest.raises(ValueError):
        validate_and_clone_arguments({"n": float("nan")})
    with pytest.raises(ValueError):
        validate_and_clone_arguments("not-a-dict")

    # Part B: Raw malformed JSON-RPC request frame sent over real MCP memory streams
    proxy = StdioMCPProxy(
        server_name="safe-test-server", server_config=cfg, authorizer=manager
    )
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        c_read, c_write = client_streams
        s_read, s_write = server_streams
        async with anyio.create_task_group() as tg:
            tg.start_soon(proxy.run_streams, s_read, s_write)
            try:
                # Send unknown JSON-RPC method directly
                unknown_req = types.JSONRPCRequest(
                    jsonrpc="2.0", id=501, method="nonexistent/method", params={}
                )
                await c_write.send(SessionMessage(unknown_req))
                reply = await asyncio.wait_for(c_read.receive(), timeout=5.0)
                assert isinstance(reply, SessionMessage)
                assert isinstance(reply.message, types.JSONRPCError)
                assert reply.message.id == 501
                assert reply.message.error.code == types.METHOD_NOT_FOUND

                # Send invalid tools/call params (missing required `name`)
                bad_call = types.JSONRPCRequest(
                    jsonrpc="2.0", id=502, method="tools/call", params={"arguments": "not-a-dict"}
                )
                await c_write.send(SessionMessage(bad_call))
                reply2 = await asyncio.wait_for(c_read.receive(), timeout=5.0)
                assert isinstance(reply2, SessionMessage)
                assert isinstance(reply2.message, types.JSONRPCError)
                assert reply2.message.id == 502
                assert reply2.message.error.code == types.INVALID_PARAMS
            finally:
                await c_write.aclose()
                await c_read.aclose()

    assert seen_pending == []
    audit.close()


# ======================================================================
# 3. Broker Unavailable, Invalid/Expired Token, Token Rotation
# ======================================================================


@pytest.mark.asyncio
async def test_broker_unavailable_and_invalid_or_rotated_token_fail_closed(
    tmp_path: Path,
) -> None:
    """Missing broker, wrong token, and rotated/invalidated tokens strictly fail closed."""
    sandbox = tmp_path / "sandbox"
    cfg = UpstreamServerConfig(
        command=sys.executable,
        args=["-m", "tests.test_mcp_server", "--sandbox-dir", str(sandbox)],
        enabled=True,
    )

    # 1. Missing broker runtime file -> fails closed
    missing_broker_auth = RemoteBrokerAuthorizer(
        broker_file=tmp_path / "does_not_exist.json"
    )
    async with _proxy_to_server_cfg(cfg, missing_broker_auth) as (session, _):
        await session.initialize()
        with pytest.raises(MCPError) as exc:
            await session.call_tool(
                "create_test_file", {"filename": "no_broker.txt", "content": "nope"}
            )
        assert exc.value.error.code == ERR_AUTHORIZATION_SYSTEM_FAILURE
        assert not (sandbox / "no_broker.txt").exists()

    # 2. Live broker with wrong bearer token -> HTTP 401 -> fails closed
    audit = AuditLogger(tmp_path / "audit_token.jsonl")
    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=10.0,
        on_pending_request=lambda r: manager.approve(r.internal_id),
    )
    broker_file = tmp_path / "broker.json"
    broker = LocalAuthorizationBroker(approval_manager=manager, runtime_file=broker_file)
    info1 = await broker.start()

    try:
        wrong_token_auth = RemoteBrokerAuthorizer(
            broker_url=info1.url,
            bearer_token="wrong-token-" + "x" * 32,
        )
        async with _proxy_to_server_cfg(cfg, wrong_token_auth) as (session, _):
            await session.initialize()
            with pytest.raises(MCPError) as exc2:
                await session.call_tool(
                    "create_test_file", {"filename": "bad_token.txt", "content": "nope"}
                )
            assert exc2.value.error.code == ERR_AUTHORIZATION_SYSTEM_FAILURE
            assert not (sandbox / "bad_token.txt").exists()

        # 3. Stop and restart broker -> token rotates; old token from session 1 MUST be rejected!
        old_token = info1.token
        await broker.stop()
        assert not broker_file.exists(), "Runtime file must be deleted on broker stop!"

        info2 = await broker.start()
        assert info2.token != old_token, "Bearer token must rotate on restart!"

        expired_token_auth = RemoteBrokerAuthorizer(
            broker_url=info2.url,
            bearer_token=old_token,
        )
        async with _proxy_to_server_cfg(cfg, expired_token_auth) as (session, _):
            await session.initialize()
            with pytest.raises(MCPError) as exc3:
                await session.call_tool(
                    "create_test_file",
                    {"filename": "expired_token.txt", "content": "nope"},
                )
            assert exc3.value.error.code == ERR_AUTHORIZATION_SYSTEM_FAILURE
            assert not (sandbox / "expired_token.txt").exists()
    finally:
        await broker.stop()
        audit.close()


# ======================================================================
# 4. Audit Log Directory Unavailable
# ======================================================================


@pytest.mark.asyncio
async def test_audit_log_directory_unavailable_preserves_fail_closed_security(
    tmp_path: Path,
) -> None:
    """When audit_log_path parent is blocked by an existing file, blocking still enforces."""
    # Create a regular file where a directory is expected so parent mkdir / open fails.
    blocker_file = tmp_path / "not_a_dir"
    blocker_file.write_text("file-blocking-dir", encoding="utf-8")
    impossible_log = blocker_file / "nested" / "audit.jsonl"

    errors: list[Exception] = []
    audit = AuditLogger(impossible_log, on_log_error=lambda e: errors.append(e))
    sandbox = tmp_path / "sandbox"
    cfg = UpstreamServerConfig(
        command=sys.executable,
        args=["-m", "tests.test_mcp_server", "--sandbox-dir", str(sandbox)],
        enabled=True,
    )

    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=5.0,
        on_pending_request=lambda r: manager.block(r.internal_id, reason="Blocked"),
    )
    async with _proxy_to_server_cfg(cfg, manager) as (session, _):
        await session.initialize()
        with pytest.raises(MCPError) as exc:
            await session.call_tool(
                "create_test_file",
                {"filename": "audit_dir_fail_marker.txt", "content": "nope"},
            )
        assert exc.value.error.code == ERR_AUTHORIZATION_DENIED
        assert not (sandbox / "audit_dir_fail_marker.txt").exists()
        assert len(errors) >= 1
    audit.close()


# ======================================================================
# 5. Desktop App Closes While Pending & Proxy Terminates Unexpectedly
# ======================================================================


def test_desktop_app_closes_while_real_proxy_requests_pending(tmp_path: Path) -> None:
    """Closing the desktop app cancels pending real-proxy requests with zero upstream writes."""
    app = QApplication.instance() or QApplication(["failure-ui-test"])
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    broker_file = tmp_path / "broker.json"
    cfg_file = tmp_path / "servers.json"
    cfg_file.write_text(
        json.dumps(
            {
                "default_server": "safe-test-server",
                "servers": {
                    "safe-test-server": {
                        "command": sys.executable,
                        "args": ["-m", "tests.test_mcp_server", "--sandbox-dir", str(sandbox)],
                        "enabled": True,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    controller = GuardController(
        audit_log_path=tmp_path / "audit_close.jsonl",
        timeout_seconds=30.0,
        broker_runtime_file=broker_file,
    )
    window = MainWindow(controller=controller, minimize_to_tray=False)

    # Use a separate thread to drive the real 3-process STDIO client so shutting down
    # the desktop controller's worker thread does not kill the client itself.
    client_result: dict[str, Any] = {}

    def _run_external_client() -> None:
        async def _inner() -> None:
            params = StdioServerParameters(
                command=sys.executable,
                args=[
                    "-m",
                    "app.proxy.stdio_proxy",
                    "--config",
                    str(cfg_file),
                    "--server",
                    "safe-test-server",
                    "--use-desktop-guard",
                    "--broker-file",
                    str(broker_file),
                ],
            )
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    try:
                        await session.call_tool(
                            "create_test_file",
                            {"filename": "close_pending_marker.txt", "content": "nope"},
                        )
                        client_result["code"] = 0
                    except MCPError as exc:
                        client_result["code"] = exc.error.code

        asyncio.run(_inner())

    import threading

    client_thread = threading.Thread(target=_run_external_client, daemon=True)
    try:
        controller.start_monitoring_sync(timeout=5.0)
        client_thread.start()

        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and len(window.active_popups) < 1:
            app.processEvents()
            time.sleep(0.02)
        assert len(window.active_popups) == 1

        # Explicitly close/shutdown desktop application while request is pending
        window.prepare_for_exit()
        controller.shutdown_sync(timeout=5.0)

        client_thread.join(timeout=15.0)
        assert not client_thread.is_alive()
        assert client_result.get("code") in (
            ERR_AUTHORIZATION_CANCELLED,
            ERR_AUTHORIZATION_SYSTEM_FAILURE,
        )
        assert not (sandbox / "close_pending_marker.txt").exists()
        assert not broker_file.exists()
    finally:
        window.close()
        controller.shutdown_sync()


@pytest.mark.asyncio
async def test_proxy_process_terminates_unexpectedly_broker_remains_healthy(
    tmp_path: Path,
) -> None:
    """Killing a proxy subprocess mid-flight leaves the broker healthy for subsequent calls."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    broker_file = tmp_path / "broker_kill.json"
    cfg_file = tmp_path / "servers.json"
    cfg_file.write_text(
        json.dumps(
            {
                "default_server": "safe-test-server",
                "servers": {
                    "safe-test-server": {
                        "command": sys.executable,
                        "args": ["-m", "tests.test_mcp_server", "--sandbox-dir", str(sandbox)],
                        "enabled": True,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    audit = AuditLogger(tmp_path / "audit_kill.jsonl")
    manager = ApprovalManager(audit_logger=audit, timeout_seconds=5.0)
    broker = LocalAuthorizationBroker(approval_manager=manager, runtime_file=broker_file)
    info = await broker.start()

    try:
        # Spawn a raw proxy subprocess and kill it abruptly
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "app.proxy.stdio_proxy",
                "--config",
                str(cfg_file),
                "--server",
                "safe-test-server",
                "--use-desktop-guard",
                "--broker-file",
                str(broker_file),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        await asyncio.sleep(0.5)
        proc.kill()
        proc.wait(timeout=5.0)

        # Broker must remain healthy and responsive
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(
                f"{info.url}/health",
                headers={"Authorization": f"Bearer {info.token}"},
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "protected"
    finally:
        await broker.stop()
        audit.close()
