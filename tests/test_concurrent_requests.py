"""Phase 5 concurrency stress tests (10, 25, 50 simultaneous MCP requests & GUI load)."""

from __future__ import annotations

import asyncio
import json
import os
import random
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import anyio
import mcp.types as types
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError
from mcp.shared.memory import create_client_server_memory_streams
from PySide6.QtWidgets import QApplication

from app.authorization.approval_manager import ApprovalManager
from app.authorization.ipc_broker import LocalAuthorizationBroker, RemoteBrokerAuthorizer
from app.config import UpstreamServerConfig
from app.main import GuardController
from app.models.request import (
    ERR_AUTHORIZATION_DENIED,
    InterceptedRequest,
    RequestStatus,
)
from app.monitoring.audit_logger import AuditLogger
from app.proxy.stdio_proxy import StdioMCPProxy
from app.ui.main_window import MainWindow


def _server_cfg(sandbox: Path) -> UpstreamServerConfig:
    return UpstreamServerConfig(
        description="Safe local test MCP server",
        transport="stdio",
        command=sys.executable,
        args=["-m", "tests.test_mcp_server", "--sandbox-dir", str(sandbox)],
        enabled=True,
    )


@asynccontextmanager
async def _proxy_with_manager(
    sandbox: Path, manager: ApprovalManager
) -> AsyncIterator[tuple[ClientSession, StdioMCPProxy]]:
    proxy = StdioMCPProxy(
        server_name="safe-test-server",
        server_config=_server_cfg(sandbox),
        authorizer=manager,
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


@pytest.mark.asyncio
@pytest.mark.parametrize("total_count", [10, 25, 50])
async def test_simultaneous_mcp_requests_stress_mixed_allow_block_out_of_order(
    tmp_path: Path, total_count: int
) -> None:
    """Stress test 10, 25, and 50 simultaneous real MCP tool calls with out-of-order decisions."""
    sandbox = tmp_path / f"sandbox_{total_count}"
    audit = AuditLogger(tmp_path / f"audit_{total_count}.jsonl")

    all_arrived = asyncio.Event()
    pending_by_file: dict[str, InterceptedRequest] = {}

    def on_pending(req: InterceptedRequest) -> None:
        fname = req.arguments["filename"]
        pending_by_file[fname] = req
        if len(pending_by_file) == total_count:
            all_arrived.set()

    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=30.0,
        on_pending_request=on_pending,
    )

    async with _proxy_with_manager(sandbox, manager) as (session, _):
        await session.initialize()

        tasks: list[tuple[int, str, bool, asyncio.Task[Any]]] = []
        for idx in range(total_count):
            should_allow = (idx % 2 == 0)
            fname = f"stress_{total_count}_{idx:03d}.txt"
            task = asyncio.create_task(
                session.call_tool(
                    "create_test_file",
                    {"filename": fname, "content": f"payload-{idx}"},
                )
            )
            tasks.append((idx, fname, should_allow, task))

        # Wait until ALL N requests are held pending concurrently
        await asyncio.wait_for(all_arrived.wait(), timeout=20.0)
        assert len(pending_by_file) == total_count
        assert len(manager.pending_ids()) == total_count

        # Every request must have a unique internal_id AND distinct JSON-RPC request_id
        assert len({r.internal_id for r in pending_by_file.values()}) == total_count
        assert len({r.jsonrpc_request_id for r in pending_by_file.values()}) == total_count

        # Resolve in deterministic pseudo-random out-of-order permutation
        rng = random.Random(2026 + total_count)
        order = list(tasks)
        rng.shuffle(order)

        for idx, fname, should_allow, _ in order:
            req = pending_by_file[fname]
            if should_allow:
                manager.approve(req.internal_id, reason=f"Allow #{idx}")
            else:
                manager.block(req.internal_id, reason=f"Block #{idx}")

        outcomes = await asyncio.wait_for(
            asyncio.gather(*(t for _, _, _, t in tasks), return_exceptions=True),
            timeout=30.0,
        )

        expected_allowed = 0
        expected_blocked = 0
        for (idx, fname, should_allow, _), outcome in zip(tasks, outcomes):
            target = sandbox / fname
            if should_allow:
                expected_allowed += 1
                assert not isinstance(outcome, Exception), f"Allowed #{idx} failed: {outcome}"
                assert not outcome.is_error
                assert target.read_text(encoding="utf-8") == f"payload-{idx}"
            else:
                expected_blocked += 1
                assert isinstance(outcome, MCPError)
                assert outcome.error.code == ERR_AUTHORIZATION_DENIED
                assert not target.exists(), f"Blocked file {fname} was created!"

        stats = manager.request_manager.get_stats()
        assert stats["total"] == total_count
        assert stats["completed"] == expected_allowed
        assert stats["approved_total"] == expected_allowed
        assert stats["blocked"] == expected_blocked
        assert stats["pending"] == 0

    audit.close()


@pytest.mark.asyncio
async def test_concurrent_mixed_allow_block_and_multiple_timeouts(
    tmp_path: Path,
) -> None:
    """Verify simultaneous Allow, Block, and multiple independent Timeouts."""
    sandbox = tmp_path / "sandbox_timeouts"
    audit = AuditLogger(tmp_path / "audit_timeouts.jsonl")

    all_arrived = asyncio.Event()
    by_file: dict[str, InterceptedRequest] = {}

    def on_pending(req: InterceptedRequest) -> None:
        by_file[req.arguments["filename"]] = req
        if len(by_file) == 12:
            all_arrived.set()

    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=0.7,
        on_pending_request=on_pending,
    )

    async with _proxy_with_manager(sandbox, manager) as (session, _):
        await session.initialize()

        tasks: list[tuple[str, str, asyncio.Task[Any]]] = []
        # 4 allow, 4 block, 4 timeout
        for i in range(4):
            for mode in ("allow", "block", "timeout"):
                fname = f"{mode}_{i}.txt"
                t = asyncio.create_task(
                    session.call_tool(
                        "create_test_file",
                        {"filename": fname, "content": f"body-{fname}"},
                    )
                )
                tasks.append((mode, fname, t))

        await asyncio.wait_for(all_arrived.wait(), timeout=10.0)

        for mode, fname, _ in tasks:
            if mode == "allow":
                manager.approve(by_file[fname].internal_id)
            elif mode == "block":
                manager.block(by_file[fname].internal_id, reason="Denied")
            # mode == "timeout": intentionally left undecided

        results = await asyncio.wait_for(
            asyncio.gather(*(t for _, _, t in tasks), return_exceptions=True),
            timeout=10.0,
        )

        for (mode, fname, _), res in zip(tasks, results):
            fpath = sandbox / fname
            if mode == "allow":
                assert not isinstance(res, Exception)
                assert fpath.exists()
            elif mode == "block":
                assert isinstance(res, MCPError)
                assert res.error.code == ERR_AUTHORIZATION_DENIED
                assert not fpath.exists()
            else:
                assert isinstance(res, MCPError)
                assert res.error.code == types.REQUEST_TIMEOUT
                assert not fpath.exists()

        stats = manager.request_manager.get_stats()
        assert stats["total"] == 12
        assert stats["completed"] == 4
        assert stats["blocked"] == 4
        assert stats["timed_out"] == 4
        assert stats["pending"] == 0

    audit.close()


@pytest.mark.asyncio
async def test_rapid_consecutive_requests_same_tool(tmp_path: Path) -> None:
    """20 rapid consecutive requests alternating Allow and Block."""
    sandbox = tmp_path / "sandbox_rapid"
    audit = AuditLogger(tmp_path / "audit_rapid.jsonl")

    def on_pending(req: InterceptedRequest) -> None:
        idx = int(req.arguments["filename"].split("_")[1].split(".")[0])
        if idx % 2 == 0:
            manager.approve(req.internal_id)
        else:
            manager.block(req.internal_id)

    manager = ApprovalManager(
        audit_logger=audit, timeout_seconds=10.0, on_pending_request=on_pending
    )

    async with _proxy_with_manager(sandbox, manager) as (session, _):
        await session.initialize()
        for i in range(20):
            fname = f"rapid_{i:02d}.txt"
            if i % 2 == 0:
                res = await session.call_tool(
                    "create_test_file", {"filename": fname, "content": f"v{i}"}
                )
                assert not res.is_error
                assert (sandbox / fname).read_text(encoding="utf-8") == f"v{i}"
            else:
                with pytest.raises(MCPError) as exc:
                    await session.call_tool(
                        "create_test_file", {"filename": fname, "content": "nope"}
                    )
                assert exc.value.error.code == ERR_AUTHORIZATION_DENIED
                assert not (sandbox / fname).exists()

    stats = manager.request_manager.get_stats()
    assert stats["total"] == 20
    assert stats["completed"] == 10
    assert stats["blocked"] == 10
    audit.close()


@pytest.mark.asyncio
async def test_multiple_concurrent_client_connections_through_shared_broker(
    tmp_path: Path,
) -> None:
    """Two independent STDIO proxy client sessions concurrently hitting one broker."""
    sandbox_a = tmp_path / "sandbox_a"
    sandbox_b = tmp_path / "sandbox_b"
    broker_file = tmp_path / "shared_broker.json"
    audit = AuditLogger(tmp_path / "audit_multi_clients.jsonl")

    all_arrived = asyncio.Event()
    pending_map: dict[str, InterceptedRequest] = {}

    def on_pending(req: InterceptedRequest) -> None:
        key = f"{req.server_name}:{req.arguments['filename']}"
        pending_map[key] = req
        if len(pending_map) == 6:
            all_arrived.set()

    manager = ApprovalManager(
        audit_logger=audit, timeout_seconds=20.0, on_pending_request=on_pending
    )
    broker = LocalAuthorizationBroker(
        approval_manager=manager, runtime_file=broker_file
    )
    await broker.start()

    try:
        cfg_a = tmp_path / "cfg_a.json"
        cfg_a.write_text(
            json.dumps(
                {
                    "default_server": "server-alpha",
                    "servers": {
                        "server-alpha": {
                            "command": sys.executable,
                            "args": ["-m", "tests.test_mcp_server", "--sandbox-dir", str(sandbox_a)],
                            "enabled": True,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        cfg_b = tmp_path / "cfg_b.json"
        cfg_b.write_text(
            json.dumps(
                {
                    "default_server": "server-beta",
                    "servers": {
                        "server-beta": {
                            "command": sys.executable,
                            "args": ["-m", "tests.test_mcp_server", "--sandbox-dir", str(sandbox_b)],
                            "enabled": True,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        async def _drive_client(cfg: Path, srv_name: str) -> list[Any]:
            params = StdioServerParameters(
                command=sys.executable,
                args=[
                    "-m",
                    "app.proxy.stdio_proxy",
                    "--config",
                    str(cfg),
                    "--server",
                    srv_name,
                    "--use-desktop-guard",
                    "--broker-file",
                    str(broker_file),
                ],
            )
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    tasks = [
                        asyncio.create_task(
                            session.call_tool(
                                "create_test_file",
                                {"filename": f"file_{i}.txt", "content": f"{srv_name}-{i}"},
                            )
                        )
                        for i in range(3)
                    ]
                    return await asyncio.gather(*tasks, return_exceptions=True)

        t_a = asyncio.create_task(_drive_client(cfg_a, "server-alpha"))
        t_b = asyncio.create_task(_drive_client(cfg_b, "server-beta"))

        await asyncio.wait_for(all_arrived.wait(), timeout=20.0)
        assert len(pending_map) == 6

        # Allow file_0 & file_2 on both servers; block file_1 on both servers
        for key, req in list(pending_map.items()):
            if key.endswith("file_1.txt"):
                manager.block(req.internal_id, reason="Blocked file_1")
            else:
                manager.approve(req.internal_id)

        res_a, res_b = await asyncio.wait_for(asyncio.gather(t_a, t_b), timeout=20.0)

        for sandbox, srv_name, results in (
            (sandbox_a, "server-alpha", res_a),
            (sandbox_b, "server-beta", res_b),
        ):
            assert not isinstance(results[0], Exception)
            assert isinstance(results[1], MCPError)
            assert results[1].error.code == ERR_AUTHORIZATION_DENIED
            assert not isinstance(results[2], Exception)
            assert (sandbox / "file_0.txt").read_text(encoding="utf-8") == f"{srv_name}-0"
            assert not (sandbox / "file_1.txt").exists()
            assert (sandbox / "file_2.txt").read_text(encoding="utf-8") == f"{srv_name}-2"
    finally:
        await broker.stop()
        audit.close()


def test_gui_popup_responsiveness_and_mapping_under_heavy_concurrent_load(
    tmp_path: Path,
) -> None:
    """12 simultaneous pending popups in MainWindow decided out of order with zero freeze."""
    app = QApplication.instance() or QApplication(["gui-stress-test"])
    controller = GuardController(
        audit_log_path=tmp_path / "gui_stress_audit.jsonl",
        timeout_seconds=30.0,
        broker_runtime_file=tmp_path / "gui_stress_broker.json",
        enable_local_broker=False,
    )
    window = MainWindow(controller=controller, minimize_to_tray=False)
    try:
        controller.start_monitoring_sync(timeout=5.0)
        count = 12
        futures = []
        for i in range(count):
            req = InterceptedRequest(
                server_name="stress-server",
                tool_name="create_test_file",
                arguments={"filename": f"gui_load_{i:02d}.txt", "content": "x"},
                jsonrpc_request_id=1000 + i,
            )
            futures.append((i, req, controller.worker.submit(controller.approval_manager.authorize(req))))

        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and len(window.active_popups) < count:
            app.processEvents()
            time.sleep(0.01)
        app.processEvents()

        assert len(window.active_popups) == count
        assert window.pending_count_label.text() == str(count)

        # Click buttons out of order (reverse): even -> Allow, odd -> Block
        for i, req, _ in reversed(futures):
            popup = window.active_popups[req.internal_id]
            assert f"gui_load_{i:02d}.txt" in popup.parameters_box.toPlainText()
            if i % 2 == 0:
                popup.allow_button.click()
                # Attempt duplicate click immediately — must be ignored
                popup.block_button.click()
            else:
                popup.block_button.click()
                popup.allow_button.click()
            app.processEvents()

        # Verify every future resolved with the exact intended decision
        for i, req, fut in futures:
            decision = fut.result(timeout=5.0)
            if i % 2 == 0:
                assert decision.is_allowed
                assert req.status is RequestStatus.APPROVED
            else:
                assert not decision.is_allowed
                assert req.status is RequestStatus.BLOCKED

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and len(window.active_popups) > 0:
            app.processEvents()
            time.sleep(0.01)
        app.processEvents()

        assert len(window.active_popups) == 0
        assert window.total_count_label.text() == str(count)
        assert window.approved_count_label.text() == str(count // 2)
        assert window.blocked_count_label.text() == str(count // 2)
        assert window.pending_count_label.text() == "0"
    finally:
        window.prepare_for_exit()
        window.close()
        controller.shutdown_sync()
