"""Phase 5 dedicated blocking & zero-bypass enforcement tests."""

from __future__ import annotations

import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.exceptions import MCPError
from mcp.shared.memory import create_client_server_memory_streams

from app.authorization.approval_manager import ApprovalManager
from app.config import UpstreamServerConfig
from app.models.request import (
    ERR_AUTHORIZATION_DENIED,
    ERR_AUTHORIZATION_SYSTEM_FAILURE,
    AuthorizationDecision,
    DecisionOutcome,
    InterceptedRequest,
    RequestStatus,
)
from app.monitoring.audit_logger import AuditLogger
from app.proxy.stdio_proxy import StdioMCPProxy


def _server_cfg(sandbox: Path) -> UpstreamServerConfig:
    return UpstreamServerConfig(
        description="Safe test server",
        transport="stdio",
        command=sys.executable,
        args=["-m", "tests.test_mcp_server", "--sandbox-dir", str(sandbox)],
        enabled=True,
    )


@asynccontextmanager
async def _proxy_session(
    sandbox: Path, authorizer
) -> AsyncIterator[tuple[ClientSession, StdioMCPProxy]]:
    proxy = StdioMCPProxy(
        server_name="safe-test-server",
        server_config=_server_cfg(sandbox),
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


@pytest.mark.asyncio
async def test_approving_one_call_never_authorizes_subsequent_calls_for_same_tool(
    tmp_path: Path,
) -> None:
    """Every invocation of the same tool requires its own independent approval."""
    sandbox = tmp_path / "sandbox"
    audit = AuditLogger(tmp_path / "audit.jsonl")

    decisions_queue = [
        ("allow", "approved_first.txt"),
        ("block", "blocked_second.txt"),
        ("allow", "approved_third.txt"),
        ("block", "blocked_fourth.txt"),
    ]
    decision_iter = iter(decisions_queue)

    def on_pending(req: InterceptedRequest) -> None:
        action, expected_file = next(decision_iter)
        assert req.arguments["filename"] == expected_file
        if action == "allow":
            manager.approve(req.internal_id, reason="Explicit single approval")
        else:
            manager.block(req.internal_id, reason="Explicit single block")

    manager = ApprovalManager(
        audit_logger=audit, timeout_seconds=10.0, on_pending_request=on_pending
    )

    async with _proxy_session(sandbox, manager) as (session, _):
        await session.initialize()

        for action, fname in decisions_queue:
            if action == "allow":
                res = await session.call_tool(
                    "create_test_file",
                    {"filename": fname, "content": f"ok:{fname}"},
                )
                assert not res.is_error
            else:
                with pytest.raises(MCPError) as exc:
                    await session.call_tool(
                        "create_test_file",
                        {"filename": fname, "content": f"MUST_NOT_EXIST:{fname}"},
                    )
                assert exc.value.error.code == ERR_AUTHORIZATION_DENIED

    assert (sandbox / "approved_first.txt").exists()
    assert not (sandbox / "blocked_second.txt").exists()
    assert (sandbox / "approved_third.txt").exists()
    assert not (sandbox / "blocked_fourth.txt").exists()
    audit.close()


@pytest.mark.asyncio
async def test_duplicate_internal_id_replay_fails_closed(tmp_path: Path) -> None:
    """Replaying an already-used internal_id into ApprovalManager MUST fail closed."""
    audit = AuditLogger(tmp_path / "audit_replay.jsonl")
    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=5.0,
        on_pending_request=lambda r: manager.block(r.internal_id, reason="Blocked"),
    )

    req1 = InterceptedRequest(
        internal_id="fixed-replay-id-001",
        server_name="safe-test-server",
        tool_name="create_test_file",
        arguments={"filename": "replay.txt", "content": "x"},
        jsonrpc_request_id=1,
    )
    d1 = await manager.authorize(req1)
    assert d1.outcome is DecisionOutcome.BLOCK
    assert req1.status is RequestStatus.BLOCKED

    # Replay the exact same internal_id — MUST fail closed and NEVER overwrite original record
    req2 = InterceptedRequest(
        internal_id="fixed-replay-id-001",
        server_name="safe-test-server",
        tool_name="create_test_file",
        arguments={"filename": "replay.txt", "content": "x"},
        jsonrpc_request_id=2,
    )
    d2 = await manager.authorize(req2)
    assert d2.outcome is DecisionOutcome.ERROR
    assert not d2.is_allowed
    assert manager.request_manager.get_required("fixed-replay-id-001").status is RequestStatus.BLOCKED
    audit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome",
    [
        DecisionOutcome.BLOCK,
        DecisionOutcome.TIMEOUT,
        DecisionOutcome.CANCELLED,
        DecisionOutcome.ERROR,
    ],
)
async def test_all_non_allow_outcomes_prevent_upstream_execution(
    tmp_path: Path, outcome: DecisionOutcome
) -> None:
    """Only DecisionOutcome.ALLOW may ever reach the upstream server."""
    sandbox = tmp_path / f"sandbox_{outcome.value}"
    marker = sandbox / f"marker_{outcome.value}.txt"

    class FixedOutcomeAuthorizer:
        async def authorize(self, request: InterceptedRequest) -> AuthorizationDecision:
            return AuthorizationDecision(
                outcome=outcome, reason=f"Forced {outcome.value}"
            )

    async with _proxy_session(sandbox, FixedOutcomeAuthorizer()) as (session, _):
        await session.initialize()
        with pytest.raises(MCPError):
            await session.call_tool(
                "create_test_file",
                {"filename": marker.name, "content": "MUST_NOT_EXIST"},
            )

    assert not marker.exists(), f"Outcome {outcome.value} leaked to upstream!"


@pytest.mark.asyncio
async def test_blocked_call_never_executes_even_if_duplicate_execution_attempted(
    tmp_path: Path,
) -> None:
    """Attempting to execute an already-executed request fails closed."""
    sandbox = tmp_path / "sandbox"
    audit = AuditLogger(tmp_path / "audit_dup.jsonl")
    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=5.0,
        on_pending_request=lambda r: manager.approve(r.internal_id),
    )

    async with _proxy_session(sandbox, manager) as (session, proxy):
        await session.initialize()
        res = await session.call_tool(
            "create_test_file",
            {"filename": "once.txt", "content": "hello"},
        )
        assert not res.is_error
        assert (sandbox / "once.txt").read_text(encoding="utf-8") == "hello"

        assert proxy.handler is not None
        first_id = proxy.handler.history[0].internal_id
        # Second begin_execution for the same internal_id must be rejected
        with pytest.raises(Exception):
            manager.begin_execution(first_id)
    audit.close()
