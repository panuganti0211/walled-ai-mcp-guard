"""Phase 3 tests for RequestManager, ApprovalManager, AuditLogger, and real MCP integration."""

from __future__ import annotations

import ast
import asyncio
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import anyio
import mcp.types as types
import pytest
from mcp.client.session import ClientSession
from mcp.shared.exceptions import MCPError
from mcp.shared.memory import create_client_server_memory_streams

from app.authorization.approval_manager import ApprovalManager
from app.authorization.request_manager import (
    DuplicateDecisionError,
    DuplicateExecutionError,
    DuplicateRequestError,
    InvalidStateTransitionError,
    RequestManager,
    UnknownRequestError,
)
from app.config import UpstreamServerConfig
from app.models.request import (
    ERR_AUTHORIZATION_CANCELLED,
    ERR_AUTHORIZATION_DENIED,
    ERR_AUTHORIZATION_SYSTEM_FAILURE,
    AuthorizationDecision,
    DecisionOutcome,
    InterceptedRequest,
    RequestStatus,
)
from app.monitoring.audit_logger import AuditLogger, redact_sensitive_data, redact_text
from app.proxy.stdio_proxy import StdioMCPProxy


def _make_test_server_config(sandbox_dir: Path) -> UpstreamServerConfig:
    return UpstreamServerConfig(
        description="Safe local test MCP server",
        transport="stdio",
        command=sys.executable,
        args=["-m", "tests.test_mcp_server", "--sandbox-dir", str(sandbox_dir)],
        env={},
        enabled=True,
    )


@asynccontextmanager
async def _connected_proxy_with_approval(
    sandbox_dir: Path,
    approval_manager: ApprovalManager,
) -> AsyncIterator[tuple[ClientSession, StdioMCPProxy]]:
    proxy = StdioMCPProxy(
        server_name="safe-test-server",
        server_config=_make_test_server_config(sandbox_dir),
        authorizer=approval_manager,
    )
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        client_read, client_write = client_streams
        server_read, server_write = server_streams
        async with anyio.create_task_group() as tg:
            tg.start_soon(proxy.run_streams, server_read, server_write)
            try:
                async with ClientSession(client_read, client_write) as session:
                    yield session, proxy
            finally:
                await client_write.aclose()
                await client_read.aclose()


def _read_jsonl(path: Path) -> list[dict]:
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return [json.loads(line) for line in lines]


# ======================================================================
# 1. RequestManager Lifecycle & Strict State Machine Tests
# ======================================================================


def test_request_manager_allow_lifecycle_and_parameter_isolation() -> None:
    rm = RequestManager()
    original_args = {"filename": "demo.txt", "nested": {"k": "v"}}
    req = InterceptedRequest(
        server_name="safe-test-server",
        tool_name="create_test_file",
        arguments=original_args,
        jsonrpc_request_id=42,
    )
    rm.register(req)

    # Mutating caller dict must not affect stored request parameters
    original_args["nested"]["k"] = "tampered"
    stored = rm.get_required(req.internal_id)
    assert stored.arguments["nested"]["k"] == "v"
    assert stored.jsonrpc_request_id == 42
    assert stored.status is RequestStatus.PENDING
    assert stored.completed_at is None

    rm.record_decision(
        req.internal_id,
        AuthorizationDecision(DecisionOutcome.ALLOW, reason="ok"),
    )
    assert stored.status is RequestStatus.APPROVED
    assert stored.completed_at is None

    rm.mark_executing(req.internal_id)
    assert stored.status is RequestStatus.EXECUTING
    assert rm.has_been_executed(req.internal_id) is True

    rm.mark_completed(req.internal_id)
    assert stored.status is RequestStatus.COMPLETED
    assert stored.completed_at is not None

    stats = rm.get_stats()
    assert stats["total"] == 1
    assert stats["completed"] == 1
    assert stats["approved_total"] == 1


def test_request_manager_block_transition() -> None:
    rm = RequestManager()
    req = InterceptedRequest(
        server_name="safe-test-server",
        tool_name="create_test_file",
        arguments={"filename": "blocked.txt"},
        jsonrpc_request_id="req-99",
    )
    rm.register(req)
    rm.record_decision(
        req.internal_id,
        AuthorizationDecision(DecisionOutcome.BLOCK, reason="Denied"),
    )
    assert req.status is RequestStatus.BLOCKED
    assert req.completed_at is not None
    assert req.decision is not None and not req.decision.is_allowed


def test_request_manager_prevents_invalid_transitions_and_duplicates() -> None:
    rm = RequestManager()
    req_blocked = InterceptedRequest(
        server_name="s", tool_name="t", jsonrpc_request_id=1
    )
    rm.register(req_blocked)

    # Duplicate registration forbidden
    with pytest.raises(DuplicateRequestError):
        rm.register(req_blocked)

    # Cannot jump directly from PENDING -> COMPLETED or PENDING -> EXECUTING
    with pytest.raises(InvalidStateTransitionError):
        rm.transition(req_blocked.internal_id, RequestStatus.COMPLETED)
    with pytest.raises(DuplicateExecutionError):
        rm.mark_executing(req_blocked.internal_id)

    # Block the request
    rm.record_decision(
        req_blocked.internal_id, AuthorizationDecision(DecisionOutcome.BLOCK)
    )

    # Cannot approve an already BLOCKED request
    with pytest.raises(DuplicateDecisionError):
        rm.record_decision(
            req_blocked.internal_id, AuthorizationDecision(DecisionOutcome.ALLOW)
        )

    # Cannot execute a BLOCKED request
    with pytest.raises(DuplicateExecutionError):
        rm.mark_executing(req_blocked.internal_id)

    # Completed request cannot be approved again or executed twice
    req_done = InterceptedRequest(
        server_name="s", tool_name="t", jsonrpc_request_id=2
    )
    rm.register(req_done)
    rm.record_decision(
        req_done.internal_id, AuthorizationDecision(DecisionOutcome.ALLOW)
    )
    rm.mark_executing(req_done.internal_id)

    # Duplicate execution attempt rejected
    with pytest.raises(DuplicateExecutionError):
        rm.mark_executing(req_done.internal_id)

    rm.mark_completed(req_done.internal_id)

    # Approving an already COMPLETED request rejected
    with pytest.raises(DuplicateDecisionError):
        rm.record_decision(
            req_done.internal_id, AuthorizationDecision(DecisionOutcome.ALLOW)
        )

    # Unknown request raises UnknownRequestError
    with pytest.raises(UnknownRequestError):
        rm.get_required("does-not-exist")


# ======================================================================
# 2. ApprovalManager Unit Tests (Independence, Duplicates, Timeout, Shutdown)
# ======================================================================


def test_authorization_modules_have_no_pyside6_dependency() -> None:
    """Verify ApprovalManager and RequestManager remain completely independent of PySide6."""
    for rel_path in (
        "app/authorization/approval_manager.py",
        "app/authorization/request_manager.py",
        "app/monitoring/audit_logger.py",
    ):
        tree = ast.parse(Path(rel_path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("PySide6")
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("PySide6")


@pytest.mark.asyncio
async def test_approval_manager_independent_decisions_and_duplicate_rejection(
    tmp_path: Path,
) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    pending_events: dict[str, asyncio.Event] = {}

    def on_pending(req: InterceptedRequest) -> None:
        ev = pending_events.setdefault(req.tool_name, asyncio.Event())
        ev.set()

    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=10.0,
        on_pending_request=on_pending,
    )

    req_a = InterceptedRequest(
        server_name="srv", tool_name="tool_a", jsonrpc_request_id=10
    )
    req_b = InterceptedRequest(
        server_name="srv", tool_name="tool_b", jsonrpc_request_id=11
    )

    task_a = asyncio.create_task(manager.authorize(req_a))
    task_b = asyncio.create_task(manager.authorize(req_b))

    await asyncio.wait_for(
        pending_events.setdefault("tool_a", asyncio.Event()).wait(), timeout=2.0
    )
    await asyncio.wait_for(
        pending_events.setdefault("tool_b", asyncio.Event()).wait(), timeout=2.0
    )

    assert set(manager.pending_ids()) == {req_a.internal_id, req_b.internal_id}

    # Resolve B as BLOCK first; A must remain PENDING
    manager.block(req_b.internal_id, reason="Not permitted")
    decision_b = await asyncio.wait_for(task_b, timeout=2.0)
    assert decision_b.outcome is DecisionOutcome.BLOCK
    assert req_b.status is RequestStatus.BLOCKED
    assert req_a.status is RequestStatus.PENDING

    # Duplicate decision on B (approve after block) MUST fail
    with pytest.raises(DuplicateDecisionError):
        manager.approve(req_b.internal_id)
    with pytest.raises(DuplicateDecisionError):
        manager.block(req_b.internal_id)

    # Resolve A as ALLOW independently
    manager.approve(req_a.internal_id, reason="Explicit allow")
    decision_a = await asyncio.wait_for(task_a, timeout=2.0)
    assert decision_a.outcome is DecisionOutcome.ALLOW
    assert req_a.status is RequestStatus.APPROVED

    # Duplicate decision on A (approve twice or block after approve) MUST fail
    with pytest.raises(DuplicateDecisionError):
        manager.approve(req_a.internal_id)
    with pytest.raises(DuplicateDecisionError):
        manager.block(req_a.internal_id)

    audit.close()


@pytest.mark.asyncio
async def test_approval_manager_timeout_rejects_and_audits(tmp_path: Path) -> None:
    log_path = tmp_path / "timeout_audit.jsonl"
    audit = AuditLogger(log_path)
    manager = ApprovalManager(audit_logger=audit, timeout_seconds=0.15)

    req = InterceptedRequest(
        server_name="srv",
        tool_name="create_test_file",
        arguments={"filename": "never.txt"},
        jsonrpc_request_id=77,
    )
    decision = await manager.authorize(req)
    assert decision.outcome is DecisionOutcome.TIMEOUT
    assert not decision.is_allowed
    assert req.status is RequestStatus.TIMED_OUT
    assert req.completed_at is not None

    # Approving after timeout MUST be rejected
    with pytest.raises(DuplicateDecisionError):
        manager.approve(req.internal_id)

    audit.close()
    records = _read_jsonl(log_path)
    timeout_records = [r for r in records if r["event_type"] == "REQUEST_TIMED_OUT"]
    assert len(timeout_records) == 1
    assert timeout_records[0]["status"] == "TIMED_OUT"
    assert timeout_records[0]["decision"] == "TIMEOUT"
    assert timeout_records[0]["request_id"] == 77
    assert timeout_records[0]["execution_result"] == "not_executed"


@pytest.mark.asyncio
async def test_approval_manager_external_task_cancellation(tmp_path: Path) -> None:
    log_path = tmp_path / "cancel_audit.jsonl"
    audit = AuditLogger(log_path)
    arrived = asyncio.Event()
    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=10.0,
        on_pending_request=lambda r: arrived.set(),
    )

    req = InterceptedRequest(
        server_name="srv", tool_name="create_test_file", jsonrpc_request_id=88
    )
    task = asyncio.create_task(manager.authorize(req))
    await asyncio.wait_for(arrived.wait(), timeout=2.0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert req.status is RequestStatus.CANCELLED
    assert manager.pending_ids() == []
    audit.close()

    records = _read_jsonl(log_path)
    assert any(r["event_type"] == "REQUEST_CANCELLED" for r in records)


@pytest.mark.asyncio
async def test_approval_manager_pending_callback_failure_fails_closed(
    tmp_path: Path,
) -> None:
    audit = AuditLogger(tmp_path / "cb_err.jsonl")

    def broken_ui_hook(req: InterceptedRequest) -> None:
        raise RuntimeError("Popup display crashed")

    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=5.0,
        on_pending_request=broken_ui_hook,
    )
    req = InterceptedRequest(
        server_name="srv", tool_name="create_test_file", jsonrpc_request_id=55
    )
    decision = await manager.authorize(req)
    assert decision.outcome is DecisionOutcome.ERROR
    assert not decision.is_allowed
    assert req.status is RequestStatus.FAILED
    assert manager.pending_ids() == []
    audit.close()


# ======================================================================
# 3. Audit Logger & Recursive Sensitive-Field Redaction Tests
# ======================================================================


def test_recursive_sensitive_field_redaction() -> None:
    payload = {
        "filename": "report.txt",
        "password": "SuperSecretPassword123!",
        "content": "Confidential customer PII and source code body",
        "headers": {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig",
            "X-API-Key": "sk-live-1234567890abcdef",
            "safe_header": "application/json",
        },
        "nested_list": [
            {"client_secret": "top-secret-val", "label": "ok"},
            "ghp_abcdefghijklmnopqrstuvwxyz123456",
            {"notes": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."},
        ],
        "token": "tok_999999",
    }

    redacted = redact_sensitive_data(payload)
    dumped = json.dumps(redacted)

    # Sensitive values and raw file content MUST NOT leak
    for secret in (
        "SuperSecretPassword123!",
        "Confidential customer PII",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "sk-live-1234567890abcdef",
        "top-secret-val",
        "ghp_abcdefghijklmnopqrstuvwxyz123456",
        "BEGIN RSA PRIVATE KEY",
        "tok_999999",
    ):
        assert secret not in dumped

    assert redacted["filename"] == "report.txt"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["content"].startswith("[REDACTED_CONTENT len=")
    assert redacted["headers"]["Authorization"] == "[REDACTED]"
    assert redacted["headers"]["X-API-Key"] == "[REDACTED]"
    assert redacted["headers"]["safe_header"] == "application/json"
    assert redacted["nested_list"][0]["client_secret"] == "[REDACTED]"
    assert redacted["nested_list"][0]["label"] == "ok"
    assert redacted["nested_list"][1] == "[REDACTED]"
    assert redacted["nested_list"][2]["notes"] == "[REDACTED]"
    assert redacted["token"] == "[REDACTED]"

    # Free-form text redaction
    scrubbed = redact_text("Failed auth with api_key=sk-test-12345678901234 and password=hunter2")
    assert scrubbed is not None
    assert "sk-test-12345678901234" not in scrubbed
    assert "hunter2" not in scrubbed


@pytest.mark.asyncio
async def test_audit_logger_failure_never_approves_or_crashes(tmp_path: Path) -> None:
    """When the audit log target is unwritable, blocked requests stay blocked and no crash occurs."""
    # Point log_path at an existing directory to force an OSError on FileHandler open.
    unwritable_path = tmp_path / "dir_not_file"
    unwritable_path.mkdir()

    errors_seen: list[Exception] = []
    failing_audit = AuditLogger(
        unwritable_path, on_log_error=lambda exc: errors_seen.append(exc)
    )

    sandbox = tmp_path / "sandbox"
    marker = sandbox / "audit_fail_blocked_marker.txt"
    arrived = asyncio.Event()
    pending_ref: list[InterceptedRequest] = []

    def on_pending(req: InterceptedRequest) -> None:
        pending_ref.append(req)
        arrived.set()

    manager = ApprovalManager(
        audit_logger=failing_audit,
        timeout_seconds=5.0,
        on_pending_request=on_pending,
    )

    async with _connected_proxy_with_approval(sandbox, manager) as (session, _):
        await session.initialize()

        call_task = asyncio.create_task(
            session.call_tool(
                "create_test_file",
                {"filename": "audit_fail_blocked_marker.txt", "content": "nope"},
            )
        )
        await asyncio.wait_for(arrived.wait(), timeout=5.0)
        manager.block(pending_ref[0].internal_id, reason="Blocked despite log error")

        with pytest.raises(MCPError) as exc_info:
            await asyncio.wait_for(call_task, timeout=5.0)

        assert exc_info.value.error.code == ERR_AUTHORIZATION_DENIED
        assert not marker.exists(), "Audit failure must NEVER allow blocked tool execution!"
        assert len(errors_seen) >= 1

    failing_audit.close()


# ======================================================================
# 4. Real End-to-End MCP Integration Tests with ApprovalManager & AuditLogger
# ======================================================================


@pytest.mark.asyncio
async def test_real_mcp_no_upstream_execution_after_timeout(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    marker = sandbox / "timeout_marker.txt"
    log_path = tmp_path / "audit_timeout.jsonl"
    audit = AuditLogger(log_path)
    manager = ApprovalManager(audit_logger=audit, timeout_seconds=0.25)

    async with _connected_proxy_with_approval(sandbox, manager) as (session, _):
        await session.initialize()

        with pytest.raises(MCPError) as exc_info:
            await session.call_tool(
                "create_test_file",
                {"filename": "timeout_marker.txt", "content": "MUST_NOT_EXIST"},
            )

        assert exc_info.value.error.code == types.REQUEST_TIMEOUT
        assert not marker.exists(), "Timed-out tool must NEVER execute upstream!"

    audit.close()
    records = _read_jsonl(log_path)
    assert any(
        r["event_type"] == "REQUEST_TIMED_OUT"
        and r["status"] == "TIMED_OUT"
        and r["execution_result"] == "not_executed"
        for r in records
    )


@pytest.mark.asyncio
async def test_real_mcp_shutdown_cancels_pending_and_prevents_upstream_execution(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    marker1 = sandbox / "shutdown_marker_1.txt"
    marker2 = sandbox / "shutdown_marker_2.txt"
    log_path = tmp_path / "audit_shutdown.jsonl"
    audit = AuditLogger(log_path)

    arrived_all = asyncio.Event()
    arrived_reqs: list[InterceptedRequest] = []

    def on_pending(req: InterceptedRequest) -> None:
        arrived_reqs.append(req)
        if len(arrived_reqs) == 2:
            arrived_all.set()

    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=30.0,
        on_pending_request=on_pending,
    )

    async with _connected_proxy_with_approval(sandbox, manager) as (session, _):
        await session.initialize()

        t1 = asyncio.create_task(
            session.call_tool(
                "create_test_file",
                {"filename": "shutdown_marker_1.txt", "content": "nope1"},
            )
        )
        t2 = asyncio.create_task(
            session.call_tool(
                "create_test_file",
                {"filename": "shutdown_marker_2.txt", "content": "nope2"},
            )
        )

        await asyncio.wait_for(arrived_all.wait(), timeout=5.0)
        assert len(manager.pending_ids()) == 2

        cancelled_ids = await manager.shutdown(reason="Desktop app closing")
        assert len(cancelled_ids) == 2
        assert manager.pending_ids() == []

        with pytest.raises(MCPError) as exc1:
            await asyncio.wait_for(t1, timeout=5.0)
        with pytest.raises(MCPError) as exc2:
            await asyncio.wait_for(t2, timeout=5.0)

        assert exc1.value.error.code == ERR_AUTHORIZATION_CANCELLED
        assert exc2.value.error.code == ERR_AUTHORIZATION_CANCELLED
        assert not marker1.exists(), "Cancelled request 1 must NEVER execute upstream!"
        assert not marker2.exists(), "Cancelled request 2 must NEVER execute upstream!"

        # Any request arriving AFTER shutdown is immediately rejected as CANCELLED
        marker3 = sandbox / "post_shutdown_marker.txt"
        with pytest.raises(MCPError) as exc3:
            await session.call_tool(
                "create_test_file",
                {"filename": "post_shutdown_marker.txt", "content": "nope3"},
            )
        assert exc3.value.error.code == ERR_AUTHORIZATION_CANCELLED
        assert not marker3.exists()

    audit.close()
    records = _read_jsonl(log_path)
    cancelled_records = [r for r in records if r["event_type"] == "REQUEST_CANCELLED"]
    assert len(cancelled_records) == 3
    assert all(r["status"] == "CANCELLED" for r in cancelled_records)
    assert all(r["execution_result"] == "not_executed" for r in cancelled_records)


@pytest.mark.asyncio
async def test_real_mcp_concurrent_approvals_blocks_timeout_and_audit_trail(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    log_path = tmp_path / "audit_concurrent.jsonl"
    audit = AuditLogger(log_path)

    all_four_arrived = asyncio.Event()
    by_filename: dict[str, InterceptedRequest] = {}

    def on_pending(req: InterceptedRequest) -> None:
        fname = req.arguments.get("filename")
        if isinstance(fname, str):
            by_filename[fname] = req
            if len(by_filename) == 4:
                all_four_arrived.set()

    manager = ApprovalManager(
        audit_logger=audit,
        timeout_seconds=0.8,
        on_pending_request=on_pending,
    )

    async with _connected_proxy_with_approval(sandbox, manager) as (session, _):
        await session.initialize()

        t_allow_1 = asyncio.create_task(
            session.call_tool(
                "create_test_file",
                {"filename": "allow_1.txt", "content": "secret_body_alpha"},
            )
        )
        t_allow_2 = asyncio.create_task(
            session.call_tool(
                "create_test_file",
                {"filename": "allow_2.txt", "content": "secret_body_beta"},
            )
        )
        t_block = asyncio.create_task(
            session.call_tool(
                "create_test_file",
                {"filename": "block_1.txt", "content": "should_never_exist"},
            )
        )
        t_timeout = asyncio.create_task(
            session.call_tool(
                "create_test_file",
                {"filename": "timeout_1.txt", "content": "should_time_out"},
            )
        )

        await asyncio.wait_for(all_four_arrived.wait(), timeout=5.0)
        assert len(manager.pending_ids()) == 4

        # Verify all 4 have independent internal IDs and JSON-RPC request IDs
        assert len({r.internal_id for r in by_filename.values()}) == 4
        assert len({r.jsonrpc_request_id for r in by_filename.values()}) == 4

        # Resolve out of order: allow_2, block_1, allow_1; leave timeout_1 undecided
        manager.approve(by_filename["allow_2.txt"].internal_id)
        manager.block(by_filename["block_1.txt"].internal_id, reason="Blocked in batch")
        manager.approve(by_filename["allow_1.txt"].internal_id)

        res2 = await asyncio.wait_for(t_allow_2, timeout=5.0)
        res1 = await asyncio.wait_for(t_allow_1, timeout=5.0)
        assert not res1.is_error
        assert not res2.is_error

        with pytest.raises(MCPError) as block_exc:
            await asyncio.wait_for(t_block, timeout=5.0)
        assert block_exc.value.error.code == ERR_AUTHORIZATION_DENIED

        with pytest.raises(MCPError) as timeout_exc:
            await asyncio.wait_for(t_timeout, timeout=5.0)
        assert timeout_exc.value.error.code == types.REQUEST_TIMEOUT

        # Disk verification
        assert (sandbox / "allow_1.txt").read_text(encoding="utf-8") == "secret_body_alpha"
        assert (sandbox / "allow_2.txt").read_text(encoding="utf-8") == "secret_body_beta"
        assert not (sandbox / "block_1.txt").exists()
        assert not (sandbox / "timeout_1.txt").exists()

        # RequestManager stats verification
        stats = manager.request_manager.get_stats()
        assert stats["total"] == 4
        assert stats["completed"] == 2
        assert stats["blocked"] == 1
        assert stats["timed_out"] == 1
        assert stats["pending"] == 0

    audit.close()

    # Audit log verification: complete trail & file contents NEVER leaked to disk log
    raw_log = log_path.read_text(encoding="utf-8")
    assert "secret_body_alpha" not in raw_log
    assert "secret_body_beta" not in raw_log
    assert "should_never_exist" not in raw_log

    records = _read_jsonl(log_path)
    event_types = {r["event_type"] for r in records}
    assert {
        "REQUEST_RECEIVED",
        "DECISION_APPROVED",
        "EXECUTION_STARTED",
        "EXECUTION_COMPLETED",
        "DECISION_BLOCKED",
        "REQUEST_TIMED_OUT",
    }.issubset(event_types)
