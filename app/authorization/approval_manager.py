"""Dedicated asynchronous ApprovalManager for independent MCP tool authorizations.

Completely decoupled from PySide6 so it can be driven by automated tests,
the PySide6 desktop GUI (Phase 4), or a remote approval interface (Phase 8).
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass

from app.authorization.request_manager import (
    DuplicateDecisionError,
    DuplicateExecutionError,
    InvalidStateTransitionError,
    RequestManager,
    UnknownRequestError,
)
from app.models.request import (
    AuthorizationDecision,
    DecisionOutcome,
    InterceptedRequest,
    RequestStatus,
)
from app.monitoring.audit_logger import AuditLogger

logger = logging.getLogger(__name__)


@dataclass
class _PendingApproval:
    request: InterceptedRequest
    loop: asyncio.AbstractEventLoop
    future: asyncio.Future[AuthorizationDecision]


class ApprovalManager:
    """Asynchronous, concurrency-safe authorization manager implementing ToolAuthorizer.

    Security invariants:
    - Every intercepted request receives an independent `asyncio.Future`.
    - Decisions are strictly one-shot; duplicate decisions raise `DuplicateDecisionError`.
    - Timeouts strictly reject the request (`TIMED_OUT`); never auto-approve.
    - Shutdown cancels every pending request (`CANCELLED`) and resolves waiting tasks
      safely without allowing upstream execution or leaving orphaned tasks.
    - Callback or audit logging errors never approve a request.
    """

    def __init__(
        self,
        *,
        request_manager: RequestManager | None = None,
        audit_logger: AuditLogger | None = None,
        timeout_seconds: float = 120.0,
        on_pending_request: Callable[[InterceptedRequest], None] | None = None,
        on_request_resolved: Callable[[InterceptedRequest], None] | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be strictly positive.")

        self._request_manager = request_manager or RequestManager()
        self._audit_logger = audit_logger
        self._timeout_seconds = float(timeout_seconds)
        self._on_pending_request = on_pending_request
        self._on_request_resolved = on_request_resolved

        self._lock = threading.RLock()
        self._pending: dict[str, _PendingApproval] = {}
        self._shutting_down = False

    @property
    def request_manager(self) -> RequestManager:
        return self._request_manager

    @property
    def audit_logger(self) -> AuditLogger | None:
        return self._audit_logger

    @property
    def timeout_seconds(self) -> float:
        return self._timeout_seconds

    @property
    def is_shutting_down(self) -> bool:
        with self._lock:
            return self._shutting_down

    def pending_ids(self) -> list[str]:
        """Return a snapshot of internal_ids currently awaiting user authorization."""
        with self._lock:
            return list(self._pending.keys())

    def _audit(
        self,
        *,
        event_type: str,
        request: InterceptedRequest,
        execution_result: str = "not_executed",
        failure_reason: str | None = None,
    ) -> None:
        if self._audit_logger is None:
            return
        try:
            self._audit_logger.log_request_event(
                event_type=event_type,
                request=request,
                execution_result=execution_result,
                failure_reason=failure_reason,
            )
        except Exception as exc:
            # Never allow audit logging failures to crash or alter authorization verdicts.
            logger.warning(
                "Audit logger error during %s for request %s: %s",
                event_type,
                request.internal_id,
                type(exc).__name__,
            )

    def _notify_resolved(self, request: InterceptedRequest) -> None:
        if self._on_request_resolved is not None:
            try:
                self._on_request_resolved(request)
            except Exception:
                logger.exception(
                    "on_request_resolved callback failed for request %s",
                    request.internal_id,
                )

    @staticmethod
    def _set_future_result_safe(
        entry: _PendingApproval, decision: AuthorizationDecision
    ) -> None:
        """Resolve an asyncio.Future safely from either the same loop or another thread."""

        def _deliver() -> None:
            if not entry.future.done():
                entry.future.set_result(decision)

        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop is entry.loop:
            _deliver()
        elif not entry.loop.is_closed():
            try:
                entry.loop.call_soon_threadsafe(_deliver)
            except RuntimeError:
                # Event loop closed concurrently during shutdown.
                pass

    # ------------------------------------------------------------------
    # ToolAuthorizer interface (called by RequestHandler)
    # ------------------------------------------------------------------

    async def authorize(self, request: InterceptedRequest) -> AuthorizationDecision:
        """Register an intercepted request, wait for user decision, and return verdict."""
        loop = asyncio.get_running_loop()

        with self._lock:
            if (
                self._request_manager.get(request.internal_id) is not None
                or request.internal_id in self._pending
            ):
                logger.warning(
                    "Duplicate internal_id %s rejected in ApprovalManager.authorize (fail-closed).",
                    request.internal_id,
                )
                return AuthorizationDecision(
                    outcome=DecisionOutcome.ERROR,
                    reason="Duplicate request identifier rejected (fail-closed).",
                    decided_by="system:duplicate-id",
                )

            self._request_manager.register(request)

            if self._shutting_down:
                decision = AuthorizationDecision(
                    outcome=DecisionOutcome.CANCELLED,
                    reason="Application is shutting down.",
                    decided_by="system:shutdown",
                )
                self._request_manager.record_decision(request.internal_id, decision)
                self._audit(
                    event_type="REQUEST_CANCELLED",
                    request=request,
                    execution_result="not_executed",
                    failure_reason=decision.reason,
                )
                self._notify_resolved(request)
                return decision

            future: asyncio.Future[AuthorizationDecision] = loop.create_future()
            entry = _PendingApproval(request=request, loop=loop, future=future)
            self._pending[request.internal_id] = entry

        self._audit(
            event_type="REQUEST_RECEIVED",
            request=request,
            execution_result="pending",
        )

        # Notify UI/observer that a new approval request is pending.
        # If the notification fails, fail closed immediately rather than hanging.
        if self._on_pending_request is not None:
            try:
                self._on_pending_request(request)
            except Exception as exc:
                logger.error(
                    "on_pending_request handler failed for %s: %s",
                    request.internal_id,
                    type(exc).__name__,
                )
                fail_decision = AuthorizationDecision(
                    outcome=DecisionOutcome.ERROR,
                    reason=f"Approval prompt delivery failed ({type(exc).__name__}); failing closed.",
                    decided_by="system:fail-closed",
                )
                self._resolve_internal(
                    request.internal_id,
                    fail_decision,
                    event_type="APPROVAL_ERROR",
                    failure_reason=fail_decision.reason,
                )
                return fail_decision

        try:
            decision = await asyncio.wait_for(future, timeout=self._timeout_seconds)
            return decision
        except asyncio.TimeoutError:
            timeout_decision = AuthorizationDecision(
                outcome=DecisionOutcome.TIMEOUT,
                reason=f"Authorization timed out after {self._timeout_seconds:.1f}s.",
                decided_by="system:timeout",
            )
            resolved = self._resolve_if_still_pending(
                request.internal_id,
                timeout_decision,
                event_type="REQUEST_TIMED_OUT",
                failure_reason=timeout_decision.reason,
            )
            return resolved
        except asyncio.CancelledError:
            cancel_decision = AuthorizationDecision(
                outcome=DecisionOutcome.CANCELLED,
                reason="Request cancelled while awaiting authorization.",
                decided_by="system:cancelled",
            )
            self._resolve_if_still_pending(
                request.internal_id,
                cancel_decision,
                event_type="REQUEST_CANCELLED",
                failure_reason=cancel_decision.reason,
            )
            raise

    # ------------------------------------------------------------------
    # Decision controls (callable from asyncio tasks OR GUI thread)
    # ------------------------------------------------------------------

    def _resolve_internal(
        self,
        internal_id: str,
        decision: AuthorizationDecision,
        *,
        event_type: str,
        failure_reason: str | None = None,
    ) -> AuthorizationDecision:
        with self._lock:
            # Verify request exists and enforce single-decision state machine.
            req = self._request_manager.get_required(internal_id)
            if req.decision is not None or req.status is not RequestStatus.PENDING:
                raise DuplicateDecisionError(
                    f"Request {internal_id} has already been decided "
                    f"(status={req.status.value})."
                )

            entry = self._pending.pop(internal_id, None)
            self._request_manager.record_decision(internal_id, decision)

        self._audit(
            event_type=event_type,
            request=req,
            execution_result="not_executed",
            failure_reason=failure_reason,
        )
        if entry is not None:
            self._set_future_result_safe(entry, decision)
        self._notify_resolved(req)
        return decision

    def _resolve_if_still_pending(
        self,
        internal_id: str,
        fallback_decision: AuthorizationDecision,
        *,
        event_type: str,
        failure_reason: str | None = None,
    ) -> AuthorizationDecision:
        with self._lock:
            req = self._request_manager.get(internal_id)
            if req is None:
                return fallback_decision
            if req.decision is not None or req.status is not RequestStatus.PENDING:
                # Another decision won the race right before timeout/cancellation.
                self._pending.pop(internal_id, None)
                return req.decision or fallback_decision

            entry = self._pending.pop(internal_id, None)
            self._request_manager.record_decision(internal_id, fallback_decision)

        self._audit(
            event_type=event_type,
            request=req,
            execution_result="not_executed",
            failure_reason=failure_reason,
        )
        if entry is not None:
            self._set_future_result_safe(entry, fallback_decision)
        self._notify_resolved(req)
        return fallback_decision

    def approve(
        self,
        internal_id: str,
        *,
        reason: str = "Approved by user",
        decided_by: str = "user",
    ) -> AuthorizationDecision:
        """Explicitly approve a single PENDING request.

        Raises:
            UnknownRequestError: If internal_id does not exist.
            DuplicateDecisionError: If the request was already decided or resolved.
        """
        decision = AuthorizationDecision(
            outcome=DecisionOutcome.ALLOW,
            reason=reason,
            decided_by=decided_by,
        )
        return self._resolve_internal(
            internal_id,
            decision,
            event_type="DECISION_APPROVED",
        )

    def block(
        self,
        internal_id: str,
        *,
        reason: str = "Blocked by user",
        decided_by: str = "user",
    ) -> AuthorizationDecision:
        """Explicitly block a single PENDING request.

        Raises:
            UnknownRequestError: If internal_id does not exist.
            DuplicateDecisionError: If the request was already decided or resolved.
        """
        decision = AuthorizationDecision(
            outcome=DecisionOutcome.BLOCK,
            reason=reason,
            decided_by=decided_by,
        )
        return self._resolve_internal(
            internal_id,
            decision,
            event_type="DECISION_BLOCKED",
            failure_reason=reason,
        )

    # ------------------------------------------------------------------
    # Execution lifecycle hooks (invoked by RequestHandler)
    # ------------------------------------------------------------------

    def begin_execution(self, internal_id: str) -> None:
        """Claim an APPROVED request for single-shot upstream execution."""
        req = self._request_manager.mark_executing(internal_id)
        self._audit(
            event_type="EXECUTION_STARTED",
            request=req,
            execution_result="executing",
        )

    def complete_execution(self, internal_id: str) -> None:
        """Mark an EXECUTING request as COMPLETED and write audit log."""
        req = self._request_manager.mark_completed(internal_id)
        self._audit(
            event_type="EXECUTION_COMPLETED",
            request=req,
            execution_result="success",
        )

    def fail_execution(
        self,
        internal_id: str,
        error_message: str,
        *,
        execution_result: str = "upstream_error",
    ) -> None:
        """Mark an active request as FAILED and write audit log."""
        req = self._request_manager.get(internal_id)
        if req is None:
            return
        try:
            req = self._request_manager.mark_failed(internal_id, error_message)
        except InvalidStateTransitionError:
            # Already in a terminal state (e.g. failed earlier); still record safely.
            pass
        self._audit(
            event_type="EXECUTION_FAILED",
            request=req,
            execution_result=execution_result,
            failure_reason=error_message,
        )

    # ------------------------------------------------------------------
    # Graceful application shutdown
    # ------------------------------------------------------------------

    async def shutdown(self, reason: str = "Application shutting down.") -> list[str]:
        """Cancel all pending approvals cleanly and block future requests.

        Resolves every waiting future with DecisionOutcome.CANCELLED so waiting
        MCP handlers can return a clean denial response without leaking tasks
        or forwarding requests upstream.
        """
        with self._lock:
            self._shutting_down = True
            pending_entries = list(self._pending.items())
            self._pending.clear()

        cancelled_ids: list[str] = []
        for internal_id, entry in pending_entries:
            decision = AuthorizationDecision(
                outcome=DecisionOutcome.CANCELLED,
                reason=reason,
                decided_by="system:shutdown",
            )
            try:
                self._request_manager.record_decision(internal_id, decision)
            except (UnknownRequestError, InvalidStateTransitionError):
                continue

            cancelled_ids.append(internal_id)
            self._audit(
                event_type="REQUEST_CANCELLED",
                request=entry.request,
                execution_result="not_executed",
                failure_reason=reason,
            )
            self._set_future_result_safe(entry, decision)
            self._notify_resolved(entry.request)

        # Yield once to the event loop so resolved waiters can wake up cleanly.
        await asyncio.sleep(0)
        return cancelled_ids

    def resume(self) -> None:
        """Re-enable accepting new authorization requests after monitoring was stopped.

        Previously cancelled requests remain permanently CANCELLED.
        """
        with self._lock:
            self._shutting_down = False


__all__ = [
    "ApprovalManager",
    "DuplicateDecisionError",
    "DuplicateExecutionError",
    "InvalidStateTransitionError",
    "RequestManager",
    "UnknownRequestError",
]
