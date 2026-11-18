"""Request lifecycle tracking and strict state-machine enforcement."""

from __future__ import annotations

import threading
from collections.abc import Callable

from app.models.request import (
    AuthorizationDecision,
    DecisionOutcome,
    InterceptedRequest,
    RequestStatus,
    utc_now,
    validate_and_clone_arguments,
)


class RequestStateError(ValueError):
    """Base error for invalid RequestManager operations."""


class InvalidStateTransitionError(RequestStateError):
    """Raised when an illegal request lifecycle state transition is attempted."""


class DuplicateDecisionError(InvalidStateTransitionError):
    """Raised when attempting to decide a request that has already been decided."""


class DuplicateExecutionError(InvalidStateTransitionError):
    """Raised when attempting to execute an already executed or non-approved request."""


class DuplicateRequestError(RequestStateError):
    """Raised when registering a duplicate internal request identifier."""


class UnknownRequestError(KeyError):
    """Raised when referencing an internal request identifier that does not exist."""


# Strict finite-state machine for intercepted MCP requests.
TERMINAL_STATES: frozenset[RequestStatus] = frozenset(
    {
        RequestStatus.BLOCKED,
        RequestStatus.COMPLETED,
        RequestStatus.FAILED,
        RequestStatus.TIMED_OUT,
        RequestStatus.CANCELLED,
    }
)

ALLOWED_TRANSITIONS: dict[RequestStatus, frozenset[RequestStatus]] = {
    RequestStatus.PENDING: frozenset(
        {
            RequestStatus.APPROVED,
            RequestStatus.BLOCKED,
            RequestStatus.TIMED_OUT,
            RequestStatus.CANCELLED,
            RequestStatus.FAILED,
        }
    ),
    RequestStatus.APPROVED: frozenset(
        {
            RequestStatus.EXECUTING,
            RequestStatus.FAILED,
            RequestStatus.CANCELLED,
        }
    ),
    RequestStatus.EXECUTING: frozenset(
        {
            RequestStatus.COMPLETED,
            RequestStatus.FAILED,
        }
    ),
    RequestStatus.BLOCKED: frozenset(),
    RequestStatus.COMPLETED: frozenset(),
    RequestStatus.FAILED: frozenset(),
    RequestStatus.TIMED_OUT: frozenset(),
    RequestStatus.CANCELLED: frozenset(),
}


def _status_for_decision(decision: AuthorizationDecision) -> RequestStatus:
    mapping = {
        DecisionOutcome.ALLOW: RequestStatus.APPROVED,
        DecisionOutcome.BLOCK: RequestStatus.BLOCKED,
        DecisionOutcome.TIMEOUT: RequestStatus.TIMED_OUT,
        DecisionOutcome.CANCELLED: RequestStatus.CANCELLED,
        DecisionOutcome.ERROR: RequestStatus.FAILED,
    }
    return mapping.get(decision.outcome, RequestStatus.FAILED)


class RequestManager:
    """Thread-safe and asyncio-safe store and state machine for intercepted MCP requests.

    Guarantees:
    - Every request has a unique internal_id while preserving its original JSON-RPC ID.
    - Parameters are validated and safely cloned on registration.
    - Invalid state transitions (e.g. approving an already blocked/completed request)
      raise `InvalidStateTransitionError`.
    - Decisions can be recorded at most once per request (`DuplicateDecisionError`).
    - Upstream execution can begin at most once and only from `APPROVED`
      (`DuplicateExecutionError`).
    """

    def __init__(
        self,
        *,
        on_change: Callable[[InterceptedRequest], None] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._requests: dict[str, InterceptedRequest] = {}
        self._order: list[str] = []
        self._executed_ids: set[str] = set()
        self._on_change = on_change

    def _notify(self, request: InterceptedRequest) -> None:
        if self._on_change is not None:
            try:
                self._on_change(request)
            except Exception:
                # UI/observer errors must never corrupt request state.
                pass

    def register(self, request: InterceptedRequest) -> InterceptedRequest:
        """Register a new PENDING intercepted MCP request."""
        if not request.internal_id or not request.internal_id.strip():
            raise RequestStateError("Request must have a non-empty internal_id.")
        if request.status is not RequestStatus.PENDING:
            raise InvalidStateTransitionError(
                f"Newly registered request {request.internal_id} must start in PENDING, "
                f"not {request.status.value}."
            )

        # Ensure stored parameters are safely JSON-validated and isolated from caller mutation.
        request.arguments = validate_and_clone_arguments(request.arguments)

        with self._lock:
            if request.internal_id in self._requests:
                raise DuplicateRequestError(
                    f"Request {request.internal_id} is already registered."
                )
            self._requests[request.internal_id] = request
            self._order.append(request.internal_id)

        self._notify(request)
        return request

    def _get_locked(self, internal_id: str) -> InterceptedRequest:
        req = self._requests.get(internal_id)
        if req is None:
            raise UnknownRequestError(f"Unknown request internal_id: {internal_id}")
        return req

    def transition(
        self,
        internal_id: str,
        new_status: RequestStatus,
        *,
        error_message: str | None = None,
    ) -> InterceptedRequest:
        """Transition a request to a new lifecycle state if permitted by the state machine."""
        with self._lock:
            req = self._get_locked(internal_id)
            current = req.status
            allowed = ALLOWED_TRANSITIONS[current]
            if new_status not in allowed:
                raise InvalidStateTransitionError(
                    f"Illegal transition for request {internal_id}: "
                    f"{current.value} -> {new_status.value}."
                )

            req.status = new_status
            if error_message is not None:
                req.error_message = error_message
            if new_status in TERMINAL_STATES and req.completed_at is None:
                req.completed_at = utc_now()

        self._notify(req)
        return req

    def record_decision(
        self,
        internal_id: str,
        decision: AuthorizationDecision,
    ) -> InterceptedRequest:
        """Atomically record the single authorization decision for a PENDING request."""
        if not isinstance(decision, AuthorizationDecision):
            raise RequestStateError("decision must be an AuthorizationDecision instance.")

        target_status = _status_for_decision(decision)

        with self._lock:
            req = self._get_locked(internal_id)
            if req.decision is not None or req.status is not RequestStatus.PENDING:
                raise DuplicateDecisionError(
                    f"Request {internal_id} has already been resolved "
                    f"(current status={req.status.value})."
                )
            if target_status not in ALLOWED_TRANSITIONS[req.status]:
                raise InvalidStateTransitionError(
                    f"Illegal decision transition for request {internal_id}: "
                    f"{req.status.value} -> {target_status.value}."
                )

            req.decision = decision
            req.status = target_status
            if target_status is RequestStatus.FAILED and decision.reason:
                req.error_message = decision.reason
            if target_status in TERMINAL_STATES:
                req.completed_at = utc_now()

        self._notify(req)
        return req

    def mark_executing(self, internal_id: str) -> InterceptedRequest:
        """Atomically claim an APPROVED request for single-shot upstream execution."""
        with self._lock:
            req = self._get_locked(internal_id)
            if internal_id in self._executed_ids:
                raise DuplicateExecutionError(
                    f"Request {internal_id} has already been executed."
                )
            if req.status is not RequestStatus.APPROVED:
                raise DuplicateExecutionError(
                    f"Request {internal_id} cannot execute from status {req.status.value}; "
                    f"must be APPROVED."
                )
            if req.decision is None or not req.decision.is_allowed:
                raise DuplicateExecutionError(
                    f"Request {internal_id} does not have an explicit ALLOW decision."
                )
            self._executed_ids.add(internal_id)
            req.status = RequestStatus.EXECUTING

        self._notify(req)
        return req

    def mark_completed(self, internal_id: str) -> InterceptedRequest:
        """Transition an EXECUTING request to COMPLETED."""
        return self.transition(internal_id, RequestStatus.COMPLETED)

    def mark_failed(self, internal_id: str, error_message: str) -> InterceptedRequest:
        """Transition a PENDING, APPROVED, or EXECUTING request to FAILED."""
        return self.transition(
            internal_id, RequestStatus.FAILED, error_message=error_message
        )

    def get(self, internal_id: str) -> InterceptedRequest | None:
        with self._lock:
            return self._requests.get(internal_id)

    def get_required(self, internal_id: str) -> InterceptedRequest:
        with self._lock:
            return self._get_locked(internal_id)

    def has_been_executed(self, internal_id: str) -> bool:
        with self._lock:
            return internal_id in self._executed_ids

    def list_pending(self) -> list[InterceptedRequest]:
        with self._lock:
            return [
                self._requests[rid]
                for rid in self._order
                if self._requests[rid].status is RequestStatus.PENDING
            ]

    def list_recent(self, limit: int = 100) -> list[InterceptedRequest]:
        with self._lock:
            ids = self._order[-limit:] if limit > 0 else []
            return [self._requests[rid] for rid in reversed(ids)]

    def get_stats(self) -> dict[str, int]:
        """Return aggregate request counters across lifecycle states."""
        with self._lock:
            counts = {
                "total": len(self._requests),
                "pending": 0,
                "approved": 0,
                "blocked": 0,
                "executing": 0,
                "completed": 0,
                "failed": 0,
                "timed_out": 0,
                "cancelled": 0,
            }
            for req in self._requests.values():
                if req.status is RequestStatus.PENDING:
                    counts["pending"] += 1
                elif req.status is RequestStatus.APPROVED:
                    counts["approved"] += 1
                elif req.status is RequestStatus.BLOCKED:
                    counts["blocked"] += 1
                elif req.status is RequestStatus.EXECUTING:
                    counts["executing"] += 1
                elif req.status is RequestStatus.COMPLETED:
                    counts["completed"] += 1
                elif req.status is RequestStatus.FAILED:
                    counts["failed"] += 1
                elif req.status is RequestStatus.TIMED_OUT:
                    counts["timed_out"] += 1
                elif req.status is RequestStatus.CANCELLED:
                    counts["cancelled"] += 1
                # Count approved-and-progressed requests separately if needed by UI
            counts["approved_total"] = sum(
                1
                for req in self._requests.values()
                if req.decision is not None and req.decision.is_allowed
            )
            counts["blocked_total"] = sum(
                1
                for req in self._requests.values()
                if req.status
                in (
                    RequestStatus.BLOCKED,
                    RequestStatus.TIMED_OUT,
                    RequestStatus.CANCELLED,
                )
                or (
                    req.status is RequestStatus.FAILED
                    and (req.decision is None or not req.decision.is_allowed)
                )
            )
            return counts
