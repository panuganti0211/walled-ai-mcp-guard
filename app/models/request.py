"""Core domain models for intercepted MCP tool requests and authorization decisions."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable


# JSON-RPC 2.0 implementation-defined server error codes (-32000 to -32099)
ERR_AUTHORIZATION_DENIED = -32003
ERR_AUTHORIZATION_CANCELLED = -32004
ERR_AUTHORIZATION_SYSTEM_FAILURE = -32005


class RequestStatus(str, Enum):
    """Lifecycle state of an intercepted MCP tool call request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class DecisionOutcome(str, Enum):
    """Authorization verdict produced by a ToolAuthorizer."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    ERROR = "ERROR"


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def validate_and_clone_arguments(arguments: Any) -> dict[str, Any]:
    """Validate MCP tool arguments as safe JSON-serializable dict and return a deep copy.

    Raises:
        ValueError: If arguments are not None/dict or cannot be safely serialized as strict JSON.
    """
    if arguments is None:
        return {}
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be a JSON object (dict).")
    for key in arguments:
        if not isinstance(key, str):
            raise ValueError("Tool argument keys must be strings.")
        if "\x00" in key:
            raise ValueError("Tool argument keys must not contain null bytes.")

    try:
        serialized = json.dumps(arguments, allow_nan=False, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Tool arguments are not safely JSON-serializable: {exc}") from exc

    cloned = json.loads(serialized)
    if not isinstance(cloned, dict):
        raise ValueError("Deserialized tool arguments must be a JSON object.")
    return cloned


@dataclass(frozen=True)
class AuthorizationDecision:
    """Immutable authorization decision for a single intercepted MCP request."""

    outcome: DecisionOutcome
    reason: str = ""
    decided_at: datetime = field(default_factory=utc_now)
    decided_by: str = "user"

    @property
    def is_allowed(self) -> bool:
        """Strictly fail-closed: only an explicit ALLOW verdict permits execution."""
        return self.outcome is DecisionOutcome.ALLOW


@dataclass
class InterceptedRequest:
    """State and metadata for an intercepted MCP tools/call request."""

    server_name: str
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    jsonrpc_request_id: int | str | None = None
    tool_description: str | None = None
    internal_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=utc_now)
    status: RequestStatus = RequestStatus.PENDING
    decision: AuthorizationDecision | None = None
    completed_at: datetime | None = None
    error_message: str | None = None

    def mark_decision(self, decision: AuthorizationDecision) -> None:
        """Record the authorization decision and update status accordingly."""
        self.decision = decision
        if decision.outcome is DecisionOutcome.ALLOW:
            self.status = RequestStatus.APPROVED
        elif decision.outcome is DecisionOutcome.BLOCK:
            self.status = RequestStatus.BLOCKED
            self.completed_at = utc_now()
        elif decision.outcome is DecisionOutcome.TIMEOUT:
            self.status = RequestStatus.TIMED_OUT
            self.completed_at = utc_now()
        elif decision.outcome is DecisionOutcome.CANCELLED:
            self.status = RequestStatus.CANCELLED
            self.completed_at = utc_now()
        else:
            self.status = RequestStatus.FAILED
            self.completed_at = utc_now()

    def mark_executing(self) -> None:
        """Transition an approved request to EXECUTING before forwarding upstream."""
        if self.status is not RequestStatus.APPROVED:
            raise RuntimeError(
                f"Cannot transition request {self.internal_id} to EXECUTING from {self.status.value}"
            )
        self.status = RequestStatus.EXECUTING

    def mark_completed(self) -> None:
        """Transition an executing request to COMPLETED."""
        self.status = RequestStatus.COMPLETED
        self.completed_at = utc_now()

    def mark_failed(self, error_message: str) -> None:
        """Transition a request to FAILED with an error summary."""
        self.status = RequestStatus.FAILED
        self.error_message = error_message
        self.completed_at = utc_now()


@runtime_checkable
class ToolAuthorizer(Protocol):
    """Pluggable asynchronous authorization boundary for MCP tool calls."""

    async def authorize(self, request: InterceptedRequest) -> AuthorizationDecision:
        """Evaluate an intercepted tool request and return an AuthorizationDecision."""
        ...


class FailClosedAuthorizer:
    """Default fail-closed authorizer that rejects all tool calls when no authorizer is wired."""

    def __init__(self, reason: str = "No authorization policy or UI handler is attached (fail-closed).") -> None:
        self._reason = reason

    async def authorize(self, request: InterceptedRequest) -> AuthorizationDecision:
        return AuthorizationDecision(
            outcome=DecisionOutcome.ERROR,
            reason=self._reason,
            decided_by="system:fail-closed",
        )
