"""Structured JSONL security audit logger with recursive sensitive-field redaction."""

from __future__ import annotations

import json
import logging
import re
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.models.request import InterceptedRequest

_stderr_logger = logging.getLogger(__name__)

# Normalized substrings indicating sensitive credential/secret keys.
_SENSITIVE_KEY_TOKENS = (
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "authorization",
    "auth_header",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_key",
    "credential",
    "cookie",
    "session_id",
    "bearer",
    "jwt",
    "passphrase",
    "ssh_key",
    "ssn",
    "credit_card",
    "cvv",
)

# Keys likely to contain raw file bodies or large potentially sensitive payloads.
_CONTENT_KEY_NAMES = frozenset(
    {
        "content",
        "contents",
        "file_content",
        "body",
        "payload",
        "raw_data",
        "data",
        "text",
        "bytes",
        "base64",
    }
)

# Regex patterns for common credential/token value formats even under generic keys.
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"^\s*Bearer\s+\S+", re.IGNORECASE),
    re.compile(r"^\s*Basic\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE),
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
)

_MAX_SAFE_STRING_LEN = 120
_MAX_REDACTION_DEPTH = 12
_REDACTED = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    """Return True if a field name looks like a credential, token, or secret."""
    normalized = re.sub(r"[^a-z0-9]+", "_", key.strip().lower())
    compact = normalized.replace("_", "")
    for token in _SENSITIVE_KEY_TOKENS:
        if token in normalized or token.replace("_", "") in compact:
            return True
    return False


def _looks_like_secret_value(value: str) -> bool:
    for pattern in _SENSITIVE_VALUE_PATTERNS:
        if pattern.search(value):
            return True
    return False


def redact_sensitive_data(
    value: Any,
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> Any:
    """Recursively redact sensitive keys, secret-shaped strings, and bulky payloads.

    Returns a strictly JSON-serializable, sanitized structure safe for audit logs.
    """
    if _depth >= _MAX_REDACTION_DEPTH:
        return "[REDACTED_MAX_DEPTH]"

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        if _looks_like_secret_value(value):
            return _REDACTED
        if len(value) > _MAX_SAFE_STRING_LEN:
            return f"[TRUNCATED len={len(value)}]"
        return value

    if isinstance(value, (bytes, bytearray)):
        return f"[REDACTED_BYTES len={len(value)}]"

    seen = _seen if _seen is not None else set()
    obj_id = id(value)
    if obj_id in seen:
        return "[CIRCULAR_REF]"

    if isinstance(value, dict):
        seen.add(obj_id)
        try:
            sanitized: dict[str, Any] = {}
            for raw_k, raw_v in value.items():
                key = str(raw_k)
                key_lower = key.strip().lower()
                if is_sensitive_key(key):
                    sanitized[key] = _REDACTED
                elif key_lower in _CONTENT_KEY_NAMES:
                    if isinstance(raw_v, (str, bytes, bytearray)):
                        sanitized[key] = f"[REDACTED_CONTENT len={len(raw_v)}]"
                    else:
                        sanitized[key] = "[REDACTED_CONTENT]"
                else:
                    sanitized[key] = redact_sensitive_data(
                        raw_v, _depth=_depth + 1, _seen=seen
                    )
            return sanitized
        finally:
            seen.discard(obj_id)

    if isinstance(value, (list, tuple, set)):
        seen.add(obj_id)
        try:
            return [
                redact_sensitive_data(item, _depth=_depth + 1, _seen=seen)
                for item in value
            ]
        finally:
            seen.discard(obj_id)

    text = str(value)
    if _looks_like_secret_value(text):
        return _REDACTED
    if len(text) > _MAX_SAFE_STRING_LEN:
        return f"[TRUNCATED len={len(text)}]"
    return text


def redact_text(text: str | None) -> str | None:
    """Redact secret patterns in free-form error or reason text."""
    if text is None:
        return None
    cleaned = text
    for pattern in _SENSITIVE_VALUE_PATTERNS:
        cleaned = pattern.sub(_REDACTED, cleaned)
    # Also scrub simple key=value or key: value secret fragments
    cleaned = re.sub(
        r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*\S+",
        r"\1=[REDACTED]",
        cleaned,
    )
    return cleaned


class AuditLogger:
    """Thread-safe JSONL audit logger backed by Python's standard logging module.

    Logging failures are caught and reported to stderr without raising exceptions
    into the authorization pipeline and without ever causing an approval bypass.
    """

    def __init__(
        self,
        log_path: str | Path = "logs/audit.jsonl",
        *,
        on_log_error: Callable[[Exception], None] | None = None,
    ) -> None:
        self._log_path = Path(log_path)
        self._on_log_error = on_log_error
        self._lock = threading.Lock()
        self._logger_name = f"walled_ai.audit.{id(self)}"
        self._logger = logging.getLogger(self._logger_name)
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._handler: logging.FileHandler | None = None
        self._closed = False

    @property
    def log_path(self) -> Path:
        return self._log_path

    def _ensure_handler(self) -> logging.FileHandler:
        if self._handler is None:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(
                self._log_path, mode="a", encoding="utf-8"
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
            self._handler = handler
        return self._handler

    def _handle_failure(self, exc: Exception) -> None:
        if self._on_log_error is not None:
            try:
                self._on_log_error(exc)
            except Exception:
                pass
        try:
            _stderr_logger.warning(
                "Audit log write failed (%s): %s", type(exc).__name__, exc
            )
        except Exception:
            print(
                f"Audit log write failed ({type(exc).__name__}): {exc}",
                file=sys.stderr,
            )

    def write_record(self, record: dict[str, Any]) -> bool:
        """Serialize a sanitized record as one JSON line and persist it.

        Returns:
            True if the record was persisted successfully, False on failure.
        """
        with self._lock:
            if self._closed:
                return False
            try:
                line = json.dumps(record, ensure_ascii=False, allow_nan=False)
                handler = self._ensure_handler()
                # Emit directly through the configured logging.FileHandler and flush.
                log_record = self._logger.makeRecord(
                    name=self._logger_name,
                    level=logging.INFO,
                    fn="",
                    lno=0,
                    msg=line,
                    args=(),
                    exc_info=None,
                )
                handler.emit(log_record)
                handler.flush()
                return True
            except Exception as exc:
                self._handle_failure(exc)
                return False

    def log_request_event(
        self,
        *,
        event_type: str,
        request: InterceptedRequest,
        execution_result: str = "not_executed",
        failure_reason: str | None = None,
    ) -> bool:
        """Write a structured, redacted audit entry for an intercepted MCP request."""
        decision_outcome = (
            request.decision.outcome.value if request.decision is not None else None
        )
        decided_by = (
            request.decision.decided_by if request.decision is not None else None
        )
        decision_reason = (
            redact_text(request.decision.reason)
            if request.decision is not None and request.decision.reason
            else None
        )
        effective_failure = redact_text(failure_reason or request.error_message)

        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "request_id": request.jsonrpc_request_id,
            "internal_id": request.internal_id,
            "server_name": request.server_name,
            "tool_name": request.tool_name,
            "argument_keys": sorted(str(k) for k in request.arguments.keys()),
            "arguments_redacted": redact_sensitive_data(request.arguments),
            "decision": decision_outcome,
            "decided_by": decided_by,
            "decision_reason": decision_reason,
            "status": request.status.value,
            "execution_result": execution_result,
            "failure_reason": effective_failure,
        }
        return self.write_record(record)

    def close(self) -> None:
        """Flush and close the underlying audit log file handler."""
        with self._lock:
            self._closed = True
            if self._handler is not None:
                try:
                    self._handler.flush()
                    self._handler.close()
                except Exception:
                    pass
                self._logger.removeHandler(self._handler)
                self._handler = None
