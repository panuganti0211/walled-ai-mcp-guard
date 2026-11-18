"""Authenticated localhost-only IPC broker connecting external STDIO proxies to the GUI.

Architecture:
- The PySide6 desktop app runs `LocalAuthorizationBroker` strictly bound to
  `127.0.0.1` with a per-session 256-bit random bearer token persisted atomically
  in a local runtime JSON file.
- External `StdioMCPProxy` processes (e.g. launched by Claude Desktop or CLI
  clients) connect via `RemoteBrokerAuthorizer`, presenting the bearer token to
  request user approval and report connection/execution lifecycle updates.
- If the desktop app is stopped, unreachable, or the token is invalid, the proxy
  strictly fails closed and never executes the upstream MCP tool.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import secrets
import socket
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.authorization.approval_manager import ApprovalManager
from app.models.request import (
    AuthorizationDecision,
    DecisionOutcome,
    InterceptedRequest,
    validate_and_clone_arguments,
)

logger = logging.getLogger(__name__)

_ALLOWED_HOST_HEADER_RE = re.compile(
    r"^(?:127\.0\.0\.1|localhost)(?::\d{1,5})?$", re.IGNORECASE
)


def is_valid_loopback_broker_url(url: str) -> bool:
    """Strictly validate that a broker URL targets only http://127.0.0.1:<port>."""
    if not isinstance(url, str) or not url:
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme != "http":
        return False
    if parsed.hostname != "127.0.0.1":
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    try:
        port = parsed.port
    except ValueError:
        return False
    if port is None or not (1 <= port <= 65535):
        return False
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.params:
        return False
    return True


def _restrict_file_permissions(path: Path) -> None:
    """Apply strict owner-only permissions to the local broker runtime token file."""
    if sys.platform == "win32":
        try:
            import ntsecuritycon as con
            import win32api
            import win32security

            user_sid, _, _ = win32security.LookupAccountName(
                None, win32api.GetUserNameEx(win32api.NameSamCompatible)
            )
            system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
            dacl = win32security.ACL()
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION, con.FILE_ALL_ACCESS, user_sid
            )
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION, con.FILE_ALL_ACCESS, system_sid
            )
            sd = win32security.SECURITY_DESCRIPTOR()
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            # Protected DACL prevents inherited read access from other local users.
            win32security.SetNamedSecurityInfo(
                str(path),
                win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION
                | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                dacl,
                None,
            )
            return
        except Exception as exc:
            logger.debug("Could not apply Windows owner-only DACL: %s", exc)
    else:
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            logger.debug("Could not chmod 0o600 runtime file: %s", exc)


def default_broker_runtime_file() -> Path:
    """Return the user-private default path for the local broker runtime descriptor."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "WalledAIMCPGuard" / "broker_runtime.json"
    return Path.home() / ".walled_ai_mcp_guard" / "broker_runtime.json"


class _AuthorizePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    internal_id: str = Field(..., min_length=1, max_length=128)
    jsonrpc_request_id: int | str | None = None
    server_name: str = Field(..., min_length=1, max_length=128)
    tool_name: str = Field(..., min_length=1, max_length=256)
    tool_description: str | None = Field(default=None, max_length=4000)
    arguments: dict[str, Any] = Field(default_factory=dict)


class _ExecutionEventPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    internal_id: str = Field(..., min_length=1, max_length=128)
    event: Literal["begin", "complete", "fail"]
    error_message: str | None = Field(default=None, max_length=2000)
    execution_result: str = Field(default="upstream_error", max_length=64)


class _HeartbeatPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_name: str = Field(..., min_length=1, max_length=128)
    proxy_pid: int = Field(..., ge=1)
    state: Literal["connected", "disconnected", "error"]
    detail: str = Field(default="", max_length=500)


@dataclass
class BrokerRuntimeInfo:
    """Connection metadata shared strictly on the local machine via runtime file."""

    url: str
    token: str
    port: int
    pid: int
    started_at: str


def read_broker_runtime_file(path: str | Path) -> BrokerRuntimeInfo | None:
    """Safely load broker connection metadata; returns None if unavailable or invalid."""
    runtime_path = Path(path)
    if runtime_path.is_symlink() or not runtime_path.is_file():
        return None
    try:
        data = json.loads(runtime_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        url = str(data["url"])
        token = str(data["token"])
        port = int(data["port"])
        pid = int(data["pid"])
        started_at = str(data.get("started_at", ""))
        if not is_valid_loopback_broker_url(url) or len(token) < 32:
            return None
        parsed = urlparse(url)
        if parsed.port != port:
            return None
        return BrokerRuntimeInfo(
            url=url, token=token, port=port, pid=pid, started_at=started_at
        )
    except Exception:
        return None


def _write_runtime_file_atomic(path: Path, info: BrokerRuntimeInfo) -> None:
    """Atomically write the runtime file with owner-only permissions."""
    if path.is_symlink():
        raise OSError(f"Refusing to write broker runtime file through symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "url": info.url,
            "token": info.token,
            "port": info.port,
            "pid": info.pid,
            "started_at": info.started_at,
        },
        indent=2,
    )
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=".broker_", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        _restrict_file_permissions(Path(tmp_name))
        os.replace(tmp_name, path)
        _restrict_file_permissions(path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _reserve_loopback_socket(port: int = 0) -> socket.socket:
    """Bind a TCP socket strictly to 127.0.0.1 and return it ready for uvicorn."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(64)
    return sock


class LocalAuthorizationBroker:
    """Authenticated 127.0.0.1-only HTTP broker backed by ApprovalManager."""

    def __init__(
        self,
        *,
        approval_manager: ApprovalManager,
        runtime_file: str | Path | None = None,
        port: int = 0,
        on_proxy_status: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self._approval_manager = approval_manager
        self._runtime_file = (
            Path(runtime_file) if runtime_file is not None else default_broker_runtime_file()
        )
        self._requested_port = port
        self._on_proxy_status = on_proxy_status

        self._token: str = secrets.token_urlsafe(32)
        self._server: uvicorn.Server | None = None
        self._server_task: asyncio.Task[None] | None = None
        self._socket: socket.socket | None = None
        self._runtime_info: BrokerRuntimeInfo | None = None
        self._active_proxies: dict[str, dict[str, Any]] = {}
        self._app = self._build_app()

    @property
    def runtime_file(self) -> Path:
        return self._runtime_file

    @property
    def runtime_info(self) -> BrokerRuntimeInfo | None:
        return self._runtime_info

    @property
    def is_running(self) -> bool:
        return (
            self._server is not None
            and self._server_task is not None
            and not self._server_task.done()
        )

    def _verify_auth(
        self,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> None:
        # Reject browser-originated requests to mitigate cross-site localhost attacks.
        if request.headers.get("origin") is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-origin requests are forbidden.",
            )

        # Strict Host header verification to block DNS rebinding attacks.
        host_header = (request.headers.get("host") or "").strip()
        if not host_header or not _ALLOWED_HOST_HEADER_RE.match(host_header):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden or missing host header.",
            )

        if not self._token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Broker token invalidated.",
            )

        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing bearer token.",
            )
        presented = authorization[len("Bearer ") :].strip()
        if not presented or not hmac.compare_digest(presented, self._token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid bearer token.",
            )

    def _build_app(self) -> FastAPI:
        app = FastAPI(
            title="Walled AI MCP Guard Local Broker",
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
        )

        @app.get("/health", dependencies=[Depends(self._verify_auth)])
        async def health() -> dict[str, Any]:
            return {
                "status": "stopped" if self._approval_manager.is_shutting_down else "protected",
                "pending": len(self._approval_manager.pending_ids()),
                "connected_proxies": sum(
                    1
                    for info in self._active_proxies.values()
                    if info.get("state") == "connected"
                ),
            }

        @app.post("/v1/proxy/heartbeat", dependencies=[Depends(self._verify_auth)])
        async def heartbeat(payload: _HeartbeatPayload) -> dict[str, str]:
            key = f"{payload.server_name}:{payload.proxy_pid}"
            if payload.state == "disconnected":
                self._active_proxies.pop(key, None)
            else:
                self._active_proxies[key] = {
                    "server_name": payload.server_name,
                    "proxy_pid": payload.proxy_pid,
                    "state": payload.state,
                    "detail": payload.detail,
                }
            if self._on_proxy_status is not None:
                try:
                    self._on_proxy_status(
                        payload.state, payload.server_name, payload.detail
                    )
                except Exception:
                    logger.debug("on_proxy_status callback failed.", exc_info=True)
            return {"status": "ok"}

        @app.post("/v1/authorize", dependencies=[Depends(self._verify_auth)])
        async def authorize(payload: _AuthorizePayload) -> dict[str, Any]:
            try:
                safe_args = validate_and_clone_arguments(payload.arguments)
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid tool arguments: {exc}",
                ) from exc

            intercepted = InterceptedRequest(
                internal_id=payload.internal_id,
                jsonrpc_request_id=payload.jsonrpc_request_id,
                server_name=payload.server_name,
                tool_name=payload.tool_name,
                tool_description=payload.tool_description,
                arguments=safe_args,
            )
            decision = await self._approval_manager.authorize(intercepted)
            return {
                "outcome": decision.outcome.value,
                "reason": decision.reason,
                "decided_by": decision.decided_by,
                "decided_at": decision.decided_at.isoformat(),
            }

        @app.post("/v1/execution/event", dependencies=[Depends(self._verify_auth)])
        async def execution_event(payload: _ExecutionEventPayload) -> dict[str, str]:
            try:
                if payload.event == "begin":
                    self._approval_manager.begin_execution(payload.internal_id)
                elif payload.event == "complete":
                    self._approval_manager.complete_execution(payload.internal_id)
                elif payload.event == "fail":
                    self._approval_manager.fail_execution(
                        payload.internal_id,
                        payload.error_message or "Upstream execution failed.",
                        execution_result=payload.execution_result,
                    )
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=str(exc),
                ) from exc
            return {"status": "ok"}

        return app

    async def start(self) -> BrokerRuntimeInfo:
        """Bind to 127.0.0.1, start uvicorn in the active asyncio loop, and publish runtime info."""
        if self.is_running and self._runtime_info is not None:
            return self._runtime_info

        self._token = secrets.token_urlsafe(32)
        sock = _reserve_loopback_socket(self._requested_port)
        bound_port = sock.getsockname()[1]
        self._socket = sock

        config = uvicorn.Config(
            self._app,
            host="127.0.0.1",
            port=bound_port,
            log_level="warning",
            access_log=False,
            loop="asyncio",
        )
        server = uvicorn.Server(config)
        # Never overwrite process signal handlers from inside the desktop GUI.
        server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
        self._server = server

        self._server_task = asyncio.create_task(
            server.serve(sockets=[sock]),
            name="mcp-guard-local-broker",
        )

        for _ in range(200):
            if server.started:
                break
            if self._server_task.done():
                exc = self._server_task.exception()
                raise RuntimeError(f"Local broker failed to start: {exc}")
            await asyncio.sleep(0.01)

        if not server.started:
            await self.stop()
            raise RuntimeError("Local broker timed out while starting.")

        info = BrokerRuntimeInfo(
            url=f"http://127.0.0.1:{bound_port}",
            token=self._token,
            port=bound_port,
            pid=os.getpid(),
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._runtime_info = info
        _write_runtime_file_atomic(self._runtime_file, info)
        logger.info("LocalAuthorizationBroker listening on %s", info.url)
        return info

    async def stop(self) -> None:
        """Invalidate token, stop the loopback broker, and remove the runtime descriptor file."""
        self._token = ""
        self._remove_runtime_file()

        if self._server is not None:
            self._server.should_exit = True

        if self._server_task is not None:
            try:
                await asyncio.wait_for(self._server_task, timeout=3.0)
            except asyncio.TimeoutError:
                self._server_task.cancel()
                try:
                    await self._server_task
                except asyncio.CancelledError:
                    pass
            except Exception:
                pass
            self._server_task = None

        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

        self._server = None
        self._runtime_info = None
        self._active_proxies.clear()

    def _remove_runtime_file(self) -> None:
        try:
            if self._runtime_file.exists():
                self._runtime_file.unlink()
        except OSError:
            pass


class RemoteBrokerAuthorizer:
    """Fail-closed ToolAuthorizer client used by external STDIO proxy processes.

    Connects exclusively over localhost (`127.0.0.1`) using the bearer token from
    the desktop GUI's runtime descriptor file. Any missing file, invalid token,
    connection failure, or invalid response strictly fails closed.
    """

    def __init__(
        self,
        *,
        broker_file: str | Path | None = None,
        broker_url: str | None = None,
        bearer_token: str | None = None,
        request_timeout_seconds: float = 150.0,
    ) -> None:
        self._broker_file = (
            Path(broker_file) if broker_file is not None else default_broker_runtime_file()
        )
        self._explicit_url = broker_url
        self._explicit_token = bearer_token
        self._request_timeout_seconds = float(request_timeout_seconds)
        self._event_chains: dict[str, asyncio.Task[None]] = {}

    def _resolve_connection(self) -> tuple[str, str] | None:
        if self._explicit_url and self._explicit_token:
            if not is_valid_loopback_broker_url(self._explicit_url):
                return None
            return self._explicit_url.rstrip("/"), self._explicit_token
        info = read_broker_runtime_file(self._broker_file)
        if info is None:
            return None
        return info.url.rstrip("/"), info.token

    async def send_heartbeat(
        self,
        *,
        server_name: str,
        state: Literal["connected", "disconnected", "error"],
        detail: str = "",
    ) -> None:
        conn = self._resolve_connection()
        if conn is None:
            return
        base_url, token = conn
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(
                    f"{base_url}/v1/proxy/heartbeat",
                    headers={"Authorization": f"Bearer {token}"},
                    json={
                        "server_name": server_name,
                        "proxy_pid": os.getpid(),
                        "state": state,
                        "detail": detail,
                    },
                )
        except Exception:
            pass

    async def authorize(self, request: InterceptedRequest) -> AuthorizationDecision:
        """Request user approval from the local desktop GUI broker (fail-closed)."""
        conn = self._resolve_connection()
        if conn is None:
            return AuthorizationDecision(
                outcome=DecisionOutcome.ERROR,
                reason="Walled AI MCP Guard desktop app is not running or monitoring is stopped (fail-closed).",
                decided_by="system:broker-unavailable",
            )

        base_url, token = conn
        payload = {
            "internal_id": request.internal_id,
            "jsonrpc_request_id": request.jsonrpc_request_id,
            "server_name": request.server_name,
            "tool_name": request.tool_name,
            "tool_description": request.tool_description,
            "arguments": request.arguments,
        }

        try:
            async with httpx.AsyncClient(timeout=self._request_timeout_seconds) as client:
                resp = await client.post(
                    f"{base_url}/v1/authorize",
                    headers={"Authorization": f"Bearer {token}"},
                    json=payload,
                )
        except Exception as exc:
            logger.error("Failed to reach local authorization broker: %s", type(exc).__name__)
            return AuthorizationDecision(
                outcome=DecisionOutcome.ERROR,
                reason=f"Could not contact Walled AI MCP Guard desktop broker ({type(exc).__name__}); failing closed.",
                decided_by="system:broker-error",
            )

        if resp.status_code != 200:
            return AuthorizationDecision(
                outcome=DecisionOutcome.ERROR,
                reason=f"Local authorization broker rejected request (HTTP {resp.status_code}); failing closed.",
                decided_by="system:broker-rejected",
            )

        try:
            body = resp.json()
            outcome = DecisionOutcome(body["outcome"])
            reason = str(body.get("reason", ""))
            decided_by = str(body.get("decided_by", "desktop-broker"))
        except Exception:
            return AuthorizationDecision(
                outcome=DecisionOutcome.ERROR,
                reason="Local authorization broker returned malformed decision (fail-closed).",
                decided_by="system:broker-malformed",
            )

        return AuthorizationDecision(
            outcome=outcome,
            reason=reason,
            decided_by=decided_by,
        )

    def _fire_execution_event(
        self,
        *,
        internal_id: str,
        event: Literal["begin", "complete", "fail"],
        error_message: str | None = None,
        execution_result: str = "upstream_error",
    ) -> None:
        conn = self._resolve_connection()
        if conn is None:
            return
        base_url, token = conn
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        prev_task = self._event_chains.get(internal_id)

        async def _send() -> None:
            if prev_task is not None:
                try:
                    await prev_task
                except Exception:
                    pass
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    await client.post(
                        f"{base_url}/v1/execution/event",
                        headers={"Authorization": f"Bearer {token}"},
                        json={
                            "internal_id": internal_id,
                            "event": event,
                            "error_message": error_message,
                            "execution_result": execution_result,
                        },
                    )
            except Exception:
                pass
            finally:
                if self._event_chains.get(internal_id) is task:
                    self._event_chains.pop(internal_id, None)

        task = loop.create_task(_send())
        self._event_chains[internal_id] = task

    def begin_execution(self, internal_id: str) -> None:
        self._fire_execution_event(internal_id=internal_id, event="begin")

    def complete_execution(self, internal_id: str) -> None:
        self._fire_execution_event(internal_id=internal_id, event="complete")

    def fail_execution(
        self,
        internal_id: str,
        error_message: str,
        *,
        execution_result: str = "upstream_error",
    ) -> None:
        self._fire_execution_event(
            internal_id=internal_id,
            event="fail",
            error_message=error_message,
            execution_result=execution_result,
        )
