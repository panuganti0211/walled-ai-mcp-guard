"""Authenticated Remote MCP Gateway over Official MCP SDK 2.3.0 Streamable HTTP.

Designed to bridge remote MCP clients (such as Claude Web behind a public HTTPS
reverse proxy / OAuth front-end, or authenticated remote HTTP MCP clients) to an
explicitly configured upstream MCP server through the exact same RequestHandler +
ApprovalManager enforcement boundary used by StdioMCPProxy.

Security notes:
- Claude Web requires a public HTTPS endpoint (never plain local HTTP) and OAuth 2.1
  Protected Resource Metadata (RFC 9728) for production custom connectors.
- This gateway binds strictly to `127.0.0.1` by default for local TLS termination
  via Caddy, Nginx, or Cloudflare Tunnel, and enforces mandatory Bearer token
  authentication (minimum 32-char secret loaded from environment, never hardcoded),
  DNS-rebinding Host/Origin protection (`TransportSecuritySettings`), payload size
  caps, sliding-window rate limiting, and fail-closed tool authorization.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import logging
import os
import socket
import sys
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import mcp.types as types
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, status
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from app import __version__ as app_version
from app.config import UpstreamServerConfig, build_sanitized_env, load_config
from app.models.request import (
    FailClosedAuthorizer,
    InterceptedRequest,
    ToolAuthorizer,
)
from app.proxy.request_handler import RequestHandler

logger = logging.getLogger(__name__)

ENV_GATEWAY_TOKEN = "MCP_GUARD_GATEWAY_TOKEN"
_MIN_TOKEN_LEN = 32
_DEFAULT_MAX_BODY_BYTES = 1_048_576  # 1 MiB


class GatewayConfigError(ValueError):
    """Raised when the Remote MCP Gateway configuration is insecure or invalid."""


@dataclass(frozen=True)
class GatewayRuntimeInfo:
    """Running endpoint metadata for a started RemoteMCPGateway instance."""

    host: str
    port: int
    base_url: str
    mcp_url: str


class _SlidingWindowRateLimiter:
    """In-memory sliding-window per-client rate limiter for gateway protection."""

    def __init__(self, max_requests: int = 120, window_seconds: float = 60.0) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, client_key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self._window_seconds
        bucket = self._hits[client_key]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self._max_requests:
            return False
        bucket.append(now)
        return True


def _extract_bearer_token(headers: list[tuple[bytes, bytes]]) -> str | None:
    for raw_key, raw_val in headers:
        if raw_key.lower() == b"authorization":
            try:
                value = raw_val.decode("latin-1")
            except Exception:
                return None
            if value.startswith("Bearer "):
                token = value[len("Bearer ") :].strip()
                return token or None
    return None


def _extract_content_length(headers: list[tuple[bytes, bytes]]) -> int | None:
    for raw_key, raw_val in headers:
        if raw_key.lower() == b"content-length":
            try:
                return int(raw_val.decode("ascii").strip())
            except Exception:
                return -1
    return None


class _ProtectedStreamableHTTPASGI:
    """ASGI endpoint enforcing Bearer auth, rate limit, and payload cap before MCP."""

    def __init__(self, gateway: RemoteMCPGateway) -> None:
        self._gateway = gateway

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return

        # 1. Fail closed if bearer token is not configured
        expected_token = self._gateway.bearer_token
        if not expected_token or len(expected_token) < _MIN_TOKEN_LEN:
            resp = JSONResponse(
                {"detail": "Remote MCP gateway authentication is not configured (fail-closed)."},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
            await resp(scope, receive, send)
            return

        headers = list(scope.get("headers") or [])

        # 2. Enforce constant-time Bearer token verification BEFORE touching MCP SDK
        presented = _extract_bearer_token(headers)
        if not presented or not hmac.compare_digest(presented, expected_token):
            logger.warning("Rejected unauthenticated or invalid-token request to /mcp.")
            resp = JSONResponse(
                {"detail": "Authentication required. Present a valid Bearer token."},
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={
                    "WWW-Authenticate": 'Bearer realm="walled-ai-mcp-guard", error="invalid_token"'
                },
            )
            await resp(scope, receive, send)
            return

        # 3. Rate limiting
        client = scope.get("client")
        client_key = client[0] if client else "unknown"
        if not self._gateway.rate_limiter.allow(client_key):
            resp = JSONResponse(
                {"detail": "Rate limit exceeded."},
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            )
            await resp(scope, receive, send)
            return

        # 4. Payload size cap
        content_len = _extract_content_length(headers)
        if content_len is not None and (
            content_len < 0 or content_len > self._gateway.max_request_body_size
        ):
            resp = JSONResponse(
                {"detail": "Request body exceeds maximum allowed size."},
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            )
            await resp(scope, receive, send)
            return

        # 5. Delegate to live StreamableHTTPSessionManager
        session_manager = self._gateway.session_manager
        if session_manager is None:
            resp = JSONResponse(
                {"detail": "Remote MCP gateway is not ready (fail-closed)."},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
            await resp(scope, receive, send)
            return

        await session_manager.handle_request(scope, receive, send)


def _reserve_socket(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(64)
    return sock


class RemoteMCPGateway:
    """FastAPI + MCP SDK 2.3.0 Streamable HTTP Remote MCP Gateway.

    Connects to a configured upstream MCP server and routes every `tools/call`
    strictly through `RequestHandler` + `ToolAuthorizer` (`ApprovalManager` or
    `RemoteBrokerAuthorizer` -> PySide6 desktop app).
    """

    def __init__(
        self,
        *,
        server_name: str,
        server_config: UpstreamServerConfig,
        bearer_token: str | None,
        authorizer: ToolAuthorizer | None = None,
        on_request_event: Callable[[InterceptedRequest], None] | None = None,
        mcp_path: str = "/mcp",
        allowed_hosts: list[str] | None = None,
        allowed_origins: list[str] | None = None,
        max_request_body_size: int = _DEFAULT_MAX_BODY_BYTES,
        rate_limit_per_minute: int = 120,
        stateless_http: bool = False,
        json_response: bool = False,
    ) -> None:
        if not bearer_token or len(bearer_token.strip()) < _MIN_TOKEN_LEN:
            raise GatewayConfigError(
                f"RemoteMCPGateway requires a bearer token of at least {_MIN_TOKEN_LEN} characters "
                f"(set {ENV_GATEWAY_TOKEN}; never hardcode secrets)."
            )
        if not mcp_path.startswith("/"):
            raise GatewayConfigError("mcp_path must start with '/'.")

        self._server_name = server_name
        self._server_config = server_config
        self._bearer_token = bearer_token.strip()
        self._authorizer: ToolAuthorizer = (
            authorizer
            if authorizer is not None
            else FailClosedAuthorizer(
                reason="Remote MCP gateway has no interactive authorizer attached (fail-closed)."
            )
        )
        self._on_request_event = on_request_event
        self._mcp_path = mcp_path
        self._allowed_hosts = (
            list(allowed_hosts)
            if allowed_hosts is not None
            else ["127.0.0.1:*", "localhost:*"]
        )
        self._allowed_origins = (
            list(allowed_origins)
            if allowed_origins is not None
            else ["http://127.0.0.1:*", "http://localhost:*"]
        )
        self._max_request_body_size = int(max_request_body_size)
        self._rate_limiter = _SlidingWindowRateLimiter(
            max_requests=rate_limit_per_minute, window_seconds=60.0
        )
        self._stateless_http = stateless_http
        self._json_response = json_response

        self._handler: RequestHandler | None = None
        self._session_manager: StreamableHTTPSessionManager | None = None
        self._upstream_init: types.InitializeResult | None = None

        self._server: uvicorn.Server | None = None
        self._server_task: asyncio.Task[None] | None = None
        self._socket: socket.socket | None = None
        self._runtime_info: GatewayRuntimeInfo | None = None

        self._app = self._build_fastapi_app()

    @property
    def app(self) -> FastAPI:
        return self._app

    @property
    def bearer_token(self) -> str:
        return self._bearer_token

    @property
    def max_request_body_size(self) -> int:
        return self._max_request_body_size

    @property
    def rate_limiter(self) -> _SlidingWindowRateLimiter:
        return self._rate_limiter

    @property
    def handler(self) -> RequestHandler | None:
        return self._handler

    @property
    def session_manager(self) -> StreamableHTTPSessionManager | None:
        return self._session_manager

    @property
    def runtime_info(self) -> GatewayRuntimeInfo | None:
        return self._runtime_info

    def _build_downstream_mcp_server(
        self,
        handler: RequestHandler,
        upstream_init: types.InitializeResult,
    ) -> Server[Any]:
        caps = upstream_init.capabilities
        server_kwargs: dict[str, Any] = {
            "name": f"walled-ai-mcp-guard-gateway ({self._server_name})",
            "version": app_version,
            "instructions": upstream_init.instructions,
            "on_ping": handler.handle_ping,
        }

        if caps.tools is not None:
            server_kwargs["on_list_tools"] = handler.handle_list_tools
            server_kwargs["on_call_tool"] = handler.handle_call_tool

        if caps.resources is not None:
            server_kwargs["on_list_resources"] = handler.handle_list_resources
            server_kwargs["on_list_resource_templates"] = (
                handler.handle_list_resource_templates
            )
            server_kwargs["on_read_resource"] = handler.handle_read_resource
            if caps.resources.subscribe:
                server_kwargs["on_subscribe_resource"] = handler.handle_subscribe_resource
                server_kwargs["on_unsubscribe_resource"] = (
                    handler.handle_unsubscribe_resource
                )

        if caps.prompts is not None:
            server_kwargs["on_list_prompts"] = handler.handle_list_prompts
            server_kwargs["on_get_prompt"] = handler.handle_get_prompt

        if caps.completions is not None:
            server_kwargs["on_completion"] = handler.handle_completion

        if caps.logging is not None:
            server_kwargs["on_set_logging_level"] = handler.handle_set_logging_level

        return Server(**server_kwargs)

    @asynccontextmanager
    async def _lifespan(self, _app: FastAPI) -> AsyncIterator[None]:
        server_params = StdioServerParameters(
            command=self._server_config.command,
            args=list(self._server_config.args),
            env=build_sanitized_env(self._server_config.env),
            cwd=self._server_config.cwd,
        )
        logger.info(
            "RemoteMCPGateway starting upstream MCP server '%s'", self._server_name
        )

        async with stdio_client(server_params, errlog=sys.stderr) as (
            upstream_read,
            upstream_write,
        ):
            async with ClientSession(
                upstream_read,
                upstream_write,
                client_info=types.Implementation(
                    name="walled-ai-mcp-guard-gateway",
                    version=app_version,
                ),
            ) as upstream_session:
                upstream_init = await upstream_session.initialize()
                self._upstream_init = upstream_init

                handler = RequestHandler(
                    server_name=self._server_name,
                    upstream=upstream_session,
                    authorizer=self._authorizer,
                    on_request_event=self._on_request_event,
                )
                self._handler = handler

                mcp_server = self._build_downstream_mcp_server(handler, upstream_init)
                security_settings = TransportSecuritySettings(
                    enable_dns_rebinding_protection=True,
                    allowed_hosts=self._allowed_hosts,
                    allowed_origins=self._allowed_origins,
                )
                session_manager = StreamableHTTPSessionManager(
                    app=mcp_server,
                    json_response=self._json_response,
                    stateless=self._stateless_http,
                    security_settings=security_settings,
                    max_request_body_size=self._max_request_body_size,
                    session_idle_timeout=1800,
                    max_sessions=100,
                )
                self._session_manager = session_manager

                heartbeat = getattr(self._authorizer, "send_heartbeat", None)
                async with session_manager.run():
                    if callable(heartbeat):
                        await heartbeat(
                            server_name=self._server_name,
                            state="connected",
                            detail=f"Remote HTTP Gateway -> {upstream_init.server_info.name}",
                        )
                    try:
                        yield
                    finally:
                        self._session_manager = None
                        self._handler = None
                        if callable(heartbeat):
                            try:
                                await heartbeat(
                                    server_name=self._server_name,
                                    state="disconnected",
                                    detail="Remote HTTP Gateway stopped",
                                )
                            except Exception:
                                pass

    def _verify_health_auth(
        self, authorization: str | None = Header(default=None)
    ) -> None:
        if not self._bearer_token or len(self._bearer_token) < _MIN_TOKEN_LEN:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Gateway authentication not configured (fail-closed).",
            )
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing bearer token.",
                headers={"WWW-Authenticate": 'Bearer realm="walled-ai-mcp-guard"'},
            )
        presented = authorization[len("Bearer ") :].strip()
        if not presented or not hmac.compare_digest(presented, self._bearer_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid bearer token.",
                headers={
                    "WWW-Authenticate": 'Bearer realm="walled-ai-mcp-guard", error="invalid_token"'
                },
            )

    def _build_fastapi_app(self) -> FastAPI:
        app = FastAPI(
            title="Walled AI MCP Guard — Remote MCP Gateway",
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
            lifespan=self._lifespan,
        )

        @app.get("/health", dependencies=[Depends(self._verify_health_auth)])
        async def health() -> dict[str, Any]:
            return {
                "status": "ready" if self._session_manager is not None else "starting",
                "server_name": self._server_name,
                "transport": "streamable-http",
                "mcp_path": self._mcp_path,
            }

        # Register the Streamable HTTP endpoint as a raw ASGI route to avoid 307 redirects.
        app.router.routes.append(
            Route(
                self._mcp_path,
                endpoint=_ProtectedStreamableHTTPASGI(self),
                methods=["GET", "POST", "DELETE"],
            )
        )
        return app

    async def start(
        self, *, host: str = "127.0.0.1", port: int = 0
    ) -> GatewayRuntimeInfo:
        """Start the FastAPI/Uvicorn Streamable HTTP gateway on the active asyncio loop."""
        sock = _reserve_socket(host, port)
        bound_port = sock.getsockname()[1]
        self._socket = sock

        config = uvicorn.Config(
            self._app,
            host=host,
            port=bound_port,
            log_level="warning",
            access_log=False,
            loop="asyncio",
        )
        server = uvicorn.Server(config)
        server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
        self._server = server

        self._server_task = asyncio.create_task(
            server.serve(sockets=[sock]),
            name="mcp-guard-http-gateway",
        )

        for _ in range(500):
            if server.started:
                break
            if self._server_task.done():
                exc = self._server_task.exception()
                raise RuntimeError(f"RemoteMCPGateway failed to start: {exc}")
            await asyncio.sleep(0.02)

        if not server.started:
            await self.stop()
            raise RuntimeError("RemoteMCPGateway timed out while starting.")

        base_url = f"http://{host}:{bound_port}"
        info = GatewayRuntimeInfo(
            host=host,
            port=bound_port,
            base_url=base_url,
            mcp_url=f"{base_url}{self._mcp_path}",
        )
        self._runtime_info = info
        logger.info("RemoteMCPGateway serving Streamable HTTP at %s", info.mcp_url)
        return info

    async def stop(self) -> None:
        """Invalidate token, shut down uvicorn and upstream MCP session cleanly."""
        self._bearer_token = ""
        if self._server is not None:
            self._server.should_exit = True
        if self._server_task is not None:
            try:
                await asyncio.wait_for(self._server_task, timeout=5.0)
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


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for running the Remote MCP Gateway behind an HTTPS reverse proxy."""
    parser = argparse.ArgumentParser(
        description="Walled AI MCP Guard — Authenticated Remote MCP Streamable HTTP Gateway"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to Guard JSON configuration file (e.g. config/servers.json).",
    )
    parser.add_argument(
        "--server",
        default=None,
        help="Configured upstream MCP server name (defaults to default_server).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1; terminate TLS via reverse proxy like Caddy/Nginx/Cloudflare Tunnel).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8443,
        help="TCP port to listen on (default: 8443).",
    )
    parser.add_argument(
        "--use-desktop-guard",
        action="store_true",
        help="Route tool approval prompts to the running Walled AI MCP Guard desktop application.",
    )
    parser.add_argument(
        "--broker-file",
        default=None,
        help="Optional explicit path to the desktop guard broker runtime file.",
    )
    parser.add_argument(
        "--allowed-host",
        action="append",
        default=None,
        help="Allowed Host header pattern (repeatable, e.g. mcp.example.com).",
    )
    parser.add_argument(
        "--allowed-origin",
        action="append",
        default=None,
        help="Allowed Origin header pattern (repeatable, e.g. https://claude.ai).",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    token = os.environ.get(ENV_GATEWAY_TOKEN, "").strip()
    if len(token) < _MIN_TOKEN_LEN:
        print(
            f"ERROR: Environment variable {ENV_GATEWAY_TOKEN} must be set to a random "
            f"secret of at least {_MIN_TOKEN_LEN} characters (fail-closed).",
            file=sys.stderr,
        )
        return 2

    cfg = load_config(args.config)
    server_name, server_cfg = cfg.get_server(args.server)

    if args.use_desktop_guard:
        from app.authorization.ipc_broker import RemoteBrokerAuthorizer

        authorizer: ToolAuthorizer = RemoteBrokerAuthorizer(
            broker_file=args.broker_file,
            request_timeout_seconds=cfg.approval_timeout_seconds + 30.0,
        )
    else:
        authorizer = FailClosedAuthorizer(
            reason="Remote gateway launched without --use-desktop-guard (fail-closed)."
        )

    allowed_hosts = ["127.0.0.1:*", "localhost:*"]
    if args.allowed_host:
        allowed_hosts.extend(args.allowed_host)
    allowed_origins = ["http://127.0.0.1:*", "http://localhost:*"]
    if args.allowed_origin:
        allowed_origins.extend(args.allowed_origin)

    gateway = RemoteMCPGateway(
        server_name=server_name,
        server_config=server_cfg,
        bearer_token=token,
        authorizer=authorizer,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )

    uvicorn.run(
        gateway.app,
        host=args.host,
        port=args.port,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
