"""Official MCP SDK v2.3.0 STDIO proxy connecting downstream clients to an upstream MCP server."""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import logging
import sys
from collections.abc import Callable
from typing import Any

import anyio
import mcp.types as types
from mcp.client import IncomingMessage
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel.server import NotificationOptions, Server
from mcp.server.session import ServerSession
from mcp.server.stdio import stdio_server
from mcp.shared._stream_protocols import ReadStream, WriteStream
from mcp.shared.message import SessionMessage

from app import __version__ as app_version
from app.config import (
    UpstreamServerConfig,
    build_sanitized_env,
    load_config,
)
from app.models.request import (
    FailClosedAuthorizer,
    InterceptedRequest,
    ToolAuthorizer,
)
from app.proxy.request_handler import RequestHandler

logger = logging.getLogger(__name__)


def _get_mcp_sdk_version() -> str:
    try:
        return importlib.metadata.version("mcp")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


class StdioMCPProxy:
    """Genuine intermediary MCP server/client proxy over official SDK transports.

    - Downstream side: serves an MCP client (e.g. Claude Desktop) using
      `mcp.server.lowlevel.server.Server` over `stdio_server()` (or any SDK streams).
    - Upstream side: spawns the explicitly configured upstream MCP server using
      `mcp.client.stdio.stdio_client` + `ClientSession`.
    - Enforcement boundary: all `tools/call` traffic passes exclusively through
      `RequestHandler`, which enforces fail-closed authorization via `ToolAuthorizer`.
    """

    def __init__(
        self,
        *,
        server_name: str,
        server_config: UpstreamServerConfig,
        authorizer: ToolAuthorizer | None = None,
        on_request_event: Callable[[InterceptedRequest], None] | None = None,
        proxy_name: str = "walled-ai-mcp-guard",
        upstream_read_timeout_seconds: float | None = None,
    ) -> None:
        self._server_name = server_name
        self._server_config = server_config
        self._authorizer: ToolAuthorizer = (
            authorizer if authorizer is not None else FailClosedAuthorizer()
        )
        self._on_request_event = on_request_event
        self._proxy_name = proxy_name
        self._upstream_read_timeout_seconds = upstream_read_timeout_seconds

        self._downstream_session: ServerSession | None = None
        self._handler: RequestHandler | None = None
        self._upstream_init: types.InitializeResult | None = None

    @property
    def handler(self) -> RequestHandler | None:
        """Return the active RequestHandler once connected upstream."""
        return self._handler

    @property
    def upstream_initialize_result(self) -> types.InitializeResult | None:
        """Return the upstream server's InitializeResult once initialized."""
        return self._upstream_init

    def _build_stdio_params(self) -> StdioServerParameters:
        return StdioServerParameters(
            command=self._server_config.command,
            args=list(self._server_config.args),
            env=build_sanitized_env(self._server_config.env),
            cwd=self._server_config.cwd,
        )

    async def _forward_upstream_notification(self, message: IncomingMessage) -> None:
        """Forward relevant upstream server-to-client notifications downstream."""
        if isinstance(message, Exception):
            logger.error("Upstream session message error: %s", message)
            return

        session = self._downstream_session
        if session is None:
            return

        try:
            if isinstance(message, types.ToolListChangedNotification):
                await session.send_tool_list_changed()
            elif isinstance(message, types.ResourceListChangedNotification):
                await session.send_resource_list_changed()
            elif isinstance(message, types.PromptListChangedNotification):
                await session.send_prompt_list_changed()
            elif isinstance(message, types.ResourceUpdatedNotification):
                await session.send_resource_updated(uri=message.params.uri)
            elif isinstance(message, types.ProgressNotification):
                await session.send_progress_notification(
                    progress_token=message.params.progress_token,
                    progress=message.params.progress,
                    total=message.params.total,
                    message=message.params.message,
                )
        except Exception:
            logger.debug("Failed to forward upstream notification downstream.", exc_info=True)

    async def _forward_upstream_log(
        self, params: types.LoggingMessageNotificationParams
    ) -> None:
        session = self._downstream_session
        if session is None:
            return
        try:
            await session.send_log_message(
                level=params.level,
                data=params.data,
                logger=params.logger,
            )
        except Exception:
            logger.debug("Failed to forward upstream log message downstream.", exc_info=True)

    def _capture_session(self, ctx: ServerRequestContext[Any]) -> None:
        if self._downstream_session is not ctx.session:
            self._downstream_session = ctx.session

    def _build_downstream_server(
        self,
        handler: RequestHandler,
        upstream_init: types.InitializeResult,
    ) -> tuple[Server[Any], NotificationOptions]:
        """Construct the low-level MCP Server mirroring upstream capabilities."""
        caps = upstream_init.capabilities

        async def _wrap_list_tools(
            ctx: ServerRequestContext[Any],
            params: types.PaginatedRequestParams | None,
        ) -> types.ListToolsResult:
            self._capture_session(ctx)
            return await handler.handle_list_tools(ctx, params)

        async def _wrap_call_tool(
            ctx: ServerRequestContext[Any],
            params: types.CallToolRequestParams,
        ) -> types.CallToolResult | types.InputRequiredResult:
            self._capture_session(ctx)
            return await handler.handle_call_tool(ctx, params)

        async def _wrap_list_resources(
            ctx: ServerRequestContext[Any],
            params: types.PaginatedRequestParams | None,
        ) -> types.ListResourcesResult:
            self._capture_session(ctx)
            return await handler.handle_list_resources(ctx, params)

        async def _wrap_list_resource_templates(
            ctx: ServerRequestContext[Any],
            params: types.PaginatedRequestParams | None,
        ) -> types.ListResourceTemplatesResult:
            self._capture_session(ctx)
            return await handler.handle_list_resource_templates(ctx, params)

        async def _wrap_read_resource(
            ctx: ServerRequestContext[Any],
            params: types.ReadResourceRequestParams,
        ) -> types.ReadResourceResult | types.InputRequiredResult:
            self._capture_session(ctx)
            return await handler.handle_read_resource(ctx, params)

        async def _wrap_subscribe_resource(
            ctx: ServerRequestContext[Any],
            params: types.SubscribeRequestParams,
        ) -> types.EmptyResult:
            self._capture_session(ctx)
            return await handler.handle_subscribe_resource(ctx, params)

        async def _wrap_unsubscribe_resource(
            ctx: ServerRequestContext[Any],
            params: types.UnsubscribeRequestParams,
        ) -> types.EmptyResult:
            self._capture_session(ctx)
            return await handler.handle_unsubscribe_resource(ctx, params)

        async def _wrap_list_prompts(
            ctx: ServerRequestContext[Any],
            params: types.PaginatedRequestParams | None,
        ) -> types.ListPromptsResult:
            self._capture_session(ctx)
            return await handler.handle_list_prompts(ctx, params)

        async def _wrap_get_prompt(
            ctx: ServerRequestContext[Any],
            params: types.GetPromptRequestParams,
        ) -> types.GetPromptResult | types.InputRequiredResult:
            self._capture_session(ctx)
            return await handler.handle_get_prompt(ctx, params)

        async def _wrap_completion(
            ctx: ServerRequestContext[Any],
            params: types.CompleteRequestParams,
        ) -> types.CompleteResult:
            self._capture_session(ctx)
            return await handler.handle_completion(ctx, params)

        async def _wrap_set_logging_level(
            ctx: ServerRequestContext[Any],
            params: types.SetLevelRequestParams,
        ) -> types.EmptyResult:
            self._capture_session(ctx)
            return await handler.handle_set_logging_level(ctx, params)

        async def _wrap_ping(
            ctx: ServerRequestContext[Any],
            params: types.RequestParams | None,
        ) -> types.EmptyResult:
            self._capture_session(ctx)
            return await handler.handle_ping(ctx, params)

        async def _wrap_roots_changed(
            ctx: ServerRequestContext[Any],
            params: types.NotificationParams | None,
        ) -> None:
            self._capture_session(ctx)
            await handler.handle_roots_list_changed(ctx, params)

        async def _wrap_progress(
            ctx: ServerRequestContext[Any],
            params: types.ProgressNotificationParams,
        ) -> None:
            self._capture_session(ctx)
            await handler.handle_progress(ctx, params)

        has_tools = caps.tools is not None
        has_resources = caps.resources is not None
        has_subscribe = bool(caps.resources and caps.resources.subscribe)
        has_prompts = caps.prompts is not None
        has_completions = caps.completions is not None
        has_logging = caps.logging is not None

        server_kwargs: dict[str, Any] = {
            "name": f"{self._proxy_name} ({self._server_name})",
            "version": app_version,
            "instructions": upstream_init.instructions,
            "on_ping": _wrap_ping,
            "on_roots_list_changed": _wrap_roots_changed,
            "on_progress": _wrap_progress,
        }

        if has_tools:
            server_kwargs["on_list_tools"] = _wrap_list_tools
            server_kwargs["on_call_tool"] = _wrap_call_tool

        if has_resources:
            server_kwargs["on_list_resources"] = _wrap_list_resources
            server_kwargs["on_list_resource_templates"] = _wrap_list_resource_templates
            server_kwargs["on_read_resource"] = _wrap_read_resource
            if has_subscribe:
                server_kwargs["on_subscribe_resource"] = _wrap_subscribe_resource
                server_kwargs["on_unsubscribe_resource"] = _wrap_unsubscribe_resource

        if has_prompts:
            server_kwargs["on_list_prompts"] = _wrap_list_prompts
            server_kwargs["on_get_prompt"] = _wrap_get_prompt

        if has_completions:
            server_kwargs["on_completion"] = _wrap_completion

        if has_logging:
            server_kwargs["on_set_logging_level"] = _wrap_set_logging_level

        server = Server(**server_kwargs)
        notification_options = NotificationOptions(
            prompts_changed=bool(caps.prompts and caps.prompts.list_changed),
            resources_changed=bool(caps.resources and caps.resources.list_changed),
            tools_changed=bool(caps.tools and caps.tools.list_changed),
        )
        return server, notification_options

    async def run_streams(
        self,
        read_stream: ReadStream[SessionMessage | Exception],
        write_stream: WriteStream[SessionMessage],
        *,
        raise_exceptions: bool = False,
    ) -> None:
        """Connect upstream over STDIO and serve downstream over the provided MCP streams."""
        server_params = self._build_stdio_params()
        logger.info(
            "Starting upstream MCP server '%s' (command=%s, mcp_sdk=%s)",
            self._server_name,
            server_params.command,
            _get_mcp_sdk_version(),
        )

        async with stdio_client(server_params, errlog=sys.stderr) as (
            upstream_read,
            upstream_write,
        ):
            async with ClientSession(
                upstream_read,
                upstream_write,
                read_timeout_seconds=self._upstream_read_timeout_seconds,
                message_handler=self._forward_upstream_notification,
                logging_callback=self._forward_upstream_log,
                client_info=types.Implementation(
                    name=self._proxy_name,
                    version=app_version,
                ),
            ) as upstream_session:
                upstream_init = await upstream_session.initialize()
                self._upstream_init = upstream_init
                logger.info(
                    "Connected to upstream MCP server '%s' (name=%s, version=%s)",
                    self._server_name,
                    upstream_init.server_info.name,
                    upstream_init.server_info.version,
                )

                handler = RequestHandler(
                    server_name=self._server_name,
                    upstream=upstream_session,
                    authorizer=self._authorizer,
                    on_request_event=self._on_request_event,
                )
                self._handler = handler

                downstream_server, notif_opts = self._build_downstream_server(
                    handler, upstream_init
                )
                init_options = downstream_server.create_initialization_options(
                    notification_options=notif_opts,
                    experimental_capabilities=upstream_init.capabilities.experimental,
                    extensions=upstream_init.capabilities.extensions,
                )

                try:
                    heartbeat = getattr(self._authorizer, "send_heartbeat", None)
                    if callable(heartbeat):
                        await heartbeat(
                            server_name=self._server_name,
                            state="connected",
                            detail=f"{upstream_init.server_info.name} v{upstream_init.server_info.version}",
                        )
                    await downstream_server.run(
                        read_stream,
                        write_stream,
                        init_options,
                        raise_exceptions=raise_exceptions,
                    )
                finally:
                    self._downstream_session = None
                    heartbeat = getattr(self._authorizer, "send_heartbeat", None)
                    if callable(heartbeat):
                        try:
                            await heartbeat(
                                server_name=self._server_name,
                                state="disconnected",
                                detail="Proxy session closed",
                            )
                        except Exception:
                            pass

    async def run_stdio(self) -> None:
        """Serve downstream over standard input/output using the official SDK stdio_server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.run_streams(read_stream, write_stream)


def _configure_stderr_logging(level: str = "INFO") -> None:
    """Configure logging strictly to stderr so stdout remains clean for JSON-RPC frames."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        force=True,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for launching the STDIO MCP proxy.

    Note: Without an interactive authorizer attached, the proxy strictly runs
    in fail-closed mode (every tool call is denied; discovery and non-tool
    operations remain functional).
    """
    parser = argparse.ArgumentParser(
        description="Walled AI MCP Guard - Official SDK STDIO Proxy"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to Guard JSON configuration file (e.g. config/servers.json).",
    )
    parser.add_argument(
        "--server",
        default=None,
        help="Name of the configured upstream server (defaults to config default_server).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level written to stderr (default: INFO).",
    )
    parser.add_argument(
        "--use-desktop-guard",
        action="store_true",
        help="Authorize tools/call via the running Walled AI MCP Guard desktop application broker (fail-closed if unavailable).",
    )
    parser.add_argument(
        "--broker-file",
        default=None,
        help="Optional explicit path to the desktop guard broker runtime descriptor JSON file.",
    )
    args = parser.parse_args(argv)

    _configure_stderr_logging(args.log_level)
    config = load_config(args.config)
    server_name, server_cfg = config.get_server(args.server)

    if args.use_desktop_guard:
        from app.authorization.ipc_broker import RemoteBrokerAuthorizer

        authorizer: ToolAuthorizer = RemoteBrokerAuthorizer(
            broker_file=args.broker_file,
            request_timeout_seconds=config.approval_timeout_seconds + 30.0,
        )
    else:
        authorizer = FailClosedAuthorizer(
            reason="Standalone CLI proxy has no interactive user authorizer attached (fail-closed)."
        )

    proxy = StdioMCPProxy(
        server_name=server_name,
        server_config=server_cfg,
        authorizer=authorizer,
    )
    anyio.run(proxy.run_stdio)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
