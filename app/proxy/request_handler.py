"""Single enforcement boundary and protocol forwarder for intercepted MCP requests."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.server.context import ServerRequestContext
from mcp.shared.exceptions import MCPError

from app.models.request import (
    ERR_AUTHORIZATION_CANCELLED,
    ERR_AUTHORIZATION_DENIED,
    ERR_AUTHORIZATION_SYSTEM_FAILURE,
    AuthorizationDecision,
    DecisionOutcome,
    FailClosedAuthorizer,
    InterceptedRequest,
    RequestStatus,
    ToolAuthorizer,
    validate_and_clone_arguments,
)

logger = logging.getLogger(__name__)

_MAX_TOOL_NAME_LEN = 256


class RequestHandler:
    """Mediates all MCP operations between a downstream client and an upstream server.

    Security invariant:
        `handle_call_tool` is the ONLY code path permitted to invoke
        `upstream.call_tool(...)`. Every tool call MUST obtain an explicit
        `DecisionOutcome.ALLOW` from the configured `ToolAuthorizer` before
        reaching the upstream server. Any missing authorizer, invalid decision,
        timeout, cancellation, or authorization exception fails closed.
    """

    def __init__(
        self,
        *,
        server_name: str,
        upstream: ClientSession,
        authorizer: ToolAuthorizer | None = None,
        on_request_event: Callable[[InterceptedRequest], None] | None = None,
    ) -> None:
        if not server_name or not server_name.strip():
            raise ValueError("server_name must be a non-empty string.")
        self._server_name = server_name.strip()
        self._upstream = upstream
        self._authorizer: ToolAuthorizer = (
            authorizer if authorizer is not None else FailClosedAuthorizer()
        )
        self._on_request_event = on_request_event
        self._tool_catalog: dict[str, types.Tool] = {}
        self._executed_ids: set[str] = set()
        self._exec_lock = asyncio.Lock()
        self._history: list[InterceptedRequest] = []

    @property
    def server_name(self) -> str:
        return self._server_name

    @property
    def history(self) -> list[InterceptedRequest]:
        """Return a shallow copy of intercepted tool request records."""
        return list(self._history)

    def _emit_event(self, request: InterceptedRequest) -> None:
        if self._on_request_event is not None:
            try:
                self._on_request_event(request)
            except Exception:
                logger.exception(
                    "Request event observer raised an error for request %s",
                    request.internal_id,
                )

    def _validate_tool_name(self, raw_name: Any) -> str:
        if not isinstance(raw_name, str):
            raise MCPError(
                code=types.INVALID_PARAMS,
                message="Tool name must be a string.",
            )
        name = raw_name.strip()
        if not name or len(name) > _MAX_TOOL_NAME_LEN or "\x00" in name:
            raise MCPError(
                code=types.INVALID_PARAMS,
                message="Invalid tool name in tools/call request.",
            )
        return name

    async def _authorize_fail_closed(
        self, request: InterceptedRequest
    ) -> AuthorizationDecision:
        """Invoke the configured authorizer with strict fail-closed semantics."""
        if self._authorizer is None:
            return AuthorizationDecision(
                outcome=DecisionOutcome.ERROR,
                reason="No authorizer configured (fail-closed).",
                decided_by="system:fail-closed",
            )

        try:
            decision = await self._authorizer.authorize(request)
        except asyncio.CancelledError:
            request.mark_decision(
                AuthorizationDecision(
                    outcome=DecisionOutcome.CANCELLED,
                    reason="Request cancelled while awaiting authorization.",
                    decided_by="system:cancelled",
                )
            )
            self._emit_event(request)
            raise
        except Exception as exc:
            logger.error(
                "Authorizer error for request %s (tool=%s): %s",
                request.internal_id,
                request.tool_name,
                type(exc).__name__,
            )
            return AuthorizationDecision(
                outcome=DecisionOutcome.ERROR,
                reason=f"Authorization failed ({type(exc).__name__}); failing closed.",
                decided_by="system:fail-closed",
            )

        if not isinstance(decision, AuthorizationDecision):
            logger.error(
                "Authorizer returned invalid decision object (%s) for request %s; failing closed.",
                type(decision).__name__,
                request.internal_id,
            )
            return AuthorizationDecision(
                outcome=DecisionOutcome.ERROR,
                reason="Authorizer returned an invalid decision object (fail-closed).",
                decided_by="system:fail-closed",
            )

        return decision

    def _build_denial_error(
        self,
        request: InterceptedRequest,
        decision: AuthorizationDecision,
    ) -> MCPError:
        data = {
            "internal_id": request.internal_id,
            "request_id": request.jsonrpc_request_id,
            "server_name": request.server_name,
            "tool_name": request.tool_name,
            "status": request.status.value,
            "outcome": decision.outcome.value,
            "reason": decision.reason,
        }
        if decision.outcome is DecisionOutcome.BLOCK:
            reason_suffix = f" ({decision.reason})" if decision.reason else ""
            return MCPError(
                code=ERR_AUTHORIZATION_DENIED,
                message=(
                    f"Walled AI MCP Guard blocked tool '{request.tool_name}' "
                    f"on server '{request.server_name}'{reason_suffix}."
                ),
                data=data,
            )
        if decision.outcome is DecisionOutcome.TIMEOUT:
            return MCPError(
                code=types.REQUEST_TIMEOUT,
                message=(
                    f"Authorization timed out for tool '{request.tool_name}' "
                    f"on server '{request.server_name}'."
                ),
                data=data,
            )
        if decision.outcome is DecisionOutcome.CANCELLED:
            return MCPError(
                code=ERR_AUTHORIZATION_CANCELLED,
                message=(
                    f"Authorization cancelled for tool '{request.tool_name}' "
                    f"on server '{request.server_name}'."
                ),
                data=data,
            )
        return MCPError(
            code=ERR_AUTHORIZATION_SYSTEM_FAILURE,
            message=(
                f"Tool '{request.tool_name}' denied because authorization could not "
                f"be verified (fail-closed)."
            ),
            data=data,
        )

    # ------------------------------------------------------------------
    # Tool operations (discovery + intercepted execution)
    # ------------------------------------------------------------------

    async def handle_list_tools(
        self,
        ctx: ServerRequestContext[Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        """Forward tools/list and cache tool descriptions for authorization prompts."""
        result = await self._upstream.list_tools(params=params)
        for tool in result.tools:
            self._tool_catalog[tool.name] = tool
        return result

    async def handle_call_tool(
        self,
        ctx: ServerRequestContext[Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult | types.InputRequiredResult:
        """Intercept tools/call, require explicit authorization, then forward if approved."""
        tool_name = self._validate_tool_name(params.name)
        try:
            safe_arguments = validate_and_clone_arguments(params.arguments)
        except ValueError as exc:
            raise MCPError(
                code=types.INVALID_PARAMS,
                message=f"Invalid tool arguments for '{tool_name}': {exc}",
            ) from exc

        tool_meta = self._tool_catalog.get(tool_name)
        tool_description = tool_meta.description if tool_meta is not None else None

        intercepted = InterceptedRequest(
            server_name=self._server_name,
            tool_name=tool_name,
            arguments=safe_arguments,
            jsonrpc_request_id=ctx.request_id,
            tool_description=tool_description,
        )
        self._history.append(intercepted)
        self._emit_event(intercepted)

        decision = await self._authorize_fail_closed(intercepted)
        if intercepted.decision is None:
            intercepted.mark_decision(decision)
        self._emit_event(intercepted)

        if not decision.is_allowed:
            raise self._build_denial_error(intercepted, decision)

        # Prevent duplicate execution of the same authorized request.
        async with self._exec_lock:
            if intercepted.internal_id in self._executed_ids:
                self._fail_execution(
                    intercepted,
                    "Duplicate tool execution prevented.",
                    execution_result="not_executed",
                )
                self._emit_event(intercepted)
                raise MCPError(
                    code=ERR_AUTHORIZATION_SYSTEM_FAILURE,
                    message="Duplicate tool execution prevented.",
                    data={"internal_id": intercepted.internal_id},
                )
            try:
                self._begin_execution(intercepted)
            except Exception as exc:
                self._fail_execution(
                    intercepted,
                    f"Execution transition denied: {exc}",
                    execution_result="not_executed",
                )
                self._emit_event(intercepted)
                raise MCPError(
                    code=ERR_AUTHORIZATION_SYSTEM_FAILURE,
                    message=f"Tool execution denied: {exc}",
                    data={"internal_id": intercepted.internal_id},
                ) from exc
            self._executed_ids.add(intercepted.internal_id)
        self._emit_event(intercepted)

        try:
            result = await self._upstream.call_tool(
                name=tool_name,
                arguments=safe_arguments,
                meta=params.meta,
                input_responses=params.input_responses,
                request_state=params.request_state,
            )
        except MCPError as exc:
            self._fail_execution(
                intercepted, str(exc), execution_result="upstream_error"
            )
            self._emit_event(intercepted)
            raise
        except Exception as exc:
            logger.error(
                "Upstream call_tool failure for request %s (tool=%s): %s",
                intercepted.internal_id,
                tool_name,
                type(exc).__name__,
            )
            self._fail_execution(
                intercepted,
                f"Upstream execution failed: {exc}",
                execution_result="upstream_error",
            )
            self._emit_event(intercepted)
            raise MCPError(
                code=types.INTERNAL_ERROR,
                message=f"Upstream MCP server error while executing '{tool_name}': {exc}",
                data={
                    "internal_id": intercepted.internal_id,
                    "server_name": self._server_name,
                    "tool_name": tool_name,
                },
            ) from exc

        if isinstance(result, types.CallToolResult) and result.is_error:
            self._fail_execution(
                intercepted,
                "Upstream tool returned an error result.",
                execution_result="tool_error",
            )
        else:
            self._complete_execution(intercepted)
        self._emit_event(intercepted)
        return result  # type: ignore[return-value]

    def _begin_execution(self, request: InterceptedRequest) -> None:
        hook = getattr(self._authorizer, "begin_execution", None)
        if callable(hook):
            hook(request.internal_id)
        else:
            request.mark_executing()

    def _complete_execution(self, request: InterceptedRequest) -> None:
        hook = getattr(self._authorizer, "complete_execution", None)
        if callable(hook):
            hook(request.internal_id)
        else:
            request.mark_completed()

    def _fail_execution(
        self,
        request: InterceptedRequest,
        error_message: str,
        *,
        execution_result: str = "upstream_error",
    ) -> None:
        hook = getattr(self._authorizer, "fail_execution", None)
        if callable(hook):
            hook(
                request.internal_id,
                error_message,
                execution_result=execution_result,
            )
        else:
            request.mark_failed(error_message)

    # ------------------------------------------------------------------
    # Non-tool MCP operations (forwarded transparently)
    # ------------------------------------------------------------------

    async def handle_list_resources(
        self,
        ctx: ServerRequestContext[Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListResourcesResult:
        return await self._upstream.list_resources(params=params)

    async def handle_list_resource_templates(
        self,
        ctx: ServerRequestContext[Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListResourceTemplatesResult:
        return await self._upstream.list_resource_templates(params=params)

    async def handle_read_resource(
        self,
        ctx: ServerRequestContext[Any],
        params: types.ReadResourceRequestParams,
    ) -> types.ReadResourceResult | types.InputRequiredResult:
        return await self._upstream.read_resource(
            uri=params.uri,
            input_responses=params.input_responses,
            request_state=params.request_state,
            meta=params.meta,
        )

    async def handle_subscribe_resource(
        self,
        ctx: ServerRequestContext[Any],
        params: types.SubscribeRequestParams,
    ) -> types.EmptyResult:
        return await self._upstream.subscribe_resource(uri=params.uri, meta=params.meta)

    async def handle_unsubscribe_resource(
        self,
        ctx: ServerRequestContext[Any],
        params: types.UnsubscribeRequestParams,
    ) -> types.EmptyResult:
        return await self._upstream.unsubscribe_resource(uri=params.uri, meta=params.meta)

    async def handle_list_prompts(
        self,
        ctx: ServerRequestContext[Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListPromptsResult:
        return await self._upstream.list_prompts(params=params)

    async def handle_get_prompt(
        self,
        ctx: ServerRequestContext[Any],
        params: types.GetPromptRequestParams,
    ) -> types.GetPromptResult | types.InputRequiredResult:
        return await self._upstream.get_prompt(
            name=params.name,
            arguments=params.arguments,
            input_responses=params.input_responses,
            request_state=params.request_state,
            meta=params.meta,
        )

    async def handle_completion(
        self,
        ctx: ServerRequestContext[Any],
        params: types.CompleteRequestParams,
    ) -> types.CompleteResult:
        context_args = params.context.arguments if params.context is not None else None
        return await self._upstream.complete(
            ref=params.ref,
            argument={
                "name": params.argument.name,
                "value": params.argument.value,
            },
            context_arguments=context_args,
        )

    async def handle_set_logging_level(
        self,
        ctx: ServerRequestContext[Any],
        params: types.SetLevelRequestParams,
    ) -> types.EmptyResult:
        return await self._upstream.set_logging_level(level=params.level, meta=params.meta)

    async def handle_ping(
        self,
        ctx: ServerRequestContext[Any],
        params: types.RequestParams | None,
    ) -> types.EmptyResult:
        return await self._upstream.send_ping(meta=ctx.meta)

    async def handle_roots_list_changed(
        self,
        ctx: ServerRequestContext[Any],
        params: types.NotificationParams | None,
    ) -> None:
        await self._upstream.send_roots_list_changed()

    async def handle_progress(
        self,
        ctx: ServerRequestContext[Any],
        params: types.ProgressNotificationParams,
    ) -> None:
        await self._upstream.send_progress_notification(
            progress_token=params.progress_token,
            progress=params.progress,
            total=params.total,
            message=params.message,
            meta=params.meta,
        )
