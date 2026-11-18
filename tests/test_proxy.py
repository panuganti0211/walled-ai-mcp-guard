"""Phase 2 integration & security tests for Walled AI MCP Guard STDIO Proxy.

All core protocol tests run against the real `tests.test_mcp_server` MCP server
using the official MCP Python SDK 2.3.0 client/server transports (no mocked protocol).
"""

from __future__ import annotations

import asyncio
import json
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Awaitable

import anyio
import mcp.types as types
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError
from mcp.shared.memory import create_client_server_memory_streams

from app.config import (
    ConfigError,
    UpstreamServerConfig,
    load_config,
    resolve_sandbox_path,
)
from app.models.request import (
    ERR_AUTHORIZATION_DENIED,
    ERR_AUTHORIZATION_SYSTEM_FAILURE,
    AuthorizationDecision,
    DecisionOutcome,
    InterceptedRequest,
    RequestStatus,
    ToolAuthorizer,
)
from app.proxy.stdio_proxy import StdioMCPProxy


class CallbackAuthorizer:
    """Explicit programmable authorizer used by integration tests."""

    def __init__(
        self,
        fn: Callable[[InterceptedRequest], Awaitable[Any]],
    ) -> None:
        self._fn = fn
        self.received: list[InterceptedRequest] = []

    async def authorize(self, request: InterceptedRequest) -> AuthorizationDecision:
        self.received.append(request)
        return await self._fn(request)


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
async def _connected_proxy_session(
    sandbox_dir: Path,
    authorizer: ToolAuthorizer | None = None,
) -> AsyncIterator[tuple[ClientSession, StdioMCPProxy]]:
    """Run StdioMCPProxy connected to a real upstream STDIO test MCP server."""
    server_cfg = _make_test_server_config(sandbox_dir)
    proxy = StdioMCPProxy(
        server_name="safe-test-server",
        server_config=server_cfg,
        authorizer=authorizer,
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
                # Closing the client streams triggers clean shutdown of the proxy loop.
                await client_write.aclose()
                await client_read.aclose()


# ======================================================================
# 1. Configuration & Sandbox Security Validation
# ======================================================================


def test_example_config_loads_cleanly() -> None:
    config = load_config(Path("config/servers.example.json"))
    name, server = config.get_server()
    assert name == "filesystem-sandbox"
    assert server.transport == "stdio"
    assert server.enabled is True


@pytest.mark.parametrize(
    "bad_command",
    [
        "cmd.exe",
        "powershell.exe",
        "bash",
        "python; whoami",
        "python && dir",
        "python | cat",
        "",
    ],
)
def test_config_rejects_shell_or_injected_commands(
    tmp_path: Path, bad_command: str
) -> None:
    cfg_path = tmp_path / "bad_config.json"
    cfg_path.write_text(
        json.dumps(
            {
                "default_server": "bad",
                "servers": {
                    "bad": {
                        "transport": "stdio",
                        "command": bad_command,
                        "args": [],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(cfg_path)


def test_config_rejects_unconfigured_or_disabled_server(tmp_path: Path) -> None:
    cfg_path = tmp_path / "servers.json"
    cfg_path.write_text(
        json.dumps(
            {
                "default_server": "active",
                "servers": {
                    "active": {
                        "command": sys.executable,
                        "args": ["-m", "tests.test_mcp_server"],
                        "enabled": True,
                    },
                    "inactive": {
                        "command": sys.executable,
                        "args": ["-m", "tests.test_mcp_server"],
                        "enabled": False,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    cfg = load_config(cfg_path)
    with pytest.raises(ConfigError):
        cfg.get_server("unknown-server")
    with pytest.raises(ConfigError):
        cfg.get_server("inactive")


@pytest.mark.parametrize(
    "bad_path",
    [
        "../outside.txt",
        "..\\outside.txt",
        "sub/../../outside.txt",
        "C:\\Windows\\win.ini",
        "/etc/passwd",
        "\\\\server\\share\\file.txt",
        "D:relative_drive.txt",
        "valid\x00evil.txt",
    ],
)
def test_resolve_sandbox_path_blocks_escapes(tmp_path: Path, bad_path: str) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    with pytest.raises(ValueError):
        resolve_sandbox_path(sandbox, bad_path)


# ======================================================================
# 2. Initialization, Tool Discovery & Non-Tool Protocol Forwarding
# ======================================================================


@pytest.mark.asyncio
async def test_initialization_tool_discovery_and_non_tool_forwarding(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    authorizer = CallbackAuthorizer(
        lambda req: asyncio.sleep(0, result=AuthorizationDecision(DecisionOutcome.BLOCK))
    )

    async with _connected_proxy_session(sandbox, authorizer=authorizer) as (
        session,
        proxy,
    ):
        init_result = await session.initialize()
        assert "walled-ai-mcp-guard" in init_result.server_info.name
        assert init_result.capabilities.tools is not None
        assert init_result.capabilities.resources is not None
        assert init_result.capabilities.prompts is not None

        # Tool discovery
        tools_result = await session.list_tools()
        tool_names = {tool.name for tool in tools_result.tools}
        assert tool_names == {
            "get_current_time",
            "read_test_file",
            "create_test_file",
            "list_test_directory",
        }

        # Non-tool operations forward cleanly without triggering tool authorization
        resources_result = await session.list_resources()
        assert any(str(r.uri) == "sandbox://info" for r in resources_result.resources)

        read_res = await session.read_resource("sandbox://info")
        assert len(read_res.contents) == 1
        info_payload = json.loads(read_res.contents[0].text)
        assert info_payload["sandbox_active"] is True

        prompts_result = await session.list_prompts()
        assert any(p.name == "sandbox_summary" for p in prompts_result.prompts)

        prompt_res = await session.get_prompt("sandbox_summary", {"topic": "audit"})
        assert "audit" in prompt_res.messages[0].content.text

        await session.send_ping()

        # Verify no tool authorization was invoked for non-tool operations
        assert authorizer.received == []
        assert proxy.handler is not None
        assert proxy.handler.history == []


# ======================================================================
# 3. Approved Tool Calls Execute Upstream
# ======================================================================


@pytest.mark.asyncio
async def test_approved_tool_calls_execute_upstream(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"

    async def approve_explicitly(req: InterceptedRequest) -> AuthorizationDecision:
        return AuthorizationDecision(
            outcome=DecisionOutcome.ALLOW,
            reason="Explicitly approved in Phase 2 test",
            decided_by="test-user",
        )

    authorizer = CallbackAuthorizer(approve_explicitly)

    async with _connected_proxy_session(sandbox, authorizer=authorizer) as (
        session,
        proxy,
    ):
        await session.initialize()
        await session.list_tools()

        # 1. get_current_time
        time_res = await session.call_tool("get_current_time", {})
        assert not time_res.is_error
        parsed_time = datetime.fromisoformat(time_res.content[0].text)
        assert parsed_time.tzinfo is not None

        # 2. create_test_file
        create_res = await session.call_tool(
            "create_test_file",
            {"filename": "notes/hello.txt", "content": "Walled AI verified!"},
        )
        assert not create_res.is_error
        assert (sandbox / "notes" / "hello.txt").read_text(encoding="utf-8") == (
            "Walled AI verified!"
        )

        # 3. list_test_directory
        list_res = await session.call_tool("list_test_directory", {"subpath": "notes"})
        assert not list_res.is_error
        listing = json.loads(list_res.content[0].text)
        assert listing["entries"] == [{"name": "hello.txt", "type": "file"}]

        # 4. read_test_file
        read_res = await session.call_tool(
            "read_test_file", {"filename": "notes/hello.txt"}
        )
        assert not read_res.is_error
        assert read_res.content[0].text == "Walled AI verified!"

        # Verify request metadata & JSON-RPC request IDs were captured accurately
        assert len(authorizer.received) == 4
        request_ids = [r.jsonrpc_request_id for r in authorizer.received]
        assert all(rid is not None for rid in request_ids)
        assert len(set(request_ids)) == 4
        assert all(r.status is RequestStatus.COMPLETED for r in authorizer.received)
        assert all(r.tool_description for r in authorizer.received)


# ======================================================================
# 4. Blocked Tool Calls NEVER Execute Upstream (Marker File Test)
# ======================================================================


@pytest.mark.asyncio
async def test_blocked_tool_call_never_executes_upstream(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    marker_file = sandbox / "blocked_marker.txt"

    async def block_all(req: InterceptedRequest) -> AuthorizationDecision:
        return AuthorizationDecision(
            outcome=DecisionOutcome.BLOCK,
            reason="User denied file creation",
            decided_by="test-user",
        )

    authorizer = CallbackAuthorizer(block_all)

    async with _connected_proxy_session(sandbox, authorizer=authorizer) as (
        session,
        proxy,
    ):
        await session.initialize()

        with pytest.raises(MCPError) as exc_info:
            await session.call_tool(
                "create_test_file",
                {"filename": "blocked_marker.txt", "content": "MUST_NOT_BE_WRITTEN"},
            )

        assert exc_info.value.error.code == ERR_AUTHORIZATION_DENIED
        assert "blocked" in exc_info.value.error.message.lower()
        assert not marker_file.exists(), "Blocked tool must NEVER create the marker file!"
        assert len(authorizer.received) == 1
        assert authorizer.received[0].status is RequestStatus.BLOCKED


# ======================================================================
# 5. Missing Authorization & Authorizer Errors Fail Closed
# ======================================================================


@pytest.mark.asyncio
async def test_missing_authorizer_fails_closed(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    marker_file = sandbox / "no_authorizer_marker.txt"

    # authorizer=None MUST default to FailClosedAuthorizer
    async with _connected_proxy_session(sandbox, authorizer=None) as (session, proxy):
        await session.initialize()

        with pytest.raises(MCPError) as exc_info:
            await session.call_tool(
                "create_test_file",
                {"filename": "no_authorizer_marker.txt", "content": "SHOULD_NOT_EXIST"},
            )

        assert exc_info.value.error.code == ERR_AUTHORIZATION_SYSTEM_FAILURE
        assert not marker_file.exists()


@pytest.mark.asyncio
async def test_authorizer_exception_and_invalid_return_fail_closed(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    call_count = 0

    async def faulty_authorizer(req: InterceptedRequest) -> Any:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("Simulated authorization backend crash")
        # Return an invalid truthy value (must NOT be treated as approval!)
        return True

    async with _connected_proxy_session(
        sandbox, authorizer=CallbackAuthorizer(faulty_authorizer)
    ) as (session, proxy):
        await session.initialize()

        with pytest.raises(MCPError) as exc1:
            await session.call_tool(
                "create_test_file",
                {"filename": "crash_marker.txt", "content": "nope"},
            )
        assert exc1.value.error.code == ERR_AUTHORIZATION_SYSTEM_FAILURE
        assert not (sandbox / "crash_marker.txt").exists()

        with pytest.raises(MCPError) as exc2:
            await session.call_tool(
                "create_test_file",
                {"filename": "invalid_decision_marker.txt", "content": "nope"},
            )
        assert exc2.value.error.code == ERR_AUTHORIZATION_SYSTEM_FAILURE
        assert not (sandbox / "invalid_decision_marker.txt").exists()


# ======================================================================
# 6. Concurrent Simultaneous Requests (Independent & Out-of-Order)
# ======================================================================


@pytest.mark.asyncio
async def test_concurrent_requests_are_independent(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"

    all_arrived = asyncio.Event()
    gates: dict[str, asyncio.Event] = {
        "req_block.txt": asyncio.Event(),
        "req_allow_1.txt": asyncio.Event(),
        "req_allow_2.txt": asyncio.Event(),
    }
    decisions: dict[str, AuthorizationDecision] = {}
    arrived_requests: dict[str, InterceptedRequest] = {}

    async def gated_authorizer(req: InterceptedRequest) -> AuthorizationDecision:
        filename = req.arguments["filename"]
        arrived_requests[filename] = req
        if len(arrived_requests) == 3:
            all_arrived.set()
        await gates[filename].wait()
        return decisions[filename]

    authorizer = CallbackAuthorizer(gated_authorizer)

    async with _connected_proxy_session(sandbox, authorizer=authorizer) as (
        session,
        proxy,
    ):
        await session.initialize()

        task_block = asyncio.create_task(
            session.call_tool(
                "create_test_file",
                {"filename": "req_block.txt", "content": "must-not-exist"},
            )
        )
        task_allow_1 = asyncio.create_task(
            session.call_tool(
                "create_test_file",
                {"filename": "req_allow_1.txt", "content": "alpha"},
            )
        )
        task_allow_2 = asyncio.create_task(
            session.call_tool(
                "create_test_file",
                {"filename": "req_allow_2.txt", "content": "beta"},
            )
        )

        # Confirm all 3 requests are simultaneously pending in the proxy
        await asyncio.wait_for(all_arrived.wait(), timeout=10.0)
        assert len(arrived_requests) == 3

        # Confirm distinct JSON-RPC request IDs and internal IDs
        rpc_ids = {r.jsonrpc_request_id for r in arrived_requests.values()}
        internal_ids = {r.internal_id for r in arrived_requests.values()}
        assert len(rpc_ids) == 3
        assert len(internal_ids) == 3

        # Resolve OUT OF ORDER: allow_2 first, then allow_1, then block last
        decisions["req_allow_2.txt"] = AuthorizationDecision(DecisionOutcome.ALLOW)
        gates["req_allow_2.txt"].set()
        res_allow_2 = await asyncio.wait_for(task_allow_2, timeout=10.0)
        assert not res_allow_2.is_error
        assert (sandbox / "req_allow_2.txt").read_text(encoding="utf-8") == "beta"
        # Other two are still held pending — neither file should exist yet
        assert not (sandbox / "req_allow_1.txt").exists()
        assert not (sandbox / "req_block.txt").exists()

        decisions["req_allow_1.txt"] = AuthorizationDecision(DecisionOutcome.ALLOW)
        gates["req_allow_1.txt"].set()
        res_allow_1 = await asyncio.wait_for(task_allow_1, timeout=10.0)
        assert not res_allow_1.is_error
        assert (sandbox / "req_allow_1.txt").read_text(encoding="utf-8") == "alpha"

        decisions["req_block.txt"] = AuthorizationDecision(
            DecisionOutcome.BLOCK, reason="Blocked independently"
        )
        gates["req_block.txt"].set()
        with pytest.raises(MCPError) as blocked_exc:
            await asyncio.wait_for(task_block, timeout=10.0)
        assert blocked_exc.value.error.code == ERR_AUTHORIZATION_DENIED
        assert not (sandbox / "req_block.txt").exists()


# ======================================================================
# 7. Upstream Errors & Live Sandbox Confinement
# ======================================================================


@pytest.mark.asyncio
async def test_upstream_errors_and_sandbox_confinement(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    outside_secret = tmp_path / "outside_secret.txt"
    outside_secret.write_text("TOP_SECRET", encoding="utf-8")

    authorizer = CallbackAuthorizer(
        lambda req: asyncio.sleep(0, result=AuthorizationDecision(DecisionOutcome.ALLOW))
    )

    async with _connected_proxy_session(sandbox, authorizer=authorizer) as (
        session,
        proxy,
    ):
        await session.initialize()

        # 1. Missing file inside sandbox returns an upstream tool error cleanly
        missing_res = await session.call_tool(
            "read_test_file", {"filename": "does_not_exist.txt"}
        )
        assert missing_res.is_error is True

        # 2. Traversal read attempt is rejected by upstream sandbox
        traversal_read = await session.call_tool(
            "read_test_file", {"filename": "../outside_secret.txt"}
        )
        assert traversal_read.is_error is True
        assert "TOP_SECRET" not in traversal_read.content[0].text

        # 3. Traversal write attempt is rejected and creates nothing outside sandbox
        traversal_write = await session.call_tool(
            "create_test_file",
            {"filename": "../escape_marker.txt", "content": "escaped"},
        )
        assert traversal_write.is_error is True
        assert not (tmp_path / "escape_marker.txt").exists()

        # 4. Proxy remains healthy after upstream errors
        ok_res = await session.call_tool("get_current_time", {})
        assert not ok_res.is_error


# ======================================================================
# 8. Full 3-Process Real STDIO Subprocess End-to-End Test
# ======================================================================


@pytest.mark.asyncio
async def test_full_stdio_subprocess_proxy_end_to_end(tmp_path: Path) -> None:
    """Launch `app.proxy.stdio_proxy` as a real STDIO subprocess wrapping `test_mcp_server`."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    config_file = tmp_path / "servers.json"
    config_file.write_text(
        json.dumps(
            {
                "default_server": "safe-test-server",
                "servers": {
                    "safe-test-server": {
                        "transport": "stdio",
                        "command": sys.executable,
                        "args": [
                            "-m",
                            "tests.test_mcp_server",
                            "--sandbox-dir",
                            str(sandbox),
                        ],
                        "enabled": True,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    proxy_params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "app.proxy.stdio_proxy",
            "--config",
            str(config_file),
            "--server",
            "safe-test-server",
        ],
    )

    async with stdio_client(proxy_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_res = await session.initialize()
            assert "walled-ai-mcp-guard" in init_res.server_info.name

            tools_res = await session.list_tools()
            assert {t.name for t in tools_res.tools} == {
                "get_current_time",
                "read_test_file",
                "create_test_file",
                "list_test_directory",
            }

            # Resource forwarding over real STDIO pipes
            res_read = await session.read_resource("sandbox://info")
            assert json.loads(res_read.contents[0].text)["sandbox_active"] is True

            # Standalone CLI proxy has no interactive authorizer -> MUST fail closed
            marker = sandbox / "cli_fail_closed_marker.txt"
            with pytest.raises(MCPError) as exc_info:
                await session.call_tool(
                    "create_test_file",
                    {"filename": "cli_fail_closed_marker.txt", "content": "nope"},
                )
            assert exc_info.value.error.code == ERR_AUTHORIZATION_SYSTEM_FAILURE
            assert not marker.exists()
