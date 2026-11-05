"""The differences between the MCP Python SDK 1.x and 2.x the runtime depends on, in one place.

The runtime image installs whatever MCP SDK version the application needs (the application's
requirements are installed first and constrain the Backplane's). Gateway (server) and workloads
(client) run in the same image, so they always use the same SDK; both speak the session-based
handshake (``initialize`` -> ``notifications/initialized`` -> ``tools/list`` -> ``tools/call``,
``Mcp-Session-Id``) on 1.x and 2.x.

=========================  =====================================  =======================================
                           SDK 1.x                                SDK 2.x
=========================  =====================================  =======================================
HTTP client library        httpx / httpcore                       httpx2 / httpcore2 (same structure)
error raised by a session  mcp.shared.exceptions.McpError          mcp.shared.exceptions.MCPError
low-level server handlers  decorators (list_tools, call_tool)     constructor (on_list_tools, on_call_tool)
handler context            server.request_context                 ServerRequestContext argument
request ``_meta``          pydantic model (extra fields)          dict
result / init fields       camelCase attributes                   snake_case attributes (camelCase aliases)
transport context manager  (read, write, get_session_id)          (read, write)
read timeout               datetime.timedelta                     float seconds
=========================  =====================================  =======================================

Input validation: the gateway does not validate tool arguments against the declared JSON schema
before the tool runs. The application's own ADK tool object receives the arguments exactly as it
does in one process (ADK passes the model's arguments to the tool; the tool decides), so a tool
behaves the same in-process and distributed.
"""
from __future__ import annotations

from datetime import timedelta
from importlib.metadata import version
from typing import Any, Awaitable, Callable

from mcp import types

MCP_VERSION = version("mcp")
MCP2 = int(MCP_VERSION.split(".")[0]) >= 2

if MCP2:                                                  # pragma: no cover - exercised per installed SDK
    import httpcore2 as httpcore_lib
    import httpx2 as httpx_lib
    from mcp.shared.exceptions import MCPError as McpError
else:                                                     # pragma: no cover
    import httpcore as httpcore_lib
    import httpx as httpx_lib
    from mcp.shared.exceptions import McpError

try:
    AnyIOBackend = httpcore_lib.AnyIOBackend
except AttributeError:                                    # pragma: no cover - httpcore < 1.0
    from httpcore._backends.anyio import AnyIOBackend    # type: ignore[no-redef]

__all__ = ["MCP2", "MCP_VERSION", "AnyIOBackend", "McpError", "build_server", "error_message", "httpcore_lib",
           "httpx_lib", "init_info", "read_timeout", "request_meta", "request_scope", "result_parts",
           "tool_schema", "transport_streams"]

# (context, tool name, arguments) -> result
CallHandler = Callable[[Any, str, dict[str, Any]], Awaitable[types.CallToolResult]]


def build_server(name: str, tools: list[types.Tool], call: CallHandler) -> Any:
    """A low-level MCP server offering ``tools``; tools/call goes to ``call(ctx, name, arguments)``
    without input validation (see the module docstring)."""
    from mcp.server.lowlevel import Server

    if MCP2:
        async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
            return types.ListToolsResult(tools=tools)

        async def on_call_tool(ctx: Any, params: Any) -> types.CallToolResult:
            return await call(ctx, str(params.name), dict(params.arguments or {}))

        return Server(name, version="1.0.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool)

    server = Server(name, version="1.0.0")

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return tools

    @server.call_tool(validate_input=False)
    async def _call_tool(tool: str, arguments: dict[str, Any]) -> types.CallToolResult:
        return await call(server.request_context, tool, dict(arguments or {}))

    return server


def request_scope(ctx: Any) -> dict[str, Any]:
    """The ASGI scope of the HTTP request a tools/call arrived on (``scope["state"]``: what the
    PEP verified for this request)."""
    return ctx.request.scope


def request_meta(ctx: Any) -> dict[str, Any]:
    meta = getattr(ctx, "meta", None)
    if meta is None:
        return {}
    if isinstance(meta, dict):
        return dict(meta)
    return dict(getattr(meta, "model_extra", None) or {})


def result_parts(res: Any) -> tuple[bool, Any, list[Any]]:
    """(is_error, structured content, content) of a CallToolResult."""
    is_error = getattr(res, "is_error", None)
    if is_error is None:
        is_error = getattr(res, "isError", False)
    structured = getattr(res, "structured_content", None) if MCP2 else getattr(res, "structuredContent", None)
    return bool(is_error), structured, list(getattr(res, "content", None) or [])


def init_info(init: Any) -> dict[str, Any]:
    if MCP2:
        return {"protocolVersion": init.protocol_version, "serverInfo": init.server_info.model_dump()}
    return {"protocolVersion": init.protocolVersion, "serverInfo": init.serverInfo.model_dump()}


def read_timeout(seconds: float) -> Any:
    return float(seconds) if MCP2 else timedelta(seconds=seconds)


def transport_streams(opened: Any) -> tuple[Any, Any, Callable[[], str | None] | None]:
    """(read, write, session-id getter or None) of an opened Streamable HTTP client transport."""
    if len(opened) >= 3:
        return opened[0], opened[1], opened[2]
    return opened[0], opened[1], None


def tool_schema(tool: Any) -> dict[str, Any]:
    """The input schema of a listed tool."""
    schema = getattr(tool, "input_schema", None) if MCP2 else getattr(tool, "inputSchema", None)
    return dict(schema or {})


def error_message(exc: Any) -> str:
    err = getattr(exc, "error", None)
    return str(getattr(err, "message", "") or exc)
