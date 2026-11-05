"""The gateway's MCP tool server and the agents' MCP client with the installed MCP SDK (1.x or 2.x).

The official SDK client talks to the gateway's real McpToolServer in one process (ASGI): the
session handshake, tools/list, tools/call with the correlation ``_meta``, results with structured
content, and arguments passed to the tool exactly as the model produced them (no schema
validation in front of the tool: the application's ADK tool decides, as in one process).
"""
from __future__ import annotations

import asyncio
from typing import Any

from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client

from zt_distributed.mcp_client import AgentAuth, call_meta
from zt_distributed.mcp_compat import MCP_VERSION, httpx_lib, init_info, read_timeout, result_parts, \
    transport_streams
from zt_distributed.mcp_server import K_STATE, K_WORKFLOW_RUN_ID, McpToolServer, mcp_name

AUTHORITY = "zt-gateway.test"


def _server(calls: list[dict[str, Any]]) -> McpToolServer:
    async def execute_tool(**kw: Any) -> tuple[str, dict[str, Any]]:
        calls.append(kw)
        if kw["args"].get("fail"):
            return "denied", {"status": "zero_trust_denied", "reason": "test"}
        return "ok", {"status": "ok", "echo": kw["args"], "run": kw["workflow_run_id"]}

    return McpToolServer(execute_tool=execute_tool, authority=AUTHORITY, declarations={
        ("signoff_agent", "request_signoff"): {
            "description": "Ask for a sign-off.",
            "parameters": {"type": "object", "properties": {"amount": {"type": "integer"}}, "required": ["amount"]}},
    })


def _asgi(server: McpToolServer) -> Any:
    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        scope["state"] = {"zt_identity": "agent:signoff_agent", "zt_spans": [], "zt_rec": {}}   # set by the PEP
        await server.manager.handle_request(scope, receive, send)
    return app


async def _session_roundtrip() -> tuple[dict[str, Any], list[str], list[Any], list[dict[str, Any]], str | None]:
    calls: list[dict[str, Any]] = []
    server = _server(calls)
    auth = AgentAuth("signoff_agent", {})
    async with server.manager.run():
        http = httpx_lib.AsyncClient(transport=httpx_lib.ASGITransport(app=_asgi(server)), auth=auth,
                                     base_url=f"http://{AUTHORITY}")
        async with streamable_http_client(f"http://{AUTHORITY}/mcp", http_client=http) as opened:
            r, w, _sid = transport_streams(opened)
            async with ClientSession(r, w, read_timeout_seconds=read_timeout(10)) as session:
                info = init_info(await session.initialize())
                listed = [t.name for t in (await session.list_tools()).tools]
                meta = call_meta(request_id="r1", workflow_run_id="wfr-1", trace_id="t1", idempotency_key="k1",
                                 call_id="c1", state={"seat": "aisle"})
                results = [await session.call_tool(mcp_name("signoff_agent", "request_signoff"), args, meta=meta)
                           for args in ({"amount": "300"}, {"amount": 5, "fail": True})]
        await http.aclose()
    return info, listed, results, calls, auth.session_id


def test_mcp_session_with_installed_sdk():
    info, listed, results, calls, session_id = asyncio.run(_session_roundtrip())
    assert info["protocolVersion"] and info["serverInfo"]["name"] == "zt-adk-gateway-tools", MCP_VERSION
    assert listed == ["signoff_agent__request_signoff"]
    assert session_id                                       # the server's Mcp-Session-Id, seen by the client
    ok_err, ok_body, ok_content = result_parts(results[0])
    assert not ok_err and ok_body["status"] == "ok" and ok_body["run"] == "wfr-1"
    assert isinstance(ok_content[0], types.TextContent)
    # the string the model produced for an integer parameter reaches the tool unchanged
    assert calls[0]["args"] == {"amount": "300"}
    assert calls[0]["session_state"] == {"seat": "aisle"}
    denied_err, denied_body, _ = result_parts(results[1])
    assert denied_err and denied_body["status"] == "zero_trust_denied"


def test_meta_keys_travel_in_the_request():
    meta = call_meta(request_id="r", workflow_run_id="w", trace_id="t", idempotency_key="i", call_id="c", state={})
    assert meta[K_WORKFLOW_RUN_ID] == "w" and meta[K_STATE] == {}
