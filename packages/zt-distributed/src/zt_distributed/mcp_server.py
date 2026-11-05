"""MCP tool server of the gateway (official SDK, low-level Server + StreamableHTTPSessionManager).

* Tools = the application's tools with an implementation, one MCP tool per agent and tool:
  ``<agent>__<tool>``; description and inputSchema are exactly ADK's function declaration of
  that tool. An agent may only call its own tools (the name's agent part must be the
  authenticated agent).
* tools/call -> Gateway.execute_tool(): the authentication result of THIS HTTP request +
  content rules + PEP/PDP/Permit Lease (+ approvals) + PSL admission + the tool host +
  post-obligations (one code path, no second authorization engine).
* The caller's session state travels in ``_meta`` (signed with the body, RFC 9421 content
  digest); the tool's state delta and actions come back in ``structuredContent``.
* Session mode: stateful (Mcp-Session-Id), JSON responses (no SSE on POST), no standalone GET
  stream (405 after authentication), DELETE terminates.
* Arguments are not validated against the declared schema before the tool runs: the
  application's ADK tool receives them exactly as in one process (zt_distributed.mcp_compat).
* MCP SDK 1.x and 2.x (zt_distributed.mcp_compat).
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from mcp import types
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings

from .mcp_compat import build_server, request_meta, request_scope

META_NS = "org.zt-adk/"
K_REQUEST_ID = META_NS + "request_id"
K_WORKFLOW_RUN_ID = META_NS + "workflow_run_id"
K_TRACE_ID = META_NS + "trace_id"
K_IDEMPOTENCY = META_NS + "idempotency_key"
K_CALL_ID = META_NS + "call_id"
K_ATTEMPT = META_NS + "attempt"
K_STATE = META_NS + "state"
SEP = "__"


def mcp_name(agent: str, tool: str) -> str:
    return f"{agent}{SEP}{tool}"


def split_name(name: str) -> tuple[str, str]:
    agent, sep, tool = name.partition(SEP)
    if not sep:
        raise ValueError(f"not an agent tool name: {name}")
    return agent, tool


def _schema(params: dict[str, Any]) -> dict[str, Any]:
    schema = dict(params or {})
    schema.setdefault("type", "object")
    schema.setdefault("properties", {})
    return schema


class McpToolServer:
    def __init__(self, *, execute_tool: Callable[..., Any], declarations: dict[tuple[str, str], dict[str, Any]],
                 authority: str, server_name: str = "zt-adk-gateway-tools") -> None:
        """``declarations``: (agent, tool) -> {"description": str, "parameters": JSON schema}."""
        self.execute_tool = execute_tool
        self.tool_defs = [
            types.Tool(name=mcp_name(agent, tool), description=(d.get("description") or tool).strip()[:2000],
                       inputSchema=_schema(d.get("parameters") or {}))
            for (agent, tool), d in sorted(declarations.items())
        ]
        self.server = build_server(server_name, self.tool_defs, self._call)
        self.manager = StreamableHTTPSessionManager(
            app=self.server, json_response=True, stateless=False,
            security_settings=TransportSecuritySettings(
                enable_dns_rebinding_protection=True, allowed_hosts=[authority], allowed_origins=[]),
        )

    async def _call(self, ctx: Any, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        state = request_scope(ctx)["state"]               # set by the PEP for THIS HTTP request
        state["t_handler_start_ns"] = time.perf_counter_ns()
        meta = request_meta(ctx)
        session_state = meta.get(K_STATE)
        kind, body = await self.execute_tool(
            ident=state["zt_identity"], mcp_tool=name, args=dict(arguments),
            workflow_run_id=str(meta.get(K_WORKFLOW_RUN_ID, "")),
            idempotency_key=str(meta.get(K_IDEMPOTENCY) or ""),
            request_id=str(meta.get(K_REQUEST_ID, "")), call_id=str(meta.get(K_CALL_ID, "")),
            session_state=session_state if isinstance(session_state, dict) else {},
            spans=state["zt_spans"], rec=state["zt_rec"], psl_attempt=state.get("zt_psl_attempt"))
        state["t_handler_end_ns"] = time.perf_counter_ns()
        state["zt_rec"]["mcp_jsonrpc_id"] = str(ctx.request_id)
        text = json.dumps(body, ensure_ascii=False, default=str)
        # tool-level outcomes (denial, obligation failure, tool exception) are isError results
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)],
                                    structuredContent=json.loads(text), isError=kind != "ok")
