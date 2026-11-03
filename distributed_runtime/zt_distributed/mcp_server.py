"""MCP tool server (official SDK, low-level Server + StreamableHTTPSessionManager).

* Tools = the ORIGINAL bank_adk tool functions (same names, docstrings as
  descriptions, inputSchema derived from the original Python signatures).
* tools/call -> Gateway.execute_tool(): the authentication result of THIS HTTP
  request + gateway PSL checks + PEP/PDP/Permit Lease + PSL admission + original tool
  + post-obligations (one code path, no second authorization engine).
* Session mode: stateful (Mcp-Session-Id), JSON responses (no SSE on POST),
  no standalone GET stream (405 after authentication), DELETE terminates.
* Correlation travels in the tools/call `_meta` (signed as part of the body,
  RFC 9421 content digest): request_id, workflow_run_id, trace_id, idempotency_key, attempt.
  MCP session ids, JSON-RPC ids and agent_id strings are never used as identity.
"""
from __future__ import annotations

import inspect
import json
import time
from typing import Any, Callable

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings

META_NS = "org.citi-p3.ztbp/"
K_REQUEST_ID = META_NS + "request_id"
K_WORKFLOW_RUN_ID = META_NS + "workflow_run_id"
K_TRACE_ID = META_NS + "trace_id"
K_IDEMPOTENCY = META_NS + "idempotency_key"
K_CALL_ID = META_NS + "call_id"
K_ATTEMPT = META_NS + "attempt"

_JSON_TYPES = {str: "string", int: "integer", float: "number", bool: "boolean"}


def input_schema(fn: Callable[..., Any]) -> dict[str, Any]:
    sig = inspect.signature(fn)
    props: dict[str, Any] = {}
    required: list[str] = []
    for name, p in sig.parameters.items():
        ann = p.annotation if p.annotation is not inspect.Parameter.empty else str
        if isinstance(ann, str):                       # postponed annotations
            ann = {"str": str, "int": int, "float": float, "bool": bool}.get(ann, str)
        jt = _JSON_TYPES.get(ann, "string")
        prop: dict[str, Any] = {"type": jt}
        if p.default is not inspect.Parameter.empty:
            prop["default"] = p.default
        else:
            required.append(name)
        props[name] = prop
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


class McpToolServer:
    def __init__(self, *, execute_tool: Callable[..., Any], tool_functions: dict[str, Callable[..., Any]],
                 authority: str) -> None:
        self.execute_tool = execute_tool
        self.tool_defs = [
            types.Tool(name=name, description=(fn.__doc__ or name).strip(), inputSchema=input_schema(fn))
            for name, fn in sorted(tool_functions.items())
        ]
        self.server: Server = Server("citi-p3-zero-trust-backplane-tools", version="1.0.0")

        @self.server.list_tools()
        async def _list_tools() -> list[types.Tool]:
            return self.tool_defs

        @self.server.call_tool(validate_input=True)
        async def _call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
            return await self._call(name, arguments)

        self.manager = StreamableHTTPSessionManager(
            app=self.server,
            json_response=True,
            stateless=False,
            security_settings=TransportSecuritySettings(
                enable_dns_rebinding_protection=True, allowed_hosts=[authority], allowed_origins=[]),
        )

    async def _call(self, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        ctx = self.server.request_context
        state = ctx.request.scope["state"]                # set by the PEP for THIS HTTP request
        state["t_handler_start_ns"] = time.perf_counter_ns()
        meta = dict(getattr(ctx.meta, "model_extra", None) or {}) if ctx.meta is not None else {}
        kind, body = await self.execute_tool(
            ident=state["zt_identity"], tool_name=name, args=dict(arguments),
            workflow_run_id=str(meta.get(K_WORKFLOW_RUN_ID, "")),
            idempotency_key=str(meta.get(K_IDEMPOTENCY) or ""),
            request_id=str(meta.get(K_REQUEST_ID, "")),
            spans=state["zt_spans"], rec=state["zt_rec"], psl_attempt=state.get("zt_psl_attempt"))
        state["t_handler_end_ns"] = time.perf_counter_ns()
        state["zt_rec"]["mcp_jsonrpc_id"] = str(ctx.request_id)
        if kind == "ok":
            result = body["result"]
            text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
            return types.CallToolResult(content=[types.TextContent(type="text", text=text)], isError=False)
        # Tool-level errors (authorization denial, obligation failure, tool exception)
        # are CallToolResult.isError=true, as specified for tool execution errors.
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(body, ensure_ascii=False, default=str))],
            structuredContent=body, isError=True)
