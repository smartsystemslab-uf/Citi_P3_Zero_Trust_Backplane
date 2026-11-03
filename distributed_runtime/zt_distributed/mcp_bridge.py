"""Thin aiohttp -> ASGI bridge for the official MCP SDK Streamable HTTP transport.

Why: TLS (and the verified client certificate) terminates inside the aiohttp PEP
process exactly as in the previous round. The MCP protocol itself (JSON-RPC
parsing, initialize/initialized, sessions, tools/list, tools/call, response
encoding, Mcp-Session-Id / MCP-Protocol-Version handling) is done entirely by
`mcp.server.streamable_http_manager.StreamableHTTPSessionManager` (SDK 1.30.0).

The bridge only:
  * builds an ASGI http scope from the aiohttp request (method, path, headers,
    body), adding `scope["state"]` with the AuthenticatedIdentity that the PEP
    already verified for THIS request (Starlette exposes it as request.state);
  * streams the ASGI response messages back through aiohttp.
It never parses or rewrites MCP messages.
"""
from __future__ import annotations

import asyncio
from typing import Any

from aiohttp import web


class AsgiBridge:
    def __init__(self, asgi_app: Any) -> None:
        self.app = asgi_app

    async def handle(self, request: web.Request, body: bytes, state: dict[str, Any]) -> tuple[web.StreamResponse, dict[str, str]]:
        peer = request.transport.get_extra_info("peername") if request.transport else None
        sock = request.transport.get_extra_info("sockname") if request.transport else None
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": request.method,
            "scheme": "https" if request.secure else "http",
            "path": request.path,
            "raw_path": request.raw_path.split("?", 1)[0].encode("latin-1"),
            "query_string": request.query_string.encode("latin-1"),
            "root_path": "",
            "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in request.headers.items()],
            "client": (peer[0], peer[1]) if peer else None,
            "server": (sock[0], sock[1]) if sock else None,
            "state": state,
        }
        body_sent = False
        disconnected = asyncio.Event()

        async def receive() -> dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            await disconnected.wait()
            return {"type": "http.disconnect"}

        response: web.StreamResponse | None = None
        resp_headers: dict[str, str] = {}

        async def send(message: dict[str, Any]) -> None:
            nonlocal response
            if message["type"] == "http.response.start":
                response = web.StreamResponse(status=message["status"])
                for k, v in message.get("headers", []):
                    key, val = k.decode("latin-1"), v.decode("latin-1")
                    if key.lower() in ("content-length", "transfer-encoding"):
                        continue
                    response.headers.add(key, val)
                    resp_headers[key.lower()] = val
                await response.prepare(request)
            elif message["type"] == "http.response.body":
                assert response is not None
                chunk = message.get("body", b"")
                if chunk:
                    if "zt_capture" in state:
                        state["zt_capture"].append(chunk)
                    await response.write(chunk)
                if not message.get("more_body", False):
                    await response.write_eof()

        try:
            await self.app(scope, receive, send)
        finally:
            disconnected.set()
        if response is None:                        # app produced nothing: internal error
            response = web.Response(status=500, text="no response from MCP transport")
        return response, resp_headers
