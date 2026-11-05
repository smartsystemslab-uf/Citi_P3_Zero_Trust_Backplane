"""Agent workload: hosts exactly one agent of the protected ADK application (one container per agent).

* Inbound: POST /v1/invoke, accepted only from the gateway (the mTLS peer must present the
  gateway's SPIFFE ID). Modes: ``run`` (continue the caller's session with this agent) and
  ``agent_tool`` (fresh session, AgentTool semantics) -- see workload_runtime.
* Outbound: every tool call (MCP tools/call through the official SDK session of THIS workload)
  and every call of another agent (route) goes to the gateway PEP with THIS workload's
  credentials -- its X.509-SVID and its own agent certificate, every HTTP request signed
  (RFC 9421 + content digest). Upstream identities are never forwarded as the caller.
"""
from __future__ import annotations

import argparse
import asyncio
import contextvars
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any

from aiohttp import web

from zt_identity.agent_identity.client import AgentCredentialManager
from zt_identity.events import EventLog
from zt_identity.identity import AuthenticationError
from zt_identity.workload_identity.spiffe_tls import WorkloadIdentity
from zt_identity.workload_identity.svid import PeerIdentityCache

from . import deployment as D
from . import remote
from .appload import load_app
from .mcp_client import AgentSigningAuth, McpToolSession, SpiffeHTTPTransport, call_meta
from .mcp_server import mcp_name
from .transport import ServiceClient, SpanWriter
from .workload_runtime import HostedAgentRunner


@dataclass(frozen=True)
class RunInfo:
    workflow_run_id: str
    trace_id: str


RUN: contextvars.ContextVar[RunInfo | None] = contextvars.ContextVar("run_info", default=None)


class AgentService:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.dep = D.load()
        self.agent_id = args.agent_id
        self.workload = self.dep.agents[self.agent_id]
        self.events = EventLog(args.events, component=self.workload.name)
        self.spans = SpanWriter(args.spans)
        self.peer_cache = PeerIdentityCache(self.dep.trust_domain)
        self.gateway_id = self.dep.gateway.spiffe_id
        self.counters: dict[str, int] = {}
        self.started = time.monotonic()
        self.ready_s: float | None = None
        self.mcp_protocol_stats: dict[str, int] = {}
        self.sign_times: dict[str, float] = {}
        self.identity: WorkloadIdentity | None = None
        self.creds: AgentCredentialManager | None = None
        self.mcp: McpToolSession | None = None
        self.mcp_auth: AgentSigningAuth | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        td = self.dep.trust_domain
        self.identity = WorkloadIdentity(trust_domain=td, events=self.events)
        self.identity.bind_loop(loop)
        expected = {"zt-gateway": self.gateway_id, "agent-issuer": self.dep.issuer.spiffe_id}
        issuer_client = ServiceClient(identity=self.identity, trust_domain=td, expected_servers=expected,
                                      conn_mode="reuse")

        async def post_json(url: str, payload: dict) -> tuple[int, dict]:
            status, body, _ = await issuer_client.post(url, payload)
            return status, body

        self.creds = AgentCredentialManager(
            agent_id=self.agent_id, workload_spiffe_id=lambda: self.identity.spiffe_id,
            issuer_url=self.dep.issuer_url(), post_json=post_json, enrollment_key_path=self.args.enrollment_key,
            events=self.events, renew_fraction=self.args.renew_fraction)
        await self.creds.start()
        self.gateway = ServiceClient(identity=self.identity, trust_domain=td, expected_servers=expected,
                                     conn_mode=self.args.conn_mode, agent_creds=self.creds,
                                     timeout_s=self.args.call_timeout)
        self.gw_url = self.dep.gateway_url()
        mtrans = SpiffeHTTPTransport(identity=self.identity, trust_domain=td, expected_servers=expected,
                                     conn_mode=self.args.conn_mode)
        self.mcp_auth = AgentSigningAuth(self.agent_id, self.mcp_protocol_stats, self.creds,
                                         lambda: self.identity.spiffe_id, self.sign_times)
        self.mcp = McpToolSession(url=f"{self.gw_url}/mcp", agent_id=self.agent_id, transport=mtrans,
                                  auth=self.mcp_auth, events=self.events, protocol_stats=self.mcp_protocol_stats,
                                  read_timeout_s=self.args.call_timeout)
        delay = 0.5
        while True:                       # the gateway may still be starting
            try:
                await self.mcp.connect("startup")
                break
            except Exception as exc:
                self.events.emit("mcp_connect_retry", error=f"{type(exc).__name__}: {exc}"[:200])
                await asyncio.sleep(delay)
                delay = min(delay * 2, 5.0)
        app = load_app()
        if app.model.fingerprint() != self.dep.fingerprint:
            raise RuntimeError("the application in this image differs from the deployment descriptor")
        self.hosted = HostedAgentRunner(agents=app.agents, agent_name=self.agent_id, app_name=app.app_name)
        remote.HOOKS.invoke_agent = self._call_agent
        remote.HOOKS.call_tool = self._call_tool
        self.spans.start()
        self.ready_s = time.monotonic() - self.started

    # ---------------- outbound hops (own credentials) -------------------
    async def _call_agent(self, target: str, payload: dict[str, Any]) -> dict[str, Any]:
        run = RUN.get()
        if run is None:
            return {"status": "agent_error", "reason": "outbound call outside an invocation"}
        body = {"request_id": str(uuid.uuid4()), "workflow_run_id": run.workflow_run_id, "trace_id": run.trace_id,
                **payload}
        t0 = time.perf_counter_ns()
        try:
            status, data, info = await self.gateway.post(
                f"{self.gw_url}/v1/agents/{target}/invoke", body, headers={"X-ZT-Agent-Id": self.agent_id},
                sign_for=(body["request_id"], run.workflow_run_id))
        except Exception as exc:
            self._count("route_transport_error")
            return {"status": "agent_error", "reason": f"{type(exc).__name__}: {exc}"[:300], "target_agent": target}
        self.spans.add({"ts": time.time(), "kind": "route", "name": target, "status": status,
                        "sign_ms": round(info["sign_ms"], 4), "rtt_ms": round(info["rtt_ms"], 4),
                        "total_ms": round((time.perf_counter_ns() - t0) / 1e6, 4)})
        if status == 200 and data.get("status") == "ok":
            return data
        self._count(f"route_{status}")
        self._maybe_reenroll(status, data)
        return {"status": "zero_trust_denied" if status in (401, 403) else "agent_error",
                "reason": data.get("reason") or data.get("detail") or data.get("error"), "target_agent": target,
                **({"rules": data["rules"]} if data.get("rules") else {})}

    async def _call_tool(self, agent: str, tool: str, args: dict[str, Any], call_id: str,
                         state: dict[str, Any]) -> dict[str, Any]:
        run = RUN.get()
        if run is None or self.mcp is None:
            return {"status": "tool_error", "reason": "tool call outside an invocation"}
        call_id = call_id or str(uuid.uuid4())
        request_id = str(uuid.uuid4())
        meta = call_meta(request_id=request_id, workflow_run_id=run.workflow_run_id, trace_id=run.trace_id,
                         idempotency_key=f"adk:{run.workflow_run_id}:{self.agent_id}:{call_id}", call_id=call_id,
                         state=state)
        t0 = time.perf_counter_ns()
        t_mono = time.monotonic()
        try:
            res = await self.mcp.call(mcp_name(self.agent_id, tool), args, meta)
        except Exception as exc:          # transport / JSON-RPC errors (incl. a PEP 401/403 ending the session)
            err = f"{type(exc).__name__}: {exc}"[:200]
            rej = self.mcp_auth.last_reject if self.mcp_auth is not None else None
            if rej is not None and rej["t"] >= t_mono:
                err = f"pep_{int(rej['status'])}:{rej['reason']} ({err})"[:200]
                self._maybe_reenroll(int(rej["status"]), {"reason": rej["reason"]})
            self._count("mcp_transport_error")
            return {"status": "zero_trust_denied" if err.startswith("pep_4") else "tool_error", "tool": tool,
                    "agent": self.agent_id, "reason": err}
        self.spans.add({"ts": time.time(), "kind": "mcp_call", "name": tool, "status": "error" if res.isError else "ok",
                        "sign_ms": round(self.sign_times.pop(request_id, 0.0), 4),
                        "total_ms": round((time.perf_counter_ns() - t0) / 1e6, 4), "request_id": request_id})
        body = res.structuredContent if isinstance(res.structuredContent, dict) else {}
        if not body:
            text = "".join(c.text for c in res.content if getattr(c, "type", "") == "text")
            try:
                body = json.loads(text)
            except ValueError:
                body = {"status": "tool_error", "reason": text[:300]}
        if res.isError:
            self._count("mcp_tool_denied_or_failed")
        return body

    def _count(self, key: str) -> None:
        self.counters[key] = self.counters.get(key, 0) + 1

    def _maybe_reenroll(self, status: int, body: dict[str, Any]) -> None:
        if self.creds is not None and status == 401 and body.get("reason") == "agent_cert_revoked":
            asyncio.get_running_loop().create_task(self.creds.reenroll("pep_reported_agent_cert_revoked"))

    # ---------------- inbound ----------------------------------------------
    async def invoke(self, request: web.Request) -> web.Response:
        t0 = time.perf_counter_ns()
        try:
            peer = self.peer_cache.identity_for(request.transport.get_extra_info("ssl_object"))
        except AuthenticationError as exc:
            return web.json_response({"status": "rejected", "reason": exc.code}, status=401)
        if peer.spiffe_id != self.gateway_id:
            return web.json_response({"status": "rejected", "reason": "caller_not_pep"}, status=403)
        data = await request.json()
        token = RUN.set(RunInfo(str(data["workflow_run_id"]), str(data["trace_id"])))
        try:
            result = await self.hosted.run(data)
        except Exception as exc:
            self._count("invoke_error")
            self.events.emit("invoke_error", error=f"{type(exc).__name__}: {exc}"[:300])
            return web.json_response({"status": "agent_error", "error": f"{type(exc).__name__}: {exc}"[:300]},
                                     status=500)
        finally:
            RUN.reset(token)
        self._count("invoke_ok" if result.get("status") == "ok" else "invoke_not_ok")
        self.spans.add({"ts": time.time(), "kind": "invoke", "name": self.agent_id, "mode": data.get("mode"),
                        "total_ms": round((time.perf_counter_ns() - t0) / 1e6, 4),
                        "workflow_run_id": data.get("workflow_run_id")})
        return web.json_response(result, status=200 if result.get("status") == "ok" else 502, dumps=_dumps)

    async def health(self, request: web.Request) -> web.Response:
        ident = self.identity
        return web.json_response({
            "status": "ok" if self.ready_s is not None else "starting", "agent_id": self.agent_id,
            "ready_s": self.ready_s,
            "svid": {"spiffe_id": ident.spiffe_id, "serial": ident.cert_serial, "not_after": ident.not_after_iso,
                     "generation": ident.generation} if ident else None,
            "agent_credential": self.creds.status() if self.creds else None,
            "counters": self.counters, "mcp": self.mcp.status() if self.mcp else None,
        })


def _dumps(obj: Any) -> str:
    return json.dumps(obj, default=str)


async def main_async(args: argparse.Namespace) -> None:
    svc = AgentService(args)
    await svc.start()
    app = web.Application(client_max_size=32 * 1024 * 1024)
    app.router.add_post("/v1/invoke", svc.invoke)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    ssl_ctx = svc.identity.server_context(session_tickets=args.session_tickets == "on")
    await web.TCPSite(runner, "0.0.0.0", D.AGENT_PORT, ssl_context=ssl_ctx, backlog=4096).start()
    ops = web.Application()                       # local-only, not exposed on the network
    ops.router.add_get("/health", svc.health)
    ops_runner = web.AppRunner(ops, access_log=None)
    await ops_runner.setup()
    await web.TCPSite(ops_runner, "127.0.0.1", D.OPS_PORT).start()
    svc.events.emit("agent_ready", agent_id=svc.agent_id, ready_s=round(svc.ready_s or 0, 4))
    await asyncio.Event().wait()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-id", default=os.environ.get("AGENT_ID"))
    ap.add_argument("--conn-mode", default=os.environ.get("CONN_MODE", "reuse"))
    ap.add_argument("--session-tickets", default=os.environ.get("TLS_SESSION_TICKETS", "on"))
    ap.add_argument("--enrollment-key", default="/run/secrets/agent-enroll/enroll.key")
    ap.add_argument("--renew-fraction", type=float, default=float(os.environ.get("AGENT_RENEW_FRACTION", "0.5")))
    ap.add_argument("--call-timeout", type=float, default=float(os.environ.get("CALL_TIMEOUT_S", "900")),
                    help="seconds an outbound route / tool call may take (covers approval waits)")
    ap.add_argument("--events", default=os.environ.get("ZT_EVENTS_FILE"))
    ap.add_argument("--spans", default=os.environ.get("ZT_SPANS_FILE"))
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
