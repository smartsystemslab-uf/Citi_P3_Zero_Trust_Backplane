"""Agent workload: hosts exactly one original ADK agent (one container per agent).

* Inbound: POST /v1/invoke, accepted only from the gateway: the mTLS peer must present
  the gateway's SPIFFE ID.
* Outbound: every tool call (MCP tools/call through the official SDK session of THIS
  workload) and every child-agent invocation goes to the gateway PEP with THIS
  workload's credentials -- its X.509-SVID and its own agent certificate, every HTTP
  request signed (RFC 9421 + content digest). Upstream identities are never forwarded as
  the caller identity of a hop.
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
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from zt_identity.agent_identity.client import AgentCredentialManager
from zt_identity.events import EventLog
from zt_identity.identity import AuthenticationError
from zt_identity.workload_identity.spiffe_tls import WorkloadIdentity
from zt_identity.workload_identity.svid import PeerIdentityCache

from . import catalog
from .agent_factory import build_hosted_agent
from .mcp_client import AgentSigningAuth, McpToolSession, SpiffeHTTPTransport, call_meta
from .scripted_model import INVOCATION_STATE
from .transport import ServiceClient, SpanWriter


def _process_age_s() -> float | None:
    """Seconds since this OS process was created (Linux /proc)."""
    try:
        start_ticks = int(open("/proc/self/stat").read().rsplit(")", 1)[1].split()[19])
        uptime = float(open("/proc/uptime").read().split()[0])
        return round(uptime - start_ticks / os.sysconf("SC_CLK_TCK"), 4)
    except (OSError, ValueError, IndexError):
        return None


@dataclass(frozen=True)
class RunInfo:
    workflow_run_id: str
    trace_id: str


RUN: contextvars.ContextVar[RunInfo | None] = contextvars.ContextVar("run_info", default=None)


class AgentService:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.agent_id = args.agent_id
        self.workload = catalog.AGENTS[self.agent_id]
        self.events = EventLog(args.events, component=self.workload.name)
        self.spans = SpanWriter(args.spans)
        self.peer_cache = PeerIdentityCache(catalog.TRUST_DOMAIN)
        self.gateway_id = catalog.SERVICES["zt-gateway"].spiffe_id
        self.identity: WorkloadIdentity | None = None
        self.creds: AgentCredentialManager | None = None
        self.counters: dict[str, int] = {}
        self.started = time.monotonic()
        self.ready_s: float | None = None
        self.mcp: McpToolSession | None = None
        self.mcp_protocol_stats: dict[str, int] = {}
        self.sign_times: dict[str, float] = {}
        self.cold_start: dict[str, Any] = {}
        self.mcp_auth: AgentSigningAuth | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self.identity = WorkloadIdentity(trust_domain=catalog.TRUST_DOMAIN, events=self.events)
        self.identity.bind_loop(loop)
        expected = {catalog.GATEWAY_HOST: self.gateway_id,
                    catalog.ISSUER_HOST: catalog.SERVICES["agent-issuer"].spiffe_id}
        issuer_client = ServiceClient(identity=self.identity, trust_domain=catalog.TRUST_DOMAIN,
                                      expected_servers=expected, conn_mode="reuse")

        async def post_json(url: str, payload: dict) -> tuple[int, dict]:
            status, body, _ = await issuer_client.post(url, payload)
            return status, body

        self.creds = AgentCredentialManager(
            agent_id=self.agent_id, workload_spiffe_id=lambda: self.identity.spiffe_id,
            issuer_url=catalog.issuer_url(), post_json=post_json,
            enrollment_key_path=self.args.enrollment_key, events=self.events,
            renew_fraction=self.args.renew_fraction)
        await self.creds.start()
        self.gateway = ServiceClient(identity=self.identity, trust_domain=catalog.TRUST_DOMAIN,
                                     expected_servers=expected, conn_mode=self.args.conn_mode,
                                     agent_creds=self.creds)
        self.gw_url = catalog.gateway_url()
        mtrans = SpiffeHTTPTransport(identity=self.identity, trust_domain=catalog.TRUST_DOMAIN,
                                     expected_servers=expected, conn_mode=self.args.conn_mode)
        self.mcp_auth = AgentSigningAuth(self.agent_id, self.mcp_protocol_stats, self.creds,
                                         lambda: self.identity.spiffe_id, self.sign_times)
        self.mcp = McpToolSession(url=f"{self.gw_url}/mcp", agent_id=self.agent_id, transport=mtrans,
                                  auth=self.mcp_auth, events=self.events, protocol_stats=self.mcp_protocol_stats)
        t0 = time.monotonic()
        delay = 0.5
        while True:                       # the gateway may still be starting
            try:
                info = await self.mcp.connect("startup")
                break
            except Exception as exc:
                self.events.emit("mcp_connect_retry", error=f"{type(exc).__name__}: {exc}"[:200])
                await asyncio.sleep(delay)
                delay = min(delay * 2, 5.0)
        self.cold_start = {"process_start_to_mcp_ready_s": _process_age_s(),
                           "service_init_to_mcp_ready_s": round(time.monotonic() - self.started, 4),
                           "mcp_connect_wall_s": round(time.monotonic() - t0, 4),
                           "time_to_first_svid_s": self.identity.time_to_first_svid_s,
                           "time_to_first_agent_cred_s": self.creds.time_to_first_credential_s,
                           **info}
        self.agent = build_hosted_agent(self.agent_id, invoke_tool=self._call_tool, invoke_agent=self._call_agent)
        self.sessions = InMemorySessionService()
        self.runner = Runner(app_name="citi_banking_adk", agent=self.agent, session_service=self.sessions)
        self.spans.start()
        self.ready_s = time.monotonic() - self.started

    # ---------------- outbound hops (own credentials) -------------------
    async def _post_gateway(self, path: str, payload: dict[str, Any], kind: str, name: str) -> tuple[int, dict]:
        run = RUN.get()
        assert run is not None, "outbound call outside an invocation"
        payload = {"request_id": str(uuid.uuid4()), "workflow_run_id": run.workflow_run_id,
                   "trace_id": run.trace_id, **payload}
        t0 = time.perf_counter_ns()
        try:
            status, body, info = await self.gateway.post(
                f"{self.gw_url}{path}", payload, headers={"X-ZT-Agent-Id": self.agent_id},
                sign_for=(payload["request_id"], run.workflow_run_id))
        except Exception as exc:
            self.spans.add({"ts": time.time(), "kind": kind, "name": name, "status": -1,
                            "error": type(exc).__name__})
            raise
        self.spans.add({"ts": time.time(), "kind": kind, "name": name, "status": status,
                        "sign_ms": round(info["sign_ms"], 4), "rtt_ms": round(info["rtt_ms"], 4),
                        "total_ms": round((time.perf_counter_ns() - t0) / 1e6, 4),
                        "workflow_run_id": run.workflow_run_id})
        return status, body

    async def _call_tool(self, tool: str, args: dict[str, Any], tool_context: Any) -> Any:
        """MCP tools/call through the official SDK session of THIS agent workload."""
        run = RUN.get()
        assert run is not None and self.mcp is not None
        call_id = getattr(tool_context, "function_call_id", None) or str(uuid.uuid4())
        request_id = str(uuid.uuid4())
        meta = call_meta(request_id=request_id, workflow_run_id=run.workflow_run_id, trace_id=run.trace_id,
                         idempotency_key=f"adk:{run.workflow_run_id}:{self.agent_id}:{call_id}", call_id=call_id)
        t0 = time.perf_counter_ns()
        t_mono = time.monotonic()
        status, err, body = "ok", "", None
        try:
            res = await self.mcp.call(tool, args, meta)
            text = "".join(c.text for c in res.content if getattr(c, "type", "") == "text")
            if res.isError:
                body = res.structuredContent or self._json_or_text(text)
                status = "tool_error_result"
            else:
                body = text
        except Exception as exc:  # transport / JSON-RPC errors (incl. a PEP 401/403, which ends the SDK session)
            status, err = "transport_error", f"{type(exc).__name__}: {exc}"[:200]
            rej = self.mcp_auth.last_reject if self.mcp_auth is not None else None
            if rej is not None and rej["t"] >= t_mono:
                http_status, reason = int(rej["status"]), str(rej["reason"])
                err = f"pep_{http_status}:{reason} ({err})"[:200]
        total = (time.perf_counter_ns() - t0) / 1e6
        self.spans.add({"ts": time.time(), "kind": "mcp_call", "name": tool, "status": status, "error": err,
                        "sign_ms": round(self.sign_times.pop(request_id, 0.0), 4), "rtt_ms": round(total, 4),
                        "total_ms": round(total, 4), "request_id": request_id,
                        "workflow_run_id": run.workflow_run_id})
        if status == "ok":
            return body
        self._count(f"mcp_{status}")
        if status == "tool_error_result" and isinstance(body, dict):
            out = dict(body)
            out.setdefault("status", "zero_trust_denied")
            out.setdefault("tool", tool)
            out.setdefault("agent", self.agent_id)
            return out
        rejected = err.startswith("pep_401") or err.startswith("pep_403")
        if rejected:
            self._maybe_reenroll(int(err[4:7]), {"reason": err[8:].split(" ", 1)[0]})
        return {"status": "zero_trust_denied" if rejected else "tool_error", "tool": tool,
                "agent": self.agent_id, "reason": err or str(body)[:200]}

    @staticmethod
    def _json_or_text(text: str) -> Any:
        try:
            return json.loads(text)
        except ValueError:
            return {"raw": text[:500]}

    async def mcp_reconnect(self, request: web.Request) -> web.Response:
        if self.mcp is None:
            return web.json_response({"status": "not_ready"}, status=503)
        info = await self.mcp.connect(request.query.get("reason", "operator"))
        return web.json_response({"status": "ok", **info})

    async def _call_agent(self, child: str, payload: dict[str, Any]) -> dict[str, Any]:
        status, body = await self._post_gateway(f"/v1/agents/{child}/invoke", payload, "route", child)
        if status == 200 and body.get("status") == "ok":
            return body.get("state_delta") or {}
        self._count(f"route_{status}")
        self._maybe_reenroll(status, body)
        denied = {"status": "zero_trust_denied" if status in (401, 403) else "agent_error",
                  "reason": body.get("reason") or body.get("detail"), "target_agent": child}
        return {"__remote_error__": json.dumps(denied)}

    def _count(self, key: str) -> None:
        self.counters[key] = self.counters.get(key, 0) + 1

    def _maybe_reenroll(self, status: int, body: dict[str, Any]) -> None:
        # the PEP reports our certificate as revoked (admin disable -> enable): re-enroll in
        # the background; this request stays failed
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
        run = RunInfo(str(data["workflow_run_id"]), str(data["trace_id"]))
        state = dict(data.get("state") or {})
        tok_run = RUN.set(run)
        tok_state = INVOCATION_STATE.set(state)
        session = await self.sessions.create_session(app_name="citi_banking_adk", user_id="ztbp", state=state)
        delta: dict[str, Any] = {}
        n_events = 0
        try:
            msg = types.Content(role="user", parts=[types.Part(text=str(data.get("message", "")))])
            async for event in self.runner.run_async(user_id="ztbp", session_id=session.id, new_message=msg):
                n_events += 1
                sd = getattr(getattr(event, "actions", None), "state_delta", None)
                if sd:
                    delta.update(sd)
        except Exception as exc:
            self._count("invoke_error")
            self.events.emit("invoke_error", error=f"{type(exc).__name__}: {exc}"[:300])
            return web.json_response({"status": "agent_error", "error": f"{type(exc).__name__}: {exc}"[:300]},
                                     status=500)
        finally:
            RUN.reset(tok_run)
            INVOCATION_STATE.reset(tok_state)
            await self.sessions.delete_session(app_name="citi_banking_adk", user_id="ztbp", session_id=session.id)
        self._count("invoke_ok")
        self.spans.add({"ts": time.time(), "kind": "invoke", "name": self.agent_id, "status": 200,
                        "total_ms": round((time.perf_counter_ns() - t0) / 1e6, 4), "events": n_events,
                        "workflow_run_id": run.workflow_run_id})
        return web.json_response({"status": "ok", "agent_id": self.agent_id, "state_delta": delta,
                                  "events": n_events})

    async def health(self, request: web.Request) -> web.Response:
        ident = self.identity
        return web.json_response({
            "status": "ok" if self.ready_s is not None else "starting", "agent_id": self.agent_id,
            "ready_s": self.ready_s,
            "time_to_first_svid_s": ident.time_to_first_svid_s if ident else None,
            "svid": {"spiffe_id": ident.spiffe_id, "serial": ident.cert_serial,
                     "not_after": ident.not_after_iso, "generation": ident.generation} if ident else None,
            "agent_credential": self.creds.status() if self.creds else None,
            "counters": self.counters,
            "mcp": self.mcp.status() if self.mcp else None,
            "cold_start": self.cold_start,
        })


async def main_async(args: argparse.Namespace) -> None:
    svc = AgentService(args)
    await svc.start()
    app = web.Application(client_max_size=4 * 1024 * 1024)
    app.router.add_post("/v1/invoke", svc.invoke)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    ssl_ctx = svc.identity.server_context(session_tickets=args.session_tickets == "on")
    await web.TCPSite(runner, "0.0.0.0", catalog.AGENT_PORT, ssl_context=ssl_ctx, backlog=4096).start()
    ops = web.Application()                       # local-only, not exposed on the network
    ops.router.add_get("/health", svc.health)
    ops.router.add_post("/mcp/reconnect", svc.mcp_reconnect)
    ops_runner = web.AppRunner(ops, access_log=None)
    await ops_runner.setup()
    await web.TCPSite(ops_runner, "127.0.0.1", catalog.OPS_PORT).start()
    svc.events.emit("agent_ready", agent_id=svc.agent_id, cold_start=svc.cold_start,
                    ready_s=round(svc.ready_s or 0, 4))
    await asyncio.Event().wait()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-id", default=os.environ.get("AGENT_ID"))
    ap.add_argument("--conn-mode", default=os.environ.get("CONN_MODE", "reuse"))
    ap.add_argument("--session-tickets", default=os.environ.get("TLS_SESSION_TICKETS", "on"))
    ap.add_argument("--enrollment-key", default="/run/secrets/agent-enroll/enroll.key")
    ap.add_argument("--renew-fraction", type=float, default=float(os.environ.get("AGENT_RENEW_FRACTION", "0.5")))
    ap.add_argument("--events", default=os.environ.get("CITI_EVENTS_FILE"))
    ap.add_argument("--spans", default=os.environ.get("CITI_SPANS_FILE"))
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
