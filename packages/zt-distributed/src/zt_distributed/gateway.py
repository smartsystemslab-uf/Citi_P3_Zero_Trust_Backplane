"""Zero Trust Backplane gateway: the network PEP of the distributed runtime (any ADK application).

Endpoints (TLS with the gateway's X.509-SVID; every caller authenticated with SPIFFE scheme B --
the workload SVID of the mTLS peer and, for agents, the agent certificate bound to it with an
RFC 9421 signature over the request):

  POST /v1/ingress/run            the trusted front end (ingress service): one user message of a
                                  conversation -> input rules + PDP input, entry route (ADK's
                                  resume rule), the entry agent's workload, then every
                                  user-visible text through the output rules + PDP output
  POST /v1/agents/{t}/invoke      an agent workload starts agent t (LLM transfer, workflow step,
                                  AgentTool) -> agent_message rules, PDP route + workflow monitor
  POST|GET|DELETE /mcp            MCP Streamable HTTP: tools/call -> tool_call rules, PDP tool
                                  placement (Permit Lease, approvals), PSL admission, the tool
                                  host, post-obligations, tool_result rules

Every policy -- PDP rules, content rules, temporal monitors -- comes from the one signed PSL
store of the protection bundle the gateway's engine verified at start-up.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from aiohttp import web
from cryptography import x509
from google.adk.events import Event
from google.genai import types

from zt_adk import model as M
from zt_adk.content import text_of
from zt_adk.engine import RunContext
from zt_identity.agent_identity.verifier import AgentCredentialAuthenticator, RegistrySnapshotCache
from zt_identity.events import EventLog
from zt_identity.identity import AuthenticatedIdentity, AuthenticationError
from zt_identity.workload_identity.service_map import IdentityMap
from zt_identity.workload_identity.spiffe_tls import WorkloadIdentity
from zt_identity.workload_identity.svid import PeerIdentityCache

from . import deployment as D
from .appload import load_app
from .gateway_engine import GatewayEngine, bound_identity
from .mcp_bridge import AsgiBridge
from .mcp_server import K_REQUEST_ID, K_WORKFLOW_RUN_ID, META_NS, McpToolServer, split_name
from .psl_guard import PslGuard, PslStartDenied, TicketError
from .remote import dump_event
from .transport import ServiceClient, SpanWriter
from .workload_runtime import HOSTED_TOOL_KINDS, ConversationStore, ToolHost

INGRESS = D.INGRESS_AGENT_ID
TOOL_KINDS = HOSTED_TOOL_KINDS
# what a route forwards to the target workload ("node": a graph workflow's node with its input,
# node path, isolation scope and branch)
ROUTE_PAYLOAD_KEYS = ("mode", "history", "state", "user_content", "request", "node_input", "node_path",
                      "isolation_scope", "branch")


class _ReqView:
    __slots__ = ("method", "path_qs", "headers", "body")

    def __init__(self, request: web.Request, body: bytes) -> None:
        self.method = request.method
        self.path_qs = request.path_qs
        self.headers = request.headers
        self.body = body


def _auth_rec(ident: AuthenticatedIdentity) -> dict[str, Any]:
    return {"mode": ident.auth_mode, "kind": ident.subject_kind, "workload": ident.workload_spiffe_id,
            "agent": ident.agent_id, "cred": ident.agent_credential_id, "idv": ident.identity_version}


def _deny(boundary: str, reason: str, status: int = 403, **extra: Any) -> web.Response:
    return web.json_response({"status": "zero_trust_denied", "boundary": boundary, "reason": reason, **extra},
                             status=status)


def _texts(raw_event: dict[str, Any]) -> list[int]:
    parts = ((raw_event.get("content") or {}).get("parts") or [])
    return [i for i, p in enumerate(parts) if p.get("text") and not p.get("thought")]


class Gateway:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.dep = D.load()
        self.events = EventLog(args.events, component="zt-gateway")
        self.spans = SpanWriter(args.spans)
        t0 = time.monotonic()
        self.app = load_app(resolve_toolsets=True, apply_model_override=False)
        self.engine = GatewayEngine(bundle_dir=args.bundle, keys_dir=args.keys, state_dir=args.state,
                                    approvals_dir=args.approvals)
        if not (self.engine.index["fingerprint"] == self.dep.fingerprint == self.app.model.fingerprint()):
            raise RuntimeError("bundle, deployment descriptor and application in the image disagree")
        self.bootstrap_s = time.monotonic() - t0
        self.policy_version = self.engine.policy_version
        self.psl = PslGuard(policy_set=self.engine.policy_set, engine=self.engine, events=self.events,
                            spans=self.spans, audit_path=Path(args.state) / "psl_audit.jsonl")
        self.tool_host = ToolHost(agents=self.app.agents, tools=self.app.tools, app_name=self.app.app_name)
        declarations = {(t.agent, t.name): {"description": t.description, "parameters": t.parameters}
                        for t in self.engine.model.tools.values() if t.kind in TOOL_KINDS}
        self.mcp_server = McpToolServer(execute_tool=self.execute_tool, declarations=declarations,
                                        authority=self.dep.gateway_authority())
        self.mcp_bridge = AsgiBridge(self.mcp_server.manager.handle_request)
        self.conversations = ConversationStore(agents=self.app.agents, root=self.dep.root_agent)
        self.runs: dict[str, RunContext] = {}
        self.counters: dict[str, int] = {}
        self.peer_serials: dict[str, dict[str, Any]] = {}
        self.mcp_sessions: dict[str, tuple] = {}
        self.mcp_messages: dict[str, int] = {}
        self.tool_executions = 0
        self.identity: WorkloadIdentity | None = None
        self.peer_cache = PeerIdentityCache(self.dep.trust_domain)
        self.registry: RegistrySnapshotCache | None = None
        self.events.emit("gateway_policies_loaded", policy_version=self.policy_version,
                         logical_peps=len(self.engine.plan.get("logical_peps", [])))

    # ------------------------------------------------------------------ start
    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        td = self.dep.trust_domain
        self.identity_map = IdentityMap(self.args.identity_map, events=self.events,
                                        on_change=self.engine.on_identity_change)
        self.identity = WorkloadIdentity(trust_domain=td, events=self.events)
        self.identity.bind_loop(loop)
        expected = {w.name: w.spiffe_id for w in self.dep.agents.values()}
        expected["agent-issuer"] = self.dep.issuer.spiffe_id
        self.downstream = ServiceClient(identity=self.identity, trust_domain=td, expected_servers=expected,
                                        conn_mode=self.args.conn_mode, timeout_s=self.args.downstream_timeout)
        ca = x509.load_pem_x509_certificate(Path(self.args.agent_ca).read_bytes())

        async def fetch() -> dict[str, Any]:
            status, body = await self.downstream.get_json(f"{self.dep.issuer_url()}/v1/registry/snapshot")
            if status != 200:
                raise RuntimeError(f"snapshot status {status}: {body}")
            return body

        self.registry = RegistrySnapshotCache(fetch, interval_s=self.args.registry_interval,
                                              max_staleness_s=self.args.registry_max_staleness, events=self.events,
                                              on_identity_change=self.engine.on_identity_change)
        while True:
            try:
                await self.registry.refresh_once()
                break
            except Exception as exc:
                self.events.emit("registry_wait", error=str(exc)[:200])
                await asyncio.sleep(1.0)
        loop.create_task(self.registry.run())
        self.authenticator = AgentCredentialAuthenticator(ca_cert=ca, registry=self.registry,
                                                          service_map=self.identity_map,
                                                          authority=self.dep.gateway_authority())
        self.spans.start()

    # ------------------------------------------------------------------ helpers
    def _count(self, key: str) -> None:
        self.counters[key] = self.counters.get(key, 0) + 1

    def _transport_of(self, request: web.Request) -> Any:
        ssl_obj = request.transport.get_extra_info("ssl_object") if request.transport else None
        transport = self.peer_cache.identity_for(ssl_obj)
        r = self.peer_serials.setdefault(transport.cert_serial, {"spiffe_id": transport.spiffe_id,
                                                                 "first_seen": time.time(), "requests": 0})
        r["requests"] += 1
        r["last_seen"] = time.time()
        return transport

    def _authenticate(self, request: web.Request, body: bytes, body_json: dict[str, Any]) -> AuthenticatedIdentity:
        return self.authenticator.authenticate(_ReqView(request, body), self._transport_of(request),
                                               body_json=body_json)

    async def _read(self, request: web.Request) -> tuple[bytes, dict[str, Any]]:
        body = await request.read()
        try:
            data = json.loads(body) if body else {}
        except ValueError as exc:
            raise web.HTTPBadRequest(text="invalid json") from exc
        if not isinstance(data, dict):
            raise web.HTTPBadRequest(text="json object required")
        return body, data

    def _span(self, rec: dict[str, Any], spans: dict[str, float], t0: int) -> None:
        rec.update({k: round(v, 4) for k, v in spans.items()})
        rec["total_ms"] = round((time.perf_counter_ns() - t0) / 1e6, 4)
        rec["ts"] = time.time()
        self.spans.add(rec)

    async def _invoke_workload(self, target: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        status, data, _ = await self.downstream.post(f"{self.dep.agent_url(target)}/v1/invoke", payload)
        return status, data

    def _agent_identity_version(self, agent: str) -> str | None:
        try:
            rec = (self.registry.current().get("agents") or {}).get(agent) if self.registry else None
        except AuthenticationError:
            return "registry-unavailable"          # matches no lease: fails closed
        return str(rec["identity_version"]) if rec else None

    def _target_disabled(self, agent: str) -> str | None:
        """Reason not to dispatch work to ``agent``: disabled in the agent registry, or the
        registry snapshot is unavailable / stale (fail closed). None when the agent may run."""
        try:
            rec = (self.registry.current().get("agents") or {}).get(agent) if self.registry else None
        except AuthenticationError as exc:
            reason: str | None = exc.code
        else:
            reason = "target_agent_not_registered" if rec is None else (
                None if rec.get("enabled") else "target_agent_disabled")
        if reason:
            self.engine.audit.write("DISPATCH_REFUSED", target=agent, reason=reason, allowed=False, durable=True)
        return reason

    def _user_role(self, ident: AuthenticatedIdentity, asserted: str) -> str:
        """The asserted end-user role counts only if the controlled service map lists it for this
        authenticated ingress service; otherwise it is unknown ('')."""
        entry = self.identity_map.lookup(ident.workload_spiffe_id or "")
        return asserted if entry is not None and entry.enabled and asserted in entry.user_roles else ""

    # ------------------------------------------------------------------ ingress
    async def ingress(self, request: web.Request) -> web.Response:
        t0 = time.perf_counter_ns()
        spans: dict[str, float] = {}
        rec: dict[str, Any] = {"ep": "ingress"}
        body, data = await self._read(request)
        try:
            ident = self._authenticate(request, body, data)
        except AuthenticationError as exc:
            self._count("authn_fail:" + exc.code)
            rec.update(status=401, error=exc.code)
            self._span(rec, spans, t0)
            return _deny("authentication", exc.code, 401)
        rec["auth"] = _auth_rec(ident)
        if ident.subject_kind != "service" or ident.agent_id != INGRESS:
            self._span({**rec, "status": 403}, spans, t0)
            return _deny("ingress", "caller_not_ingress_service")
        session = data.get("session") if isinstance(data.get("session"), dict) else {}
        session_id = str(session.get("session_id") or "")[:128]
        user_role = self._user_role(ident, str(session.get("user_role") or ""))
        conv = self.conversations.get(session_id or f"anon-{uuid.uuid4()}")
        function_response = data.get("function_response")
        if function_response is not None:
            parts = [types.Part(function_response=types.FunctionResponse(**function_response))]
            kind, text = "function_response", text_of(function_response.get("response"))
        else:
            text = str(data.get("message", ""))
            parts, kind = [types.Part(text=text)], "text"
        entry = self.conversations.entry_agent(conv)
        if function_response is not None:
            entry = self._function_call_owner(conv, str(function_response.get("id") or "")) or entry
        wfr = f"wfr-{uuid.uuid4()}"
        run = RunContext(invocation_id=wfr, workflow_instance_id=wfr, trace_id=f"trace-{uuid.uuid4()}",
                         session_id=conv.session_id, user_role=user_role, session_present=bool(session_id))
        rec.update(entry=entry, workflow_run_id=wfr, user_role=user_role or None, request_id=data.get("request_id"))
        with bound_identity(ident, spans, user_session=bool(session_id)):
            verdict = self.engine.check_input(run, text, kind=kind, entry_agent=entry)
            if verdict.allowed:
                verdict = self.engine.authorize(
                    run, self.engine.input_placement,
                    parameters={"message_sha256": hashlib.sha256(text.encode()).hexdigest(),
                                "message_length": len(text), "kind": kind},
                    event="INPUT_AUTHORIZATION", caller=INGRESS, target=entry)
            if verdict.allowed:
                verdict = self.engine.authorize(run, self.engine.route_placement(INGRESS, entry),
                                                parameters={"target_agent": entry},
                                                event="AGENT_ROUTE_AUTHORIZATION", caller=INGRESS, target=entry)
                self.engine.admit_route(run, INGRESS, entry, verdict)
        disabled = self._target_disabled(entry) if verdict.allowed else None
        if disabled:
            verdict.allowed, verdict.reason = False, disabled
        if not verdict.allowed:
            self._count("deny:input")
            rec.update(status=403, error=verdict.reason)
            self._span(rec, spans, t0)
            self.engine.close_run(run)
            return _deny("input", verdict.reason, trace_id=run.trace_id, rules=verdict.rules)
        user_event = Event(author="user", invocation_id=wfr, content=types.Content(role="user", parts=parts))
        self.runs[wfr] = run
        self.psl.dispatched(wfr, entry)
        td = time.perf_counter_ns()
        try:
            status, result = await self._invoke_workload(entry, {
                "request_id": str(uuid.uuid4()), "workflow_run_id": wfr, "trace_id": run.trace_id, "mode": "run",
                "history": conv.events + [dump_event(user_event)], "state": dict(conv.state),
                "user_content": user_event.content.model_dump(mode="json", exclude_none=True)})
        finally:
            self.runs.pop(wfr, None)
            self.psl.dispatch_ended(wfr, entry)
            self.psl.run_closed(wfr)
            closed = self.engine.close_run(run)
            if closed:
                rec["workflow_close_violations"] = closed
        spans["downstream_ms"] = (time.perf_counter_ns() - td) / 1e6
        if status != 200 or result.get("status") != "ok":
            self._count("entry_agent_error")
            rec.update(status=502, error=f"entry_agent_status_{status}")
            self._span(rec, spans, t0)
            return web.json_response({"status": "entry_agent_error", "agent_status": status,
                                      "detail": {k: v for k, v in result.items() if k != "events"},
                                      "workflow_run_id": wfr}, status=502)
        events = list(result.get("events") or [])
        withheld: list[dict[str, Any]] = []
        authorized: dict[str, bool] = {}
        for raw in events:
            author = str(raw.get("author") or "")
            idx = _texts(raw)
            if not idx or author in ("", "user"):
                continue
            parts = raw["content"]["parts"]
            text = "".join(parts[i]["text"] for i in idx)
            v = self.engine.check_output(run, author, text)
            if v.allowed and not authorized.get(author):
                # the decision is about the authoring agent: bound to ITS current identity version
                with bound_identity(ident, spans, user_session=bool(session_id),
                                    subject_identity_version=self._agent_identity_version(author)):
                    pv = self.engine.authorize(
                        run, self.engine.output_placement(author),
                        parameters={"output_sha256": hashlib.sha256(text.encode()).hexdigest(),
                                    "output_length": len(text)},
                        event="OUTPUT_AUTHORIZATION", caller=author, target="mas_output_channel")
                authorized[author] = pv.allowed
                if not pv.allowed:
                    v = pv
            if not v.allowed:
                note = json.dumps({"status": "zero_trust_denied", "boundary": "output", "reason": v.reason[:300],
                                   "rules": v.rules, "agent": author}, ensure_ascii=False)
                raw["content"]["parts"] = [p for i, p in enumerate(parts) if i not in idx] + [{"text": note}]
                withheld.append({"agent": author, "rules": v.rules})
        self.conversations.append(conv, [dump_event(user_event)] + events)
        final = ""
        for raw in reversed(events):
            idx = _texts(raw)
            if idx and raw.get("author") not in ("", "user"):
                final = "".join(raw["content"]["parts"][i]["text"] for i in idx)
                break
        self._count("ingress_ok")
        rec.update(status=200, withheld=len(withheld))
        self._span(rec, spans, t0)
        return web.json_response({"status": "ok", "workflow_run_id": wfr, "trace_id": run.trace_id,
                                  "session_id": conv.session_id, "entry_agent": entry, "final_text": final,
                                  "events": events, "withheld": withheld, "tainted": run.tainted,
                                  "gateway_timing_ms": {k: round(v, 4) for k, v in spans.items()}})

    @staticmethod
    def _function_call_owner(conv: Any, call_id: str) -> str | None:
        for raw in reversed(conv.events):
            for part in ((raw.get("content") or {}).get("parts") or []):
                fc = part.get("function_call")
                if fc and fc.get("id") == call_id:
                    return str(raw.get("author") or "") or None
        return None

    # ------------------------------------------------------------------ agent routes
    async def route(self, request: web.Request) -> web.Response:
        t0 = time.perf_counter_ns()
        spans: dict[str, float] = {}
        target = request.match_info["target"]
        rec: dict[str, Any] = {"ep": "route", "target": target}
        body, data = await self._read(request)
        try:
            ident = self._authenticate(request, body, data)
        except AuthenticationError as exc:
            self._count("authn_fail:" + exc.code)
            self._span({**rec, "status": 401, "error": exc.code}, spans, t0)
            return _deny("authentication", exc.code, 401)
        rec["auth"] = _auth_rec(ident)
        run = self.runs.get(str(data.get("workflow_run_id", "")))
        if run is None or ident.subject_kind != "agent" or target not in self.dep.agents:
            self._span({**rec, "status": 403}, spans, t0)
            return _deny("agent_route", "unknown_workflow_run_target_or_not_agent")
        caller = ident.agent_id
        mode = str(data.get("mode") or "")
        rec.update(agent=caller, mode=mode, workflow_run_id=run.workflow_instance_id)
        with bound_identity(ident, spans, user_session=run.session_present):
            verdict = None
            if mode == "agent_tool":
                verdict = self.engine.check_agent_message(run, caller, target, str(data.get("request") or ""))
            if verdict is None or verdict.allowed:
                verdict = self.engine.authorize(run, self.engine.route_placement(caller, target),
                                                parameters={"target_agent": target, "mode": mode},
                                                event="AGENT_ROUTE_AUTHORIZATION", caller=caller, target=target)
                self.engine.admit_route(run, caller, target, verdict)
        disabled = self._target_disabled(target) if verdict.allowed else None
        if disabled:
            verdict.allowed, verdict.reason = False, disabled
        if not verdict.allowed:
            self._count("deny:route")
            self._span({**rec, "status": 403, "error": verdict.reason}, spans, t0)
            return _deny("agent_route", verdict.reason, caller=caller, target=target, rules=verdict.rules)
        payload = {k: v for k, v in data.items() if k in ROUTE_PAYLOAD_KEYS}
        payload.update(request_id=str(uuid.uuid4()), workflow_run_id=run.workflow_instance_id, trace_id=run.trace_id)
        self.psl.dispatched(run.workflow_instance_id, target)
        td = time.perf_counter_ns()
        try:
            status, result = await self._invoke_workload(target, payload)
        finally:
            self.psl.dispatch_ended(run.workflow_instance_id, target)
        spans["downstream_ms"] = (time.perf_counter_ns() - td) / 1e6
        if status == 200 and mode == "agent_tool" and result.get("status") == "ok":
            check = self.engine.check_tool_result(run, caller, target, str(result.get("result_text") or ""))
            if not check.allowed:
                self._span({**rec, "status": 403, "error": check.reason}, spans, t0)
                return _deny("tool_result", check.reason, caller=caller, target=target, rules=check.rules)
        self._count(f"route_{status}")
        self._span({**rec, "status": status}, spans, t0)
        return web.json_response(result, status=200 if status == 200 else 502)

    # ------------------------------------------------------------------ tools (MCP tools/call)
    async def execute_tool(self, *, ident: AuthenticatedIdentity, mcp_tool: str, args: dict[str, Any],
                           workflow_run_id: str, idempotency_key: str, request_id: str, call_id: str,
                           session_state: dict[str, Any], spans: dict[str, float], rec: dict[str, Any],
                           psl_attempt: Any = None) -> tuple[str, dict[str, Any]]:
        att = psl_attempt
        if att is None:
            raise RuntimeError("fail-closed: tool path reached without a PSL request attempt")
        try:
            return await self._execute_tool(ident, mcp_tool, args, workflow_run_id, request_id, call_id,
                                            session_state, spans, rec, att)
        finally:
            close_v = self.psl.finish(att)
            rec.update(psl_attempt=att.attempt_id, psl_outcome=att.outcome, psl_layer=att.layer,
                       psl_violations=[v["property_id"] for v in att.violations] or None,
                       psl_close_violations=[v["property_id"] for v in close_v] or None)

    async def _execute_tool(self, ident: AuthenticatedIdentity, mcp_tool: str, args: dict[str, Any],
                            workflow_run_id: str, request_id: str, call_id: str, session_state: dict[str, Any],
                            spans: dict[str, float], rec: dict[str, Any], att: Any) -> tuple[str, dict[str, Any]]:
        psl = self.psl
        run = self.runs.get(workflow_run_id)
        try:
            agent, tool = split_name(mcp_tool)
        except ValueError:
            agent, tool = "", mcp_tool
        if run is None or ident.subject_kind != "agent" or agent != ident.agent_id:
            reason = "unknown_workflow_run_or_not_agent" if run is None or ident.subject_kind != "agent" \
                else "tool_of_another_agent"
            psl.reject(att, "run_rejected", layer="run_check", reason=reason, terminal_for_operation=False)
            return "denied", {"status": "zero_trust_denied", "boundary": "tool", "reason": reason}
        rec.update(agent=agent, tool=tool, workflow_run_id=workflow_run_id, request_id=request_id)
        with bound_identity(ident, spans, user_session=run.session_present) as actx:
            pending = await self.engine.begin_tool(run, agent=agent, tool=tool, args=dict(args), call_id=call_id)
        v = pending.verdict
        rec.update(decision=v.decision, source=v.source)
        cls = psl.authorization_result(att, pending, actx.flags)
        if not v.allowed or not pending.reserved:
            self._count("deny:tool")
            layer = {"CONTENT_POLICY": "content_policy", "APPROVAL": "approval", "OBLIGATION": "obligation",
                     "PSL_WORKFLOW_MONITOR": "workflow_monitor"}.get(v.source, "pdp")
            psl.reject(att, cls if cls != "allowed" else "authorization_denied", layer=layer, reason=v.reason,
                       terminal_for_operation=cls in ("authorization_denied", "permit_rejected"))
            self.engine.abort_tool(pending, v.reason) if pending.reserved else None
            status = "pending_approval" if v.decision == "MANUAL_REVIEW" and v.approval_id else "zero_trust_denied"
            return "denied", {"status": status, "boundary": "tool", "reason": v.reason, "rules": v.rules,
                              "approval_id": v.approval_id, "tool": tool, "agent": agent}
        if cls != "allowed":
            self.engine.abort_tool(pending, "no_verified_permit")
            psl.reject(att, "permit_rejected", layer="permit", reason="no_verified_permit", terminal_for_operation=True)
            return "denied", psl.denial_body(att, "no_verified_permit", tool=tool, agent=agent)
        psl.execution_requested(att)
        ok, reason = psl.admit(att, pending, ident, args)
        if not ok:
            self.engine.abort_tool(pending, reason)
            self._count("deny:psl")
            return "denied", psl.denial_body(att, reason, tool=tool, agent=agent)
        ticket = psl.issue_ticket(att)
        try:
            await asyncio.to_thread(psl.redeem, ticket, mcp_tool, args)   # pre-execution audit + execution_started
        except (PslStartDenied, TicketError) as exc:
            self.engine.abort_tool(pending, str(exc))
            psl.start_denied(att, str(exc))
            self._count("deny:psl")
            return "denied", psl.denial_body(att, str(exc) or "PSL_VIOLATION", tool=tool, agent=agent)
        tb = time.perf_counter_ns()
        try:
            out = await self.tool_host.execute(agent=agent, name=tool, args=args, call_id=call_id,
                                               state=session_state, invocation_id=workflow_run_id)
        except Exception as exc:
            out = {"status": "tool_error", "error": f"{type(exc).__name__}: {exc}"[:300]}
        spans["business_wall_ms"] = (time.perf_counter_ns() - tb) / 1e6
        psl.flush_deferred(att)
        if out.get("status") != "ok":
            self.engine.abort_tool(pending, str(out.get("error")))
            psl.execution_finished(att, False, None)
            self._count("tool_error")
            return "error", {"status": "tool_error", "error": out.get("error"), "tool": tool, "agent": agent}
        psl.execution_finished(att, True, out.get("result"))
        protected, check = self.engine.finish_tool(pending, out.get("result"))
        self.tool_executions += 1
        if check is not None and not check.allowed:
            self._count("deny:tool_result")
            return "denied", {"status": "zero_trust_denied", "boundary": "tool_result", "reason": check.reason,
                              "rules": check.rules, "tool": tool, "agent": agent}
        self._count("tool_ok")
        return "ok", {"status": "ok", "result": protected, "state_delta": out.get("state_delta") or {},
                      "actions": out.get("actions") or {}, "permit_id": v.permit_id, "decision": v.decision}

    # ------------------------------------------------------------------ MCP endpoint
    def _authenticate_mcp(self, request: web.Request, body: bytes, rpc: Any) -> tuple[AuthenticatedIdentity, Any]:
        transport = self._transport_of(request)
        is_call = isinstance(rpc, dict) and rpc.get("method") == "tools/call"
        meta = ((rpc.get("params") or {}).get("_meta") or {}) if is_call else {}
        ident = self.authenticator.authenticate_mcp(
            _ReqView(request, body), transport, is_tools_call=is_call,
            meta_request_id=meta.get(K_REQUEST_ID), meta_workflow_run_id=meta.get(K_WORKFLOW_RUN_ID))
        return ident, transport

    async def mcp_endpoint(self, request: web.Request) -> web.StreamResponse:
        t0 = time.perf_counter_ns()
        spans: dict[str, float] = {}
        body = await request.read()
        rpc: Any = None
        if body:
            try:
                rpc = json.loads(body)
            except ValueError:
                rpc = None
        method = rpc.get("method") if isinstance(rpc, dict) else None
        kind = method or ("jsonrpc-response" if isinstance(rpc, dict) else request.method)
        rec: dict[str, Any] = {"ep": "mcp", "http_method": request.method, "rpc_method": method}
        att = None
        if method == "tools/call":
            params = rpc.get("params") or {}
            meta = dict(params.get("_meta") or {})
            meta.pop(META_NS + "state", None)          # correlation only (never a trust input)
            att = self.psl.request_received(jsonrpc_id=rpc.get("id"), session=request.headers.get("mcp-session-id"),
                                            tool=str(params.get("name")), args=params.get("arguments") or {},
                                            meta=meta, meta_ns=META_NS)
            rec["psl_attempt"] = att.attempt_id
        try:
            ident, transport = self._authenticate_mcp(request, body, rpc)
        except AuthenticationError as exc:
            self._count("mcp_authn_fail:" + exc.code)
            if att is not None:
                self.psl.reject(att, "identity_rejected", layer="authentication", reason=exc.code,
                                terminal_for_operation=False)
                self.psl.finish(att)
            self._span({**rec, "status": 401, "error": exc.code}, spans, t0)
            return _deny("authentication", exc.code, 401)
        if att is not None:
            self.psl.identity_verified(att, ident, transport)
        if ident.subject_kind != "agent":
            if att is not None:
                self.psl.reject(att, "request_denied", layer="authentication", reason="mcp_caller_not_agent",
                                terminal_for_operation=False)
                self.psl.finish(att)
            return _deny("mcp", "mcp_caller_not_agent", 403)
        principal = (ident.auth_mode, ident.agent_id, ident.workload_spiffe_id)
        sid = request.headers.get("mcp-session-id")
        if sid:
            bound = self.mcp_sessions.get(sid)
            if bound is not None and bound != principal:
                self._count("mcp_session_principal_mismatch")
                if att is not None:
                    self.psl.reject(att, "request_denied", layer="session_binding",
                                    reason="mcp_session_bound_to_other_principal", terminal_for_operation=False)
                    self.psl.finish(att)
                return _deny("mcp", "mcp_session_bound_to_other_principal", 403)
        self.mcp_messages[kind] = self.mcp_messages.get(kind, 0) + 1
        if request.method == "GET":
            return web.Response(status=405, headers={"Allow": "POST, DELETE"})
        state: dict[str, Any] = {"zt_identity": ident, "zt_spans": spans, "zt_rec": rec, "zt_psl_attempt": att}
        resp, resp_headers = await self.mcp_bridge.handle(request, body, state)
        if att is not None and not att.closed:
            # the SDK answered without reaching the tool handler (unknown tool, schema validation,
            # protocol error): a denial by the MCP layer, never an execution
            self.psl.reject(att, "request_denied", layer="mcp_sdk", reason=f"http_{resp.status}_before_handler",
                            terminal_for_operation=False)
            self.psl.finish(att)
        new_sid = resp_headers.get("mcp-session-id")
        if method == "initialize" and new_sid and resp.status == 200:
            self.mcp_sessions[new_sid] = principal
        if request.method == "DELETE" and sid:
            self.mcp_sessions.pop(sid, None)
        rec.setdefault("status", resp.status)
        self._span(rec, spans, t0)
        return resp

    # ------------------------------------------------------------------ ops
    async def health(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "ok", "auth_scheme": "spiffe-b", "app": self.dep.app_name,
            "bootstrap_s": round(self.bootstrap_s, 3),
            "spiffe_id": self.identity.spiffe_id if self.identity else None,
            "policy_version": self.policy_version, "fingerprint": self.dep.fingerprint,
            "logical_peps": len(self.engine.plan.get("logical_peps", [])),
            "psl_monitors": sorted({m.pid for ms in self.psl.runtime.machines.values() for m in ms}),
        })

    async def stats(self, request: web.Request) -> web.Response:
        self.spans.flush()
        out: dict[str, Any] = {
            "counters": self.counters, "peer_serials": self.peer_serials,
            "identity_changes": self.engine.identity_changes,
            "revocation_epoch": self.engine.components.revocations.epoch, "tool_executions": self.tool_executions,
            "mcp_messages": self.mcp_messages, "mcp_sessions_bound": len(self.mcp_sessions),
            "psl": self.psl.snapshot(), "workflow_monitor": self.engine.monitor.snapshot(),
            "conversations": len(self.conversations._items),
        }
        if self.registry is not None:
            out["registry"] = {"refreshes": self.registry.refreshes, "failures": self.registry.refresh_failures,
                               "version": (self.registry.snapshot or {}).get("registry_version")}
        if self.identity is not None:
            out["svid"] = {"serial": self.identity.cert_serial, "not_after": self.identity.not_after_iso,
                           "generation": self.identity.generation}
        return web.json_response(out)


async def main_async(args: argparse.Namespace) -> None:
    gw = Gateway(args)
    await gw.start()
    app = web.Application(client_max_size=32 * 1024 * 1024)
    app.router.add_post("/v1/ingress/run", gw.ingress)
    app.router.add_post("/v1/agents/{target}/invoke", gw.route)
    for m in ("POST", "GET", "DELETE"):
        app.router.add_route(m, "/mcp", gw.mcp_endpoint)
    mcp_ready = asyncio.Event()

    async def run_mcp_manager() -> None:
        async with gw.mcp_server.manager.run():
            mcp_ready.set()
            await asyncio.Event().wait()

    gw.mcp_task = asyncio.create_task(run_mcp_manager())
    await mcp_ready.wait()
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    ssl_ctx = gw.identity.server_context(session_tickets=args.session_tickets == "on")
    await web.TCPSite(runner, "0.0.0.0", D.GATEWAY_PORT, ssl_context=ssl_ctx, backlog=4096).start()
    ops = web.Application()                       # local-only health/stats, not exposed on the network
    ops.router.add_get("/health", gw.health)
    ops.router.add_get("/stats", gw.stats)
    ops_runner = web.AppRunner(ops, access_log=None)
    await ops_runner.setup()
    await web.TCPSite(ops_runner, "127.0.0.1", D.OPS_PORT).start()
    gw.events.emit("gateway_ready", bootstrap_s=round(gw.bootstrap_s, 3), spiffe_id=gw.identity.spiffe_id)
    await asyncio.Event().wait()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", default="/public/bundle")
    ap.add_argument("--keys", default="/run/secrets/zt-keys")
    ap.add_argument("--state", default="/var/lib/zt-gateway/state")
    ap.add_argument("--approvals", default="/var/lib/zt-gateway/approvals")
    ap.add_argument("--identity-map", default="/etc/zt/config/identity_map.json")
    ap.add_argument("--agent-ca", default="/etc/zt/agent-ca/ca.pem")
    ap.add_argument("--registry-interval", type=float, default=float(os.environ.get("REGISTRY_INTERVAL_S", "2")))
    ap.add_argument("--registry-max-staleness", type=float, default=float(os.environ.get("REGISTRY_MAX_STALENESS_S", "10")))
    ap.add_argument("--conn-mode", default=os.environ.get("CONN_MODE", "reuse"))
    ap.add_argument("--session-tickets", default=os.environ.get("TLS_SESSION_TICKETS", "on"))
    ap.add_argument("--downstream-timeout", type=float, default=float(os.environ.get("DOWNSTREAM_TIMEOUT_S", "900")))
    ap.add_argument("--events", default=os.environ.get("ZT_EVENTS_FILE"))
    ap.add_argument("--spans", default=os.environ.get("ZT_SPANS_FILE"))
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
