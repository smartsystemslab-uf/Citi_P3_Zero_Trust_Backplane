"""Zero Trust Backplane gateway: the network PEP of the distributed runtime.

Replaces the in-process ADK plugin callbacks (Citi_P3 bank_adk/zero_trust/plugin.py)
with network enforcement points that call the SAME engine methods:

  plugin.on_user_message_callback   -> POST /v1/ingress/run       gateway_input PSL + INPUT_AUTHORIZATION
  plugin.before_agent_callback /
  plugin._authorize_agent_transfer  -> POST /v1/agents/{t}/invoke  AGENT_ROUTE_AUTHORIZATION (+ workflow_run PSL)
  plugin.before_tool_callback       -> MCP tools/call on /mcp      gateway_tool PSL + TOOL_AUTHORIZATION
                                                                   (+ workflow_run PSL) + PSL admission
  plugin.after_tool_callback        -> same handler                finish_tool (post-obligations)
  plugin.protect_final_output       -> end of /v1/ingress/run      OUTPUT_AUTHORIZATION + gateway_output PSL

The caller is not the in-process ``tool_context.agent_name`` but the identity verified
for THIS request with SPIFFE scheme B: the workload X.509-SVID of the mTLS peer
(SPIRE) and the agent certificate bound to it with an RFC 9421 signature over the
request (zt_identity). Every policy -- PDP rules, gateway content rules, temporal
monitors -- comes from the one signed PSL policy store the in-process PDP loads.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import Any

from aiohttp import web
from cryptography import x509

from zt_identity.agent_identity.verifier import AgentCredentialAuthenticator, RegistrySnapshotCache
from zt_identity.events import EventLog
from zt_identity.identity import AuthenticatedIdentity, AuthenticationError
from zt_identity.workload_identity.service_map import IdentityMap
from zt_identity.workload_identity.spiffe_tls import WorkloadIdentity
from zt_identity.workload_identity.svid import PeerIdentityCache

from . import catalog
from .agent_factory import build_original_tree, index_topology, original_tool_functions
from .backplane_adapter import BACKPLANE_ROOT, IdentityAwareBackplane, RunContext, bound_identity
from .gateway_policy import GatewayCheck, GatewayPolicies
from .mcp_bridge import AsgiBridge
from .mcp_server import K_REQUEST_ID, K_WORKFLOW_RUN_ID, META_NS, McpToolServer
from .psl_guard import PslGuard, PslStartDenied, guard_tools
from .transport import ServiceClient, SpanWriter

INGRESS_SUBJECT = "cli_user"


class _ReqView:
    __slots__ = ("method", "path_qs", "headers", "body")

    def __init__(self, request: web.Request, body: bytes) -> None:
        self.method = request.method
        self.path_qs = request.path_qs
        self.headers = request.headers
        self.body = body


def _auth_rec(ident: AuthenticatedIdentity) -> dict[str, Any]:
    return {"mode": ident.auth_mode, "kind": ident.subject_kind, "workload": ident.workload_spiffe_id,
            "agent": ident.agent_id, "cred": ident.agent_credential_id, "method": ident.authentication_method,
            "idv": ident.identity_version}


def _timed(fn: Any, args: dict[str, Any]) -> tuple[Any, int]:
    t = time.perf_counter_ns()
    out = fn(**args)
    return out, time.perf_counter_ns() - t


def _deny(boundary: str, reason: str, status: int = 403, **extra: Any) -> web.Response:
    return web.json_response({"status": "zero_trust_denied", "boundary": boundary, "reason": reason, **extra},
                             status=status)


class Gateway:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.events = EventLog(args.events, component="zt-gateway")
        self.spans = SpanWriter(args.spans)
        t0 = time.monotonic()
        root = build_original_tree()
        topo = index_topology(root)
        self.workflow_by_agent = topo.workflow_by_agent
        self.root_name = root.name
        self.engine = IdentityAwareBackplane(
            backplane_root=BACKPLANE_ROOT,
            mas_repo_root=os.environ.get("CITI_MAS_ROOT", "/opt/citi/Citi_P3"),
            output_dir=args.output_dir,
            mode="enforce",
            refresh=args.refresh_scan,
            runtime_agent_edges=topo.runtime_agent_edges,
        )
        self.bootstrap_s = time.monotonic() - t0
        store = self.engine.task4_runtime.engine.bundle            # verified, signed PslPolicyStore
        self.policy_version = store.version
        self.policies = GatewayPolicies(store.policy_set)
        self.psl = PslGuard(policy_set=store.policy_set, engine=self.engine, events=self.events, spans=self.spans,
                            audit_path=Path(args.output_dir) / "psl_audit.jsonl")
        self.tools = original_tool_functions()
        # every business function runs only with a single-use PSL admission ticket
        self.exec_tools = guard_tools(self.tools, lambda: self.psl)
        self.pool = ThreadPoolExecutor(max_workers=args.tool_threads, thread_name_prefix="tool")
        self.runs: dict[str, RunContext] = {}
        self.identity: WorkloadIdentity | None = None
        self.peer_cache = PeerIdentityCache(catalog.TRUST_DOMAIN)
        self.registry: RegistrySnapshotCache | None = None
        self.counters: dict[str, int] = {}
        self.peer_serials: dict[str, dict[str, Any]] = {}
        self.tool_executions = 0
        self.mcp_messages: dict[str, int] = {}
        self.mcp_sessions: dict[str, tuple] = {}
        self.mcp_server = McpToolServer(execute_tool=self.execute_tool, tool_functions=self.tools,
                                        authority=catalog.GATEWAY_AUTHORITY)
        self.mcp_bridge = AsgiBridge(self.mcp_server.manager.handle_request)
        self.events.emit("gateway_policies_loaded", policy_version=self.policy_version,
                         gateway_rules=self.policies.rule_counts, policy_files=list(store.source_files))

    # ------------------------------------------------------------------
    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self.identity_map = IdentityMap(self.args.identity_map, events=self.events,
                                        on_change=self.engine.on_identity_change)
        self.identity = WorkloadIdentity(trust_domain=catalog.TRUST_DOMAIN, events=self.events)
        self.identity.bind_loop(loop)
        expected = {w.name: w.spiffe_id for w in catalog.AGENTS.values()}
        expected[catalog.ISSUER_HOST] = catalog.SERVICES["agent-issuer"].spiffe_id
        self.downstream = ServiceClient(identity=self.identity, trust_domain=catalog.TRUST_DOMAIN,
                                        expected_servers=expected, conn_mode=self.args.conn_mode)
        ca = x509.load_pem_x509_certificate(Path(self.args.agent_ca).read_bytes())

        async def fetch() -> dict[str, Any]:
            status, body = await self.downstream.get_json(f"{catalog.issuer_url()}/v1/registry/snapshot")
            if status != 200:
                raise RuntimeError(f"snapshot status {status}: {body}")
            return body

        self.registry = RegistrySnapshotCache(fetch, interval_s=self.args.registry_interval,
                                              max_staleness_s=self.args.registry_max_staleness,
                                              events=self.events, on_identity_change=self.engine.on_identity_change)
        while True:
            try:
                await self.registry.refresh_once()
                break
            except Exception as exc:
                self.events.emit("registry_wait", error=str(exc)[:200])
                await asyncio.sleep(1.0)
        loop.create_task(self.registry.run())
        self.authenticator = AgentCredentialAuthenticator(
            ca_cert=ca, registry=self.registry, service_map=self.identity_map, authority=catalog.GATEWAY_AUTHORITY)
        self.spans.start()

    def _workflow_for(self, agent_name: str | None) -> str | None:
        return self.workflow_by_agent.get(agent_name) if agent_name else None

    def _count(self, key: str) -> None:
        self.counters[key] = self.counters.get(key, 0) + 1

    def _transport_of(self, request: web.Request) -> Any:
        ssl_obj = request.transport.get_extra_info("ssl_object") if request.transport else None
        transport = self.peer_cache.identity_for(ssl_obj)
        r = self.peer_serials.setdefault(transport.cert_serial, {
            "spiffe_id": transport.spiffe_id, "first_seen": time.time(), "requests": 0})
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

    async def _invoke_agent(self, target: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        status, data, _ = await self.downstream.post(f"{catalog.agent_url(target)}/v1/invoke", payload)
        return status, data

    def _record_check(self, check: GatewayCheck, *, trace_id: str, workflow_run_id: str, caller: str,
                      target: str) -> None:
        """Audit of a gateway PSL check: every decision is recorded in the Backplane audit
        (the rules' audit_log obligation); other obligations are listed with it."""
        self.engine.append_runtime_event(
            "GATEWAY_PSL_CHECK", trace_id=trace_id, workflow_instance_id=workflow_run_id,
            caller_runtime_id=caller, target_runtime_id=target, policy_version=self.policy_version,
            **check.summary())

    def _user_role(self, ident: AuthenticatedIdentity, asserted: str) -> str:
        """The asserted end-user role counts only if the controlled service map lists it for
        this authenticated ingress service; otherwise it is unknown ('')."""
        entry = self.identity_map.lookup(ident.workload_spiffe_id or "")
        return asserted if entry is not None and entry.enabled and asserted in entry.user_roles else ""

    # ------------------------------------------------------------------
    async def ingress(self, request: web.Request) -> web.Response:
        t0 = time.perf_counter_ns()
        spans: dict[str, float] = {}
        rec: dict[str, Any] = {"ep": "ingress"}
        body, data = await self._read(request)
        ta = time.perf_counter_ns()
        try:
            ident = self._authenticate(request, body, data)
        except AuthenticationError as exc:
            self._count("authn_fail:" + exc.code)
            rec.update(status=401, error=exc.code)
            self._span(rec, spans, t0)
            return _deny("authentication", exc.code, 401)
        spans["authn_ms"] = (time.perf_counter_ns() - ta) / 1e6
        rec["auth"] = _auth_rec(ident)
        if ident.subject_kind != "service" or ident.agent_id != INGRESS_SUBJECT:
            rec.update(status=403, error="caller_not_ingress_service")
            self._span(rec, spans, t0)
            return _deny("ingress", "caller_not_ingress_service")
        entry = str(data.get("entry_agent", ""))
        if entry not in catalog.AGENTS:
            rec.update(status=400, error="unknown_entry_agent")
            self._span(rec, spans, t0)
            return _deny("ingress", "unknown_entry_agent", 400)
        session = data.get("session") if isinstance(data.get("session"), dict) else {}
        session_id = str(session.get("session_id") or "")[:128]
        user_role = self._user_role(ident, str(session.get("user_role") or ""))
        message = str(data.get("message", ""))
        approvals = data.get("approvals") or {}
        run = RunContext(
            workflow_run_id=f"wfr-{uuid.uuid4()}",
            trace_id=f"trace-ztbp-{uuid.uuid4()}",
            session_id=session_id,
            user_role=user_role,
            human_approval=bool(approvals.get("human_approval")),
            secondary_authorization=bool(approvals.get("secondary_authorization")),
            change_ticket=str(approvals["change_ticket"]) if approvals.get("change_ticket") else None,
        )
        rec.update(agent=entry, request_id=data.get("request_id"), workflow_run_id=run.workflow_run_id,
                   user_role=user_role or None)

        # gateway_input (intent.psl, check-only): session context and prompt-injection patterns
        tc = time.perf_counter_ns()
        chk = self.policies.check_input(session_id=session_id, user_role=user_role, message=message)
        spans["gateway_psl_ms"] = (time.perf_counter_ns() - tc) / 1e6
        rec["input_policy"] = chk.summary()
        self._record_check(chk, trace_id=run.trace_id, workflow_run_id=run.workflow_run_id,
                           caller=INGRESS_SUBJECT, target=entry)
        if not chk.allowed:
            self._count("deny:input_policy")
            rec.update(status=403, error=chk.decision.reason())
            self._span(rec, spans, t0)
            return _deny("input_policy", chk.decision.reason(), trace_id=run.trace_id,
                         rules=[v.rule_id for v in chk.decision.violated])

        tz = time.perf_counter_ns()
        with bound_identity(ident, run, spans):
            auth = self.engine.authorize(
                self.engine.find_input_placement(),
                parameters={"message_sha256": hashlib.sha256(message.encode()).hexdigest(),
                            "message_length": len(message)},
                trace_id=run.trace_id, workflow_instance_id=run.workflow_run_id,
                event_type="INPUT_AUTHORIZATION", caller_runtime_id=INGRESS_SUBJECT, target_runtime_id=entry)
        spans["authz_ms"] = (time.perf_counter_ns() - tz) / 1e6
        rec.update(decision=auth.decision, permit_id=auth.permit_id)
        if not self.engine.should_execute(auth, critical=False):
            self._count("deny:input")
            rec.update(status=403, error=auth.reason)
            self._span(rec, spans, t0)
            return _deny("input", auth.reason, trace_id=run.trace_id)
        self.runs[run.workflow_run_id] = run
        self.psl.dispatched(run.workflow_run_id, entry)
        td = time.perf_counter_ns()
        try:
            status, result = await self._invoke_agent(entry, {
                "request_id": str(uuid.uuid4()), "workflow_run_id": run.workflow_run_id,
                "trace_id": run.trace_id, "message": message, "state": data.get("initial_state") or {}})
        finally:
            self.runs.pop(run.workflow_run_id, None)
            self.psl.dispatch_ended(run.workflow_run_id, entry)
            self.psl.run_closed(run.workflow_run_id)
            closed = self.engine.close_workflow(run.workflow_run_id)
            if closed:
                rec["workflow_close_violations"] = sorted({v.property_id for v in closed})
        spans["downstream_ms"] = (time.perf_counter_ns() - td) / 1e6
        if status != 200:
            self._count("entry_agent_error")
            rec.update(status=502, error=f"entry_agent_status_{status}")
            self._span(rec, spans, t0)
            return web.json_response({"status": "entry_agent_error", "agent_status": status, "detail": result,
                                      "workflow_run_id": run.workflow_run_id}, status=502)
        out_spans: dict[str, float] = {}
        tz = time.perf_counter_ns()
        raw = json.dumps(result, sort_keys=True, default=str).encode()
        with bound_identity(ident, run, out_spans):
            out = self.engine.authorize(
                self.engine.find_output_placement(),
                parameters={"output_sha256": hashlib.sha256(raw).hexdigest(), "output_bytes": len(raw)},
                trace_id=run.trace_id, workflow_instance_id=run.workflow_run_id,
                event_type="OUTPUT_AUTHORIZATION", caller_runtime_id=self.root_name,
                target_runtime_id="mas_output_channel")
        spans["authz_ms"] += (time.perf_counter_ns() - tz) / 1e6
        for k, v in out_spans.items():
            spans[k] = spans.get(k, 0.0) + v
        if not self.engine.should_execute(out, critical=False):
            self._count("deny:output")
            rec.update(status=403, error=out.reason)
            self._span(rec, spans, t0)
            return _deny("output", out.reason, trace_id=run.trace_id)

        # gateway_output (intent.psl, check-only): PII and unexplained amounts in the final output
        tc = time.perf_counter_ns()
        ochk = self.policies.check_output(text=raw.decode("utf-8", "replace"), request_text=message)
        spans["gateway_psl_ms"] += (time.perf_counter_ns() - tc) / 1e6
        rec["output_policy"] = ochk.summary()
        self._record_check(ochk, trace_id=run.trace_id, workflow_run_id=run.workflow_run_id,
                           caller=self.root_name, target="mas_output_channel")
        if not ochk.allowed:
            self._count("deny:output_policy")
            rec.update(status=403, error=ochk.decision.reason())
            self._span(rec, spans, t0)
            return _deny("output_policy", ochk.decision.reason(), trace_id=run.trace_id,
                         rules=[v.rule_id for v in ochk.decision.violated])
        self._count("ingress_ok")
        rec.update(status=200)
        self._span(rec, spans, t0)
        return web.json_response({
            "status": "ok", "workflow_run_id": run.workflow_run_id, "trace_id": run.trace_id,
            "entry_agent": entry, "result": result,
            "policy_flags": [f.rule_id for f in ochk.decision.flagged] or None,
            "gateway_timing_ms": {k: round(v, 4) for k, v in spans.items()}})

    async def route(self, request: web.Request) -> web.Response:
        t0 = time.perf_counter_ns()
        spans: dict[str, float] = {}
        target = request.match_info["target"]
        rec: dict[str, Any] = {"ep": "route", "target": target}
        body, data = await self._read(request)
        ta = time.perf_counter_ns()
        try:
            ident = self._authenticate(request, body, data)
        except AuthenticationError as exc:
            self._count("authn_fail:" + exc.code)
            rec.update(status=401, error=exc.code)
            self._span(rec, spans, t0)
            return _deny("authentication", exc.code, 401)
        spans["authn_ms"] = (time.perf_counter_ns() - ta) / 1e6
        rec["auth"] = _auth_rec(ident)
        run = self.runs.get(str(data.get("workflow_run_id", "")))
        if run is None or ident.subject_kind != "agent" or target not in catalog.AGENTS:
            rec.update(status=403, error="unknown_workflow_run_target_or_not_agent")
            self._span(rec, spans, t0)
            return _deny("agent_route", "unknown_workflow_run_target_or_not_agent")
        caller = ident.agent_id
        rec.update(agent=caller, request_id=data.get("request_id"), workflow_run_id=run.workflow_run_id)
        placement = self.engine.find_route_placement(caller, target)
        workflow_id = self._workflow_for(target) or self._workflow_for(caller)
        tz = time.perf_counter_ns()
        with bound_identity(ident, run, spans):
            auth = self.engine.authorize(
                placement, parameters={"target_agent": target}, trace_id=run.trace_id,
                workflow_instance_id=run.workflow_run_id, workflow_id=workflow_id,
                event_type="AGENT_ROUTE_AUTHORIZATION", caller_runtime_id=caller, target_runtime_id=target)
        spans["authz_ms"] = (time.perf_counter_ns() - tz) / 1e6
        rec.update(decision=auth.decision, permit_id=auth.permit_id, source=auth.source)
        if not self.engine.should_execute(auth, critical=False):
            self._count("deny:route")
            rec.update(status=403, error=auth.reason)
            self._span(rec, spans, t0)
            return _deny("agent_route", auth.reason, caller=caller, target=target)
        td = time.perf_counter_ns()
        self.psl.dispatched(run.workflow_run_id, target)
        try:
            status, result = await self._invoke_agent(target, {
                "request_id": str(uuid.uuid4()), "workflow_run_id": run.workflow_run_id, "trace_id": run.trace_id,
                "message": data.get("message", ""), "state": data.get("state") or {}})
        finally:
            self.psl.dispatch_ended(run.workflow_run_id, target)
        spans["downstream_ms"] = (time.perf_counter_ns() - td) / 1e6
        rec.update(status=status)
        self._span(rec, spans, t0)
        self._count(f"route_{status}")
        return web.json_response(result, status=200 if status == 200 else 502)

    # ------------------------------------------------------------------
    # Tool path (MCP tools/call): gateway_tool PSL check, PEP/PDP/Permit Lease (+ the
    # engine's workflow_run monitor), PSL admission, original tool, post-obligations.
    # ------------------------------------------------------------------
    async def execute_tool(self, *, ident: AuthenticatedIdentity, tool_name: str, args: dict[str, Any],
                           workflow_run_id: str, idempotency_key: str, request_id: str,
                           spans: dict[str, float], rec: dict[str, Any],
                           psl_attempt: Any = None) -> tuple[str, dict[str, Any]]:
        psl, att = self.psl, psl_attempt
        if att is None:
            raise RuntimeError("fail-closed: tool path reached without a PSL request attempt")
        try:
            return await self._execute_tool(ident=ident, tool_name=tool_name, args=args,
                                            workflow_run_id=workflow_run_id, idempotency_key=idempotency_key,
                                            request_id=request_id, spans=spans, rec=rec, att=att)
        finally:
            close_v = psl.finish(att)
            spans["psl_check_ms"] = att.psl_ns / 1e6
            spans["psl_binding_ms"] = att.binding_ns / 1e6
            spans["psl_audit_ms"] = att.audit_ns / 1e6
            rec.update(psl_attempt=att.attempt_id, psl_outcome=att.outcome, psl_layer=att.layer,
                       psl_violations=[v["property_id"] for v in att.violations] or None,
                       psl_close_violations=[v["property_id"] for v in close_v] or None)

    async def _execute_tool(self, *, ident: AuthenticatedIdentity, tool_name: str, args: dict[str, Any],
                            workflow_run_id: str, idempotency_key: str, request_id: str,
                            spans: dict[str, float], rec: dict[str, Any], att: Any) -> tuple[str, dict[str, Any]]:
        psl = self.psl
        run = self.runs.get(workflow_run_id)
        if run is None or ident.subject_kind != "agent":
            rec.update(status=403, error="unknown_workflow_run_or_not_agent")
            psl.reject(att, "run_rejected", layer="run_check", reason="unknown_workflow_run_or_not_agent",
                       terminal_for_operation=False)
            return "denied", {"status": "zero_trust_denied", "boundary": "tool",
                              "reason": "unknown_workflow_run_or_not_agent"}
        agent = ident.agent_id
        rec.update(agent=agent, request_id=request_id, workflow_run_id=run.workflow_run_id, tool=tool_name)

        # gateway_tool (intent.psl, check-only): facts of the run's originating user session
        tc = time.perf_counter_ns()
        chk = self.policies.check_tool(tool_name=tool_name, user_role=run.user_role)
        spans["gateway_psl_ms"] = (time.perf_counter_ns() - tc) / 1e6
        if chk.decision.violated or chk.decision.flagged:
            rec["tool_policy"] = chk.summary()
        if chk.decision.obligations or not chk.allowed:
            self._record_check(chk, trace_id=run.trace_id, workflow_run_id=run.workflow_run_id,
                               caller=agent, target=tool_name)
        if not chk.allowed:
            self._count("deny:tool_policy")
            rec.update(status=403, error=chk.decision.reason())
            psl.reject(att, "authorization_denied", layer="gateway_tool_policy", reason=chk.decision.reason(),
                       terminal_for_operation=True)
            return "denied", {"status": "zero_trust_denied", "boundary": "tool_policy",
                              "reason": chk.decision.reason(), "tool": tool_name, "agent": agent}

        workflow_id = self._workflow_for(agent)
        placement = self.engine.find_tool_placement(agent, tool_name, workflow_id=workflow_id)
        tz = time.perf_counter_ns()
        try:
            with bound_identity(ident, run, spans) as actx:
                pending = self.engine.begin_tool(
                    placement, tool_args=dict(args), trace_id=run.trace_id,
                    workflow_instance_id=run.workflow_run_id, workflow_id=workflow_id,
                    idempotency_key=idempotency_key or f"adk:{run.workflow_run_id}:{request_id}",
                    caller_runtime_id=agent, tool_name=tool_name)
        except Exception as exc:          # obligation / idempotency failures are denials
            spans["authz_ms"] = (time.perf_counter_ns() - tz) / 1e6
            self._count("deny:tool_obligation")
            rec.update(status=403, error=f"{type(exc).__name__}")
            if actx.flags.get("validate_ok"):
                psl._obs(att, [("request_attempt", att.key(), "authorization_allowed", {}),
                               ("request_attempt", att.key(), "permit_verified", {})])
            psl.reject(att, "obligation_rejected", layer="obligation_or_idempotency",
                       reason=f"{type(exc).__name__}", terminal_for_operation=True)
            return "denied", {"status": "zero_trust_denied", "boundary": "tool",
                              "reason": f"{type(exc).__name__}: {exc}", "tool": tool_name, "agent": agent}
        spans["authz_ms"] = (time.perf_counter_ns() - tz) / 1e6
        critical = bool(placement and placement.get("critical"))
        rec.update(decision=pending.authorization.decision, reason=pending.authorization.reason,
                   source=pending.authorization.source)
        cls = psl.authorization_result(att, pending, actx.flags)
        if not self.engine.should_execute(pending.authorization, critical=critical):
            self._count("deny:tool")
            rec.update(status=403, error=pending.authorization.reason)
            layer = {"authorization_denied": "pdp", "permit_rejected": "permit",
                     "authorization_unavailable": "pdp_unavailable"}.get(cls, "pdp")
            if pending.authorization.source == "PSL_WORKFLOW_MONITOR":
                layer = "workflow_monitor"
            psl.reject(att, cls if cls != "allowed" else "authorization_denied", layer=layer,
                       reason=str(pending.authorization.reason),
                       terminal_for_operation=cls in ("authorization_denied", "permit_rejected"))
            return "denied", {"status": "zero_trust_denied", "boundary": "tool",
                              "reason": pending.authorization.reason, "tool": tool_name, "agent": agent}
        args_to_run = dict(args)
        if cls != "allowed":                       # inconsistent: allowed without a verified lease
            self.engine.abort_tool(pending)
            psl.reject(att, "permit_rejected", layer="permit", reason="no_verified_permit",
                       terminal_for_operation=True)
            return "denied", psl.denial_body(att, "no_verified_permit", tool=tool_name, agent=agent)
        psl.execution_requested(att)
        ok, reason = psl.admit(att, pending, ident, args_to_run)
        if not ok:
            self.engine.abort_tool(pending)
            self._count("deny:psl")
            rec.update(status=403, error="PSL_VIOLATION", psl_reason=reason)
            return "denied", psl.denial_body(att, reason, tool=tool_name, agent=agent)
        ticket = psl.issue_ticket(att)     # pre-execution record + start happen in the tool thread
        fn = self.exec_tools.get(tool_name)
        call_args = {**args_to_run, "_psl_ticket": ticket}
        tb = time.perf_counter_ns()
        try:
            if fn is None:
                raise LookupError(f"tool {tool_name} not hosted")
            result, exec_ns = await asyncio.get_running_loop().run_in_executor(self.pool, partial(_timed, fn, call_args))
        except PslStartDenied as exc:              # refused before the business function ran
            self.engine.abort_tool(pending)
            spans["business_wall_ms"] = (time.perf_counter_ns() - tb) / 1e6
            psl.start_denied(att, str(exc))
            self._count("deny:psl")
            rec.update(status=403, error="PSL_VIOLATION", psl_reason=str(exc))
            return "denied", psl.denial_body(att, str(exc) or "PSL_VIOLATION", tool=tool_name, agent=agent)
        except Exception as exc:
            self.engine.abort_tool(pending)
            spans["business_wall_ms"] = (time.perf_counter_ns() - tb) / 1e6
            self._count("tool_error")
            rec.update(status=500, error=type(exc).__name__)
            psl.flush_deferred(att)
            psl.execution_finished(att, False, None)
            return "error", {"status": "tool_error", "error": f"{type(exc).__name__}: {exc}"}
        spans["psl_start_ms"] = att.start_ns / 1e6
        spans["business_ms"] = (exec_ns - att.start_ns) / 1e6
        spans["business_wall_ms"] = (time.perf_counter_ns() - tb) / 1e6
        psl.flush_deferred(att)
        psl.execution_finished(att, True, result)
        tf = time.perf_counter_ns()
        protected = self.engine.finish_tool(pending, result)
        spans["authz_ms"] += (time.perf_counter_ns() - tf) / 1e6
        rec.update(status=200, critical=critical, permit_id=pending.authorization.permit_id)
        self._count("tool_ok")
        self.tool_executions += 1
        return "ok", {"status": "ok", "result": protected, "permit_id": pending.authorization.permit_id,
                      "decision": pending.authorization.decision}

    # ------------------------------------------------------------------
    # MCP endpoint (Streamable HTTP, official SDK behind a thin ASGI bridge)
    # ------------------------------------------------------------------
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
        rec: dict[str, Any] = {"ep": "mcp", "http_method": request.method, "rpc_method": method,
                               "rpc_id": rpc.get("id") if isinstance(rpc, dict) else None}
        att = None
        if method == "tools/call":
            params = rpc.get("params") or {}
            rec["tool"] = params.get("name")
            # a business request: its PSL request-attempt scope opens BEFORE authentication
            att = self.psl.request_received(
                jsonrpc_id=rpc.get("id"), session=request.headers.get("mcp-session-id"),
                tool=str(params.get("name")), args=params.get("arguments") or {},
                meta=params.get("_meta") or {}, meta_ns=META_NS)
            rec["psl_attempt"] = att.attempt_id
        ta = time.perf_counter_ns()
        try:
            ident, transport = self._authenticate_mcp(request, body, rpc)
        except AuthenticationError as exc:
            self._count("mcp_authn_fail:" + exc.code)
            rec.update(status=401, error=exc.code)
            if att is not None:
                self.psl.reject(att, "identity_rejected", layer="authentication", reason=exc.code,
                                terminal_for_operation=False)
                self.psl.finish(att)
            self._span(rec, spans, t0)
            self.mcp_messages[kind] = self.mcp_messages.get(kind, 0) + 1
            return _deny("authentication", exc.code, 401)
        spans["authn_ms"] = (time.perf_counter_ns() - ta) / 1e6
        rec["auth"] = _auth_rec(ident)
        if att is not None:
            self.psl.identity_verified(att, ident, transport)
        if ident.subject_kind != "agent":
            rec.update(status=403, error="mcp_caller_not_agent")
            if att is not None:
                self.psl.reject(att, "request_denied", layer="authentication", reason="mcp_caller_not_agent",
                                terminal_for_operation=False)
                self.psl.finish(att)
            self._span(rec, spans, t0)
            return _deny("mcp", "mcp_caller_not_agent", 403)
        principal = (ident.auth_mode, ident.agent_id, ident.workload_spiffe_id)
        sid = request.headers.get("mcp-session-id")
        if sid:
            bound = self.mcp_sessions.get(sid)
            if bound is not None and bound != principal:
                self._count("mcp_session_principal_mismatch")
                rec.update(status=403, error="mcp_session_bound_to_other_principal")
                if att is not None:
                    self.psl.reject(att, "request_denied", layer="session_binding",
                                    reason="mcp_session_bound_to_other_principal", terminal_for_operation=False)
                    self.psl.finish(att)
                self._span(rec, spans, t0)
                return _deny("mcp", "mcp_session_bound_to_other_principal", 403)
            rec["session"] = sid[:8]
        self.mcp_messages[kind] = self.mcp_messages.get(kind, 0) + 1
        if request.method == "GET":
            # no standalone server->client SSE stream is offered (no server-initiated messages)
            rec.update(status=405)
            self._span(rec, spans, t0)
            return web.Response(status=405, headers={"Allow": "POST, DELETE"})
        state: dict[str, Any] = {"zt_identity": ident, "zt_spans": spans, "zt_rec": rec, "zt_psl_attempt": att}
        ts = time.perf_counter_ns()
        resp, resp_headers = await self.mcp_bridge.handle(request, body, state)
        te = time.perf_counter_ns()
        if att is not None and not att.closed:
            # the SDK answered without reaching the tool handler (unknown tool, input schema
            # validation, protocol error): a denial by the MCP layer, never an execution
            self.psl.reject(att, "request_denied", layer="mcp_sdk", reason=f"http_{resp.status}_before_handler",
                            terminal_for_operation=False)
            self.psl.finish(att)
        if "t_handler_start_ns" in state:
            spans["mcp_sdk_in_ms"] = (state["t_handler_start_ns"] - ts) / 1e6
            spans["mcp_sdk_out_ms"] = (te - state["t_handler_end_ns"]) / 1e6
        else:
            spans["mcp_sdk_total_ms"] = (te - ts) / 1e6
        new_sid = resp_headers.get("mcp-session-id")
        if method == "initialize" and new_sid and resp.status == 200:
            self.mcp_sessions[new_sid] = principal
            rec["session"] = new_sid[:8]
            rec["protocol_version_requested"] = (rpc.get("params") or {}).get("protocolVersion")
        if request.method == "DELETE" and sid:
            self.mcp_sessions.pop(sid, None)
        rec.setdefault("status", resp.status)
        rec["http_status"] = resp.status
        self._span(rec, spans, t0)
        return resp

    async def health(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "ok", "auth_scheme": "spiffe-b", "bootstrap_s": round(self.bootstrap_s, 3),
            "spiffe_id": self.identity.spiffe_id if self.identity else None,
            "policy_version": self.policy_version,
            "gateway_rules": self.policies.rule_counts,
            "psl_monitors": sorted({m.pid for ms in self.psl.runtime.machines.values() for m in ms}),
            "logical_peps": len(self.engine.plan_json.get("logical_peps", [])),
        })

    async def stats(self, request: web.Request) -> web.Response:
        self.spans.flush()
        out: dict[str, Any] = {
            "counters": self.counters, "peer_serials": self.peer_serials,
            "identity_changes": self.engine.identity_changes,
            "revocation_epoch": self.engine.components.revocations.epoch,
            "tool_executions": self.tool_executions,
            "mcp_messages": self.mcp_messages, "mcp_sessions_bound": len(self.mcp_sessions),
            "psl": self.psl.snapshot(),
            "workflow_monitor": self.engine.workflow_monitor.snapshot(),
            "mcp_session_principals": sorted({f"{p[0]}|{p[1]}|{p[2]}" for p in self.mcp_sessions.values()}),
        }
        if self.registry is not None:
            out["registry"] = {"refreshes": self.registry.refreshes, "failures": self.registry.refresh_failures,
                               "version": (self.registry.snapshot or {}).get("registry_version")}
            out["agent_cert_cache"] = {"hits": self.authenticator.cert_cache_hits,
                                       "misses": self.authenticator.cert_cache_misses}
        if self.identity is not None:
            out["svid"] = {"serial": self.identity.cert_serial, "not_after": self.identity.not_after_iso,
                           "generation": self.identity.generation}
        return web.json_response(out)


async def main_async(args: argparse.Namespace) -> None:
    gw = Gateway(args)
    await gw.start()
    app = web.Application(client_max_size=4 * 1024 * 1024)
    app.router.add_post("/v1/ingress/run", gw.ingress)
    app.router.add_post("/v1/agents/{target}/invoke", gw.route)
    for m in ("POST", "GET", "DELETE"):
        app.router.add_route(m, "/mcp", gw.mcp_endpoint)      # MCP Streamable HTTP
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
    await web.TCPSite(runner, "0.0.0.0", catalog.GATEWAY_PORT, ssl_context=ssl_ctx, backlog=4096).start()
    ops = web.Application()                       # local-only health/stats, not exposed on the network
    ops.router.add_get("/health", gw.health)
    ops.router.add_get("/stats", gw.stats)
    ops_runner = web.AppRunner(ops, access_log=None)
    await ops_runner.setup()
    await web.TCPSite(ops_runner, "127.0.0.1", catalog.OPS_PORT).start()
    gw.events.emit("gateway_ready", bootstrap_s=round(gw.bootstrap_s, 3), spiffe_id=gw.identity.spiffe_id,
                   time_to_first_svid_s=round(gw.identity.time_to_first_svid_s, 4))
    await asyncio.Event().wait()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", default="/var/lib/zt-gateway/output")
    ap.add_argument("--refresh-scan", action="store_true")
    ap.add_argument("--identity-map", default="/etc/citi/config/identity_map.json")
    ap.add_argument("--agent-ca", default="/etc/citi/agent-ca/ca.pem")
    ap.add_argument("--registry-interval", type=float, default=float(os.environ.get("REGISTRY_INTERVAL_S", "2")))
    ap.add_argument("--registry-max-staleness", type=float,
                    default=float(os.environ.get("REGISTRY_MAX_STALENESS_S", "10")))
    ap.add_argument("--conn-mode", default=os.environ.get("CONN_MODE", "reuse"))
    ap.add_argument("--session-tickets", default=os.environ.get("TLS_SESSION_TICKETS", "on"))
    ap.add_argument("--tool-threads", type=int, default=32)
    ap.add_argument("--events", default=os.environ.get("CITI_EVENTS_FILE"))
    ap.add_argument("--spans", default=os.environ.get("CITI_SPANS_FILE"))
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
