"""Runtime core of the zt-adk Backplane: one protection bundle, enforced.

The engine is used by the in-process ADK plugin (runtime ``native``) and by the distributed
gateway (runtime ``gateway``). It

* verifies the bundle (signature with the deployment's policy key, file hashes);
* starts the PDP on the bundle's signed PSL store and registries (in-process ASGI
  app, or a remote PDP service), the Permit Lease components, and the PSL request
  engines / temporal monitors of the store for its runtime;
* answers, per boundary: content checks (PSL request scopes), PDP authorization through a
  generated PEP placement (Permit Lease lease, signed decision), workflow monitor admission,
  approvals for MANUAL_REVIEW, post-obligations (masking), audit.

Nothing is allowed without a generated placement: an edge the bundle does not know is
denied (``NO_GENERATED_PEP``).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import model as M
from .approvals import ApprovalStore, operation_hash
from .audit import AuditLog
from .bundle import verify_bundle
from .content import ContentInspector
from .keys import PDP_ISSUER, POLICY_ISSUER, RUNTIME_ISSUERS, load_private, require_keys
from .manifest import IdMaps, INPUT_RUNTIME, INGRESS_RUNTIME, OUTPUT_RUNTIME
from .profile import Content

RISK_BASE = {"low": 150, "medium": 350, "high": 600, "critical": 850}
CONTENT_SCOPES = {
    "input": ("input_message", "input_received"),
    "output": ("output_message", "output_emitted"),
    "agent_message": ("agent_message", "agent_message_sent"),
    "tool_call": ("tool_call", "tool_call_requested"),
    "tool_result": ("tool_result", "tool_result_received"),
    "model": ("model_request", "model_requested"),
}
WORKFLOW_SCOPE = "workflow_run"
ADK_FRAMEWORK_FUNCTIONS = {"transfer_to_agent", "set_model_response", "finish_task", "request_task"}


class EngineError(RuntimeError):
    pass


@dataclass(frozen=True)
class RequestAuth:
    """Authentication result of one request, bound for the duration of its authorization
    (the distributed gateway; concurrent requests of the same run each have their own)."""

    factors: dict[str, bool]
    authentication: dict[str, Any]
    identity_version: str = "identity-epoch-1"


import contextvars as _cv  # noqa: E402

REQUEST_AUTH: _cv.ContextVar[RequestAuth | None] = _cv.ContextVar("zt_adk_request_auth", default=None)


@dataclass
class RunContext:
    invocation_id: str
    trace_id: str = field(default_factory=lambda: f"trace-{uuid.uuid4()}")
    workflow_instance_id: str = field(default_factory=lambda: f"run-{uuid.uuid4()}")
    session_id: str = ""
    user_role: str = ""
    session_present: bool = False
    tainted: bool = False
    taint_reasons: list[str] = field(default_factory=list)
    authentication: dict[str, Any] | None = None          # gateway: verified caller (set per request)
    auth_factors: dict[str, bool] | None = None
    identity_version: str = "identity-epoch-1"
    approved_ops: dict[str, dict[str, Any]] = field(default_factory=dict)   # request hash -> assertions

    def taint(self, reason: str) -> None:
        self.tainted = True
        if reason not in self.taint_reasons:
            self.taint_reasons.append(reason)


@dataclass
class Verdict:
    allowed: bool
    decision: str
    reason: str
    source: str
    placement: dict[str, Any] | None = None
    permit_id: str | None = None
    policy_version: str | None = None
    rules: list[str] = field(default_factory=list)
    obligations: list[Any] = field(default_factory=list)
    flagged: list[str] = field(default_factory=list)
    approval_id: str | None = None
    latency_ms: float = 0.0
    request: Any = None
    runtime_authorization: Any = None

    def summary(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "decision": self.decision, "reason": self.reason[:300],
                "source": self.source, "placement_id": (self.placement or {}).get("placement_id"),
                "permit_id": self.permit_id, "policy_version": self.policy_version, "rules": self.rules,
                "flagged": self.flagged, "approval_id": self.approval_id, "latency_ms": round(self.latency_ms, 3)}


@dataclass
class PendingTool:
    verdict: Verdict
    pep: Any
    request: Any
    obligations: list[Any]
    reserved: bool
    run: RunContext
    agent: str
    tool: str
    critical: bool


class ProtectionEngine:
    def __init__(self, *, bundle_dir: str | Path, keys_dir: str | Path, state_dir: str | Path,
                 runtime: str = "native", mode: str | None = None, pdp_client: Any = None,
                 process_spiffe_id: str | None = None, approvals_dir: str | Path | None = None) -> None:
        from zt_psl import RequestPolicyEngine
        from zt_psl.runtime import MonitorRuntime

        self.bundle_dir = Path(bundle_dir).resolve()
        self.keys_dir = Path(keys_dir).resolve()
        self.state_dir = Path(state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.runtime = runtime
        require_keys(self.keys_dir)
        self.index = verify_bundle(self.bundle_dir, self.keys_dir / "signing" / "policy_public.pem",
                                   expected_issuer=POLICY_ISSUER[0])
        self.model = M.SystemModel.from_dict(json.loads((self.bundle_dir / "system_model.json").read_text("utf-8")))
        self.ids = IdMaps.from_dict(json.loads((self.bundle_dir / "bindings.json").read_text("utf-8")))
        self.profile = json.loads((self.bundle_dir / "runtime_profile.json").read_text("utf-8"))
        self.mode = mode or self.profile["mode"]
        if self.mode not in ("enforce", "shadow"):
            raise EngineError("mode must be 'enforce' or 'shadow'")
        self.environment = self.profile["environment"]
        self.plan = json.loads((self.bundle_dir / "pep" / "generated_pep_plan.json").read_text("utf-8"))
        self.process_spiffe_id = process_spiffe_id
        self.audit = AuditLog(self.state_dir / "audit.jsonl")
        self.approvals = ApprovalStore(Path(approvals_dir) if approvals_dir else self.state_dir / "approvals")
        self.inspector = ContentInspector(Content.model_validate(self.profile["content"]))
        self._lock = threading.RLock()
        self._index_placements()
        self._start_pdp(pdp_client)
        store = self.pdp_runtime.engine.bundle if self.pdp_runtime is not None else self._load_store()
        self.policy_set = store.policy_set
        self.policy_version = store.version
        if self.policy_version != self.index.get("policy_version"):
            raise EngineError("policy store version differs from the bundle index")
        self.content_engines = {
            name: RequestPolicyEngine(self.policy_set, scope=scope, runtime=runtime)
            for name, (scope, _event) in CONTENT_SCOPES.items()
        }
        self.monitor = MonitorRuntime.from_policy_set(self.policy_set, runtime, scopes=[WORKFLOW_SCOPE],
                                                      capacity={WORKFLOW_SCOPE: 20000})
        self._start_lease()
        self.audit.write("ENGINE_START", runtime=runtime, mode=self.mode, app=self.model.app_name,
                         fingerprint=self.index["fingerprint"], policy_version=self.policy_version,
                         logical_peps=len(self.plan.get("logical_peps", [])), durable=True)

    # ------------------------------------------------------------------ setup
    def _load_store(self) -> Any:
        from zt_pdp.crypto import TrustedKeyStore
        from zt_pdp.psl_policy import PslPolicyStore

        return PslPolicyStore.load(self.bundle_dir / "policy_store",
                                   keys=TrustedKeyStore(self.keys_dir / "trusted_issuers.yaml"))

    def _start_pdp(self, pdp_client: Any) -> None:
        from zt_pdp.evidence import SecurityConfig
        from zt_pdp.evidence_issuer import IssuerKey, SignedRequestBuilder
        from .pdp_bridge import PdpBridge

        self.pdp_runtime = None
        if pdp_client is None:
            from fastapi.testclient import TestClient
            from zt_pdp.pdp_service import PdpConfig, build_runtime, create_app

            cfg = PdpConfig(
                policy_dir=self.bundle_dir / "policy_store",
                identity_file=self.bundle_dir / "pdp_config" / "identities.yaml",
                resource_file=self.bundle_dir / "pdp_config" / "resources.yaml",
                trusted_issuers=self.keys_dir / "trusted_issuers.yaml",
                security_config=self.keys_dir / "security_context.yaml",
                policy_version_store=self.state_dir / "policy_versions.json",
                audit_file=self.state_dir / "pdp_decisions.jsonl",
                pdp_private_key=self.keys_dir / "pdp_signing_private.pem",
                decision_issuer=PDP_ISSUER[0], decision_key_id=PDP_ISSUER[1],
            )
            self.pdp_runtime = build_runtime(cfg)
            pdp_client = TestClient(create_app(self.pdp_runtime, cfg))
        self.pdp_client = pdp_client

        def key(role: str) -> IssuerKey:
            issuer, key_id, _purpose = RUNTIME_ISSUERS[role]
            return IssuerKey(issuer, key_id, load_private(self.keys_dir / f"{role}_private.pem"))

        self.request_builder = SignedRequestBuilder(
            security_config=SecurityConfig(self.keys_dir / "security_context.yaml"),
            pep=key("pep"), risk=key("risk"), idp=key("idp"), workflow=key("workflow"),
            environment=self.environment, risk_model_id="zt_adk_operation_risk", risk_version="zt-adk-risk-1")
        subjects, resources = {}, {}
        env = self.ids.environment
        import yaml as _yaml

        manifest = _yaml.safe_load((self.bundle_dir / "manifest.yaml").read_text("utf-8"))
        for item in manifest["spec"]["subjects"]:
            rid = item["bindings"].get(env, {}).get("runtime_id")
            if rid:
                subjects[item["id"]] = rid
        for item in manifest["spec"]["resources"]:
            rid = item["bindings"].get(env, {}).get("runtime_id")
            if rid:
                resources[item["id"]] = rid
        self.subject_runtime = subjects
        self.resource_runtime = resources
        self.bridge = PdpBridge(http_client=pdp_client, builder=self.request_builder,
                                decision_public_key=self.keys_dir / "pdp_signing_public.pem",
                                subject_runtime_ids=subjects, resource_runtime_ids=resources)

    def _start_lease(self) -> None:
        from zt_lease.service import build_lease_components

        self.components = build_lease_components(self.bridge, current_policy_version=self.policy_version,
                                                 normal_ttl_seconds=60, critical_ttl_seconds=15, normal_max_uses=3)
        self._pep_keys: dict[str, Ed25519PrivateKey] = {}
        self._peps: dict[str, Any] = {}

    def _index_placements(self) -> None:
        self.routes: dict[tuple[str, str], dict[str, Any]] = {}
        self.tools: dict[tuple[str, str], dict[str, Any]] = {}
        self.outputs: dict[str, dict[str, Any]] = {}
        self.input_placement: dict[str, Any] | None = None
        for p in self.plan.get("logical_peps", []):
            subj, res = str(p.get("subject_runtime_id") or ""), str(p.get("resource_runtime_id") or "")
            if p["pep_type"] == "agent_route" and res.startswith("agent:"):
                self.routes[(subj, res[len("agent:"):])] = p
            elif p["pep_type"] == "input" and res == INPUT_RUNTIME:
                self.input_placement = p
            elif p["pep_type"] == "output" and res == OUTPUT_RUNTIME:
                self.outputs[subj] = p
            elif "/" in res:
                agent, _, tool = res.partition("/")
                self.tools[(agent, tool)] = p

    # ------------------------------------------------------------------ lookups
    def route_placement(self, caller: str, target: str) -> dict[str, Any] | None:
        return self.routes.get((caller, target))

    def tool_placement(self, agent: str, tool: str) -> dict[str, Any] | None:
        return self.tools.get((agent, tool))

    def output_placement(self, agent: str) -> dict[str, Any] | None:
        return self.outputs.get(agent)

    def operation(self, agent: str, tool: str) -> dict[str, Any] | None:
        return self.ids.operations.get(f"{agent}/{tool}")

    def tool_info(self, agent: str, tool: str) -> M.ToolInfo | None:
        return self.model.tool(agent, tool)

    def agent_tool_target(self, agent: str, tool: str) -> str | None:
        t = self.model.tool(agent, tool)
        return t.target_agent if t is not None and t.kind == M.AGENT_TOOL else None

    def entry_allowed(self, agent: str) -> bool:
        return (INGRESS_RUNTIME, agent) in self.routes

    # ------------------------------------------------------------------ content checks (PSL request scopes)
    def _check(self, kind: str, fields: dict[str, Any], run: RunContext, *, caller: str, target: str) -> Verdict:
        t0 = time.perf_counter_ns()
        engine = self.content_engines[kind]
        decision = engine.decide(fields)
        verdict = Verdict(allowed=decision.allowed, decision=decision.outcome,
                          reason=decision.reason() if not decision.allowed else "content_policy_ok",
                          source="CONTENT_POLICY", policy_version=self.policy_version,
                          rules=[v.rule_id for v in decision.violated], flagged=[f.rule_id for f in decision.flagged],
                          latency_ms=(time.perf_counter_ns() - t0) / 1e6)
        if decision.violated or decision.flagged:
            self.audit.write(f"CONTENT_{kind.upper()}", run=run.workflow_instance_id, trace_id=run.trace_id,
                             caller=caller, target=target, **verdict.summary(), durable=not decision.allowed)
        return verdict

    def _detector_fields(self, prefix: str, counts: Mapping[str, int]) -> dict[str, bool]:
        return {f"{prefix}.{k}": v > 0 for k, v in counts.items()}

    def check_input(self, run: RunContext, text: str, *, kind: str, entry_agent: str) -> Verdict:
        f = self.inspector.inspect(text)
        fields = {"session.present": run.session_present, "user.role": run.user_role, "entry.agent": entry_agent,
                  "input.kind": kind, "input.length": len(text),
                  "input.prompt_injection_detected": f.prompt_injection, **self._detector_fields("input.contains", f.counts)}
        return self._check("input", fields, run, caller=INGRESS_RUNTIME, target=entry_agent)

    def check_output(self, run: RunContext, agent: str, text: str) -> Verdict:
        f = self.inspector.inspect(text)
        fields = {"agent.name": agent, "user.role": run.user_role, "output.length": len(text),
                  "output.prompt_injection_detected": f.prompt_injection,
                  **self._detector_fields("output.contains", f.counts)}
        return self._check("output", fields, run, caller=agent, target=OUTPUT_RUNTIME)

    def check_agent_message(self, run: RunContext, caller: str, target: str, text: str) -> Verdict:
        f = self.inspector.inspect(text)
        fields = {"route.from": caller, "route.to": target, "message.prompt_injection_detected": f.prompt_injection,
                  **self._detector_fields("message.contains", f.counts)}
        v = self._check("agent_message", fields, run, caller=caller, target=target)
        if v.flagged and self.profile["content"].get("taint_on_flag", True):
            run.taint(f"agent_message:{caller}->{target}")
        return v

    def check_tool_call(self, run: RunContext, agent: str, tool: str) -> Verdict:
        fields = {"tool.name": tool, "tool.agent": agent, "user.role": run.user_role,
                  "session.present": run.session_present, "run.tainted": run.tainted}
        return self._check("tool_call", fields, run, caller=agent, target=tool)

    def check_tool_result(self, run: RunContext, agent: str, tool: str, text: str) -> Verdict:
        f = self.inspector.inspect(text)
        fields = {"tool.name": tool, "tool.agent": agent, "result.prompt_injection_detected": f.prompt_injection,
                  **self._detector_fields("result.contains", f.counts)}
        v = self._check("tool_result", fields, run, caller=tool, target=agent)
        if v.flagged and self.profile["content"].get("taint_on_flag", True):
            run.taint(f"tool_result:{agent}/{tool}")
        return v

    def builtin_names(self, agent: str, model_fields: set[str]) -> tuple[list[str], bool]:
        """Built-in tool names of ``agent`` behind the capability fields of a model request, and
        whether a field is not explained by any of the agent's declared built-ins."""
        names: set[str] = set()
        undeclared = False
        own = [t for t in self.model.tools.values() if t.agent == agent and t.kind == M.BUILTIN]
        for f in model_fields:
            owners = [t.name for t in own if f in (t.analysis.get("model_fields") or [t.name])]
            if owners:
                names.update(owners)
            else:
                undeclared = True
                names.add(f)
        return sorted(names), undeclared

    def check_model_request(self, run: RunContext, agent: str, function_names: list[str],
                            builtins: list[str], undeclared_builtins: bool = False) -> Verdict:
        allowed = {t.name for t in self.model.tools.values() if t.agent == agent and t.kind != M.BUILTIN}
        undeclared = sorted(set(function_names) - allowed - ADK_FRAMEWORK_FUNCTIONS)
        fields: dict[str, Any] = {"agent.name": agent, "request.undeclared_functions": bool(undeclared),
                                  "request.undeclared_builtins": bool(undeclared_builtins)}
        for b in builtins:
            if b.replace("_", "").isalnum() and b[:1].isalpha():
                fields[f"request.builtin.{b}"] = True
        v = self._check("model", fields, run, caller=agent, target="model")
        if undeclared:
            v.reason = f"{v.reason}; undeclared functions: {undeclared}"
        return v

    # ------------------------------------------------------------------ PDP authorization
    def _pep(self, placement: dict[str, Any]) -> Any:
        from zt_lease.service import register_generated_pep
        from zt_lease.pep_adapter import GeneratedPepAdapter

        pid = str(placement["physical_pep_id"])
        with self._lock:
            if pid not in self._peps:
                key = Ed25519PrivateKey.generate()
                identity = f"pep://zt-adk/{self.runtime}/{pid}"
                register_generated_pep(self.components, identity, key)
                self._peps[pid] = GeneratedPepAdapter(self.components.state_machine, self.bridge, pep_identity=identity,
                                                  pep_private_key=key,
                                                  idempotency_guard=self.components.idempotency_guard)
            return self._peps[pid]

    def risk_score(self, run: RunContext, placement: dict[str, Any]) -> int:
        op = self.operation(*str(placement.get("resource_runtime_id") or "/").split("/", 1)) \
            if "/" in str(placement.get("resource_runtime_id") or "") else None
        if op is None:
            return RISK_BASE["medium"] if placement.get("pep_type") in ("agent_route", "input", "output") \
                else RISK_BASE.get(str(placement.get("risk") or "medium"), 350)
        score = RISK_BASE[op["criticality"]]
        if op["criticality"] == "critical" and not op.get("requires_approval"):
            score = 700                     # owner declared: critical, but no approval -> high band
        if run.tainted and op["side_effect"]:
            score = max(score, 800)         # side effect after flagged content: critical band
        return score

    def auth_context(self, run: RunContext, subject_runtime: str, subject_kind: str) -> tuple[dict[str, bool], dict[str, Any]]:
        bound = REQUEST_AUTH.get()
        if bound is not None:                            # gateway: verified for THIS request
            return dict(bound.factors), dict(bound.authentication)
        if run.authentication is not None:
            return dict(run.auth_factors or {}), dict(run.authentication)
        factors = {"process_identity": True, "user_session": run.session_present}
        if self.process_spiffe_id:
            factors["process_svid"] = True
        auth = {"auth_mode": "P", "subject_kind": subject_kind, "method": "adk_plugin_in_process",
                "agent_id": subject_runtime, "workload_spiffe_id": self.process_spiffe_id}
        return factors, auth

    def _request(self, run: RunContext, placement: dict[str, Any], *, parameters: dict[str, Any],
                 idempotency_key: str | None, approvals: dict[str, Any] | None) -> Any:
        from zt_lease.models import UnifiedAuthorizationRequest

        subject_runtime = str(placement.get("subject_runtime_id") or "")
        kind = "service" if subject_runtime == INGRESS_RUNTIME else "agent"
        factors, auth = self.auth_context(run, subject_runtime, kind)
        bound = REQUEST_AUTH.get()
        identity_version = bound.identity_version if bound is not None else run.identity_version
        context: dict[str, Any] = {"trace_id": run.trace_id, "workflow_instance_id": run.workflow_instance_id,
                                   "risk_score": self.risk_score(run, placement), "auth_factors": factors,
                                   "authentication": auth, "identity_version": identity_version}
        if approvals:
            if approvals.get("human_approval"):
                context["human_approval_assertion"] = approvals["human_approval"]
            if approvals.get("secondary_authorization"):
                context["secondary_authorization_assertion"] = approvals["secondary_authorization"]
        return UnifiedAuthorizationRequest(
            subject=str(placement["subject_canonical_id"]), resource=str(placement["resource_canonical_id"]),
            action=str(placement["action"]), workflow_id=str(placement.get("workflow_id") or ""),
            audience=str(placement.get("interface_id") or placement.get("physical_pep_id") or "zt-adk"),
            endpoint=str(placement.get("interface_id") or placement.get("resource_canonical_id") or "zt-adk"),
            critical=bool(placement.get("critical")), risk=str(placement.get("risk") or "low"),
            parameters=dict(parameters), context=context, idempotency_key=idempotency_key)

    def operation_record(self, run: RunContext, placement: dict[str, Any], parameters: dict[str, Any]) -> dict[str, Any]:
        return {"subject": placement["subject_canonical_id"], "subject_runtime_id": placement["subject_runtime_id"],
                "resource": placement["resource_canonical_id"], "resource_runtime_id": placement["resource_runtime_id"],
                "action": placement["action"], "workflow_id": placement.get("workflow_id") or None,
                "workflow_instance_id": run.workflow_instance_id, "environment": self.environment,
                "parameters": dict(parameters)}

    def authorize(self, run: RunContext, placement: dict[str, Any] | None, *, parameters: dict[str, Any],
                  event: str, caller: str, target: str, idempotency_key: str | None = None,
                  approvals: dict[str, Any] | None = None) -> Verdict:
        t0 = time.perf_counter_ns()
        if placement is None:
            v = Verdict(False, "DENY", "NO_GENERATED_PEP", "LOCAL_DEFAULT_DENY", policy_version=self.policy_version)
        else:
            request = self._request(run, placement, parameters=parameters, idempotency_key=idempotency_key,
                                    approvals=approvals)
            ra = self._pep(placement).authorize(request)
            decision = ra.decision.decision.value if ra.decision is not None else ("ALLOW" if ra.allowed else "DENY")
            permit = ra.validation.permit_id if ra.validation is not None else None
            obligations: list[Any] = []
            if ra.validation is not None:
                obligations = list(ra.validation.obligations or [])
            elif ra.decision is not None:
                obligations = list(ra.decision.obligations or [])
            reason = str(ra.reason)
            rules: list[str] = []
            if ra.decision is not None:
                pdp_reason = getattr(ra.decision, "pdp_reason", "")
                if pdp_reason and not ra.allowed:
                    reason = f"{reason}: {pdp_reason}"
                rules = [r for r in (getattr(ra.decision, "pdp_matched", None) or []) if not ra.allowed]
            v = Verdict(bool(ra.allowed), decision, reason, str(ra.source), placement=placement,
                        permit_id=permit, policy_version=ra.decision.policy_version if ra.decision else None,
                        rules=rules, obligations=obligations, request=request, runtime_authorization=ra)
        v.latency_ms = (time.perf_counter_ns() - t0) / 1e6
        self.audit.write(event, run=run.workflow_instance_id, trace_id=run.trace_id, caller=caller, target=target,
                         mode=self.mode, parameters=_param_summary(parameters), **v.summary(),
                         durable=bool(placement and placement.get("critical")) or not v.allowed)
        return v

    async def authorize_operation(self, run: RunContext, placement: dict[str, Any] | None, *,
                                  parameters: dict[str, Any], event: str, caller: str, target: str,
                                  idempotency_key: str | None, agent: str, tool: str) -> Verdict:
        """PDP authorization with the approval flow for MANUAL_REVIEW decisions."""
        if placement is None:
            return self.authorize(run, None, parameters=parameters, event=event, caller=caller, target=target)
        op_record = self.operation_record(run, placement, parameters)
        req_hash = operation_hash(op_record)
        stored = None if req_hash in run.approved_ops else self._stored_approvals(req_hash)
        approvals = run.approved_ops.get(req_hash) or (stored[1] if stored else None)
        v = self.authorize(run, placement, parameters=parameters, event=event, caller=caller, target=target,
                           idempotency_key=idempotency_key, approvals=approvals)
        if v.decision != "MANUAL_REVIEW":
            if stored is not None and v.allowed:
                # an approval granted after an earlier call of this run was held: consumed now
                v.approval_id = stored[0]
                self.approvals.mark(stored[0], "used")
                self.audit.write("APPROVAL_APPLIED", run=run.workflow_instance_id, approval_id=stored[0],
                                 allowed=True, decision=v.decision, durable=True)
            return v
        op = self.operation(agent, tool) or {}
        purposes = ["human_approval"] + (["secondary_authorization"] if op.get("secondary_approval") else [])
        cfg = self.profile["approvals"]
        request = self.approvals.file_request(
            operation=op_record, request_hash=req_hash, purposes=purposes, app=self.model.app_name, agent=agent,
            tool=tool, reason=v.reason, trace_id=run.trace_id, ttl_seconds=max(60, int(cfg["lifetime_seconds"]) * 4))
        self.audit.write("APPROVAL_REQUESTED", run=run.workflow_instance_id, trace_id=run.trace_id, agent=agent,
                         tool=tool, approval_id=request.approval_id, purposes=purposes, request_hash=req_hash,
                         durable=True)
        decisions = await self.approvals.wait(request.approval_id, purposes, timeout=float(cfg["wait_seconds"]),
                                              poll=float(cfg["poll_seconds"]))
        if any(d.get("decision") == "DENY" for d in decisions.values()):
            self.audit.write("APPROVAL_DENIED", run=run.workflow_instance_id, approval_id=request.approval_id,
                             durable=True)
            return Verdict(False, "DENY", f"approval_denied:{request.approval_id}", "APPROVAL",
                           placement=placement, approval_id=request.approval_id, policy_version=self.policy_version)
        if not all(p in decisions for p in purposes):
            return Verdict(False, "MANUAL_REVIEW", f"approval_pending:{request.approval_id}", "APPROVAL",
                           placement=placement, approval_id=request.approval_id, policy_version=self.policy_version)
        assertions = {"human_approval": decisions.get("human_approval"),
                      "secondary_authorization": decisions.get("secondary_authorization")}
        run.approved_ops[req_hash] = assertions
        v = self.authorize(run, placement, parameters=parameters, event=event, caller=caller, target=target,
                           idempotency_key=idempotency_key, approvals=assertions)
        v.approval_id = request.approval_id
        if v.allowed:
            self.approvals.mark(request.approval_id, "used")
        run.approved_ops.pop(req_hash, None)
        self.audit.write("APPROVAL_APPLIED", run=run.workflow_instance_id, approval_id=request.approval_id,
                         allowed=v.allowed, decision=v.decision, durable=True)
        return v

    def _stored_approvals(self, req_hash: str) -> tuple[str, dict[str, Any]] | None:
        """(approval id, assertions) of an approval granted earlier (e.g. after a held call) for
        exactly this operation and not used yet."""
        from datetime import datetime, timezone

        for req in self.approvals.find_for_hash(req_hash):
            if req.status != "approved":
                continue
            d = self.approvals.decisions_for(req.approval_id)
            purposes = req.record.get("purposes", [])
            if not all(p in d and d[p].get("decision") == "ALLOW" for p in purposes):
                continue
            exp = min(datetime.fromisoformat(d[p]["expires_at"].replace("Z", "+00:00")) for p in purposes)
            if exp <= datetime.now(timezone.utc):
                continue
            return req.approval_id, {"human_approval": d.get("human_approval"),
                                     "secondary_authorization": d.get("secondary_authorization")}
        return None

    def should_execute(self, verdict: Verdict, *, critical: bool = False) -> bool:
        if verdict.allowed:
            return True
        if self.mode == "enforce":
            return False
        return not critical                  # shadow mode: critical operations still fail closed

    # ------------------------------------------------------------------ workflow monitor
    def admit_route(self, run: RunContext, caller: str, target: str, verdict: Verdict) -> None:
        self._admit(run, verdict, "agent_routed", {"route.from": caller, "route.to": target})

    def _admit(self, run: RunContext, verdict: Verdict, event: str, fields: dict[str, Any]) -> None:
        if not verdict.allowed or WORKFLOW_SCOPE not in self.monitor.machines:
            return
        from zt_psl.runtime import CapacityExceeded

        key = (run.workflow_instance_id,)
        try:
            res = self.monitor.admit([(WORKFLOW_SCOPE, key, event, self.monitor.bind(WORKFLOW_SCOPE, event, fields))])
        except CapacityExceeded as exc:
            verdict.allowed, verdict.decision, verdict.source = False, "DENY", "PSL_WORKFLOW_MONITOR"
            verdict.reason = f"psl_workflow_capacity:{exc}"
            return
        if not res.ok:
            ids = sorted({x.property_id for x in res.violations})
            verdict.allowed, verdict.decision, verdict.source = False, "DENY", "PSL_WORKFLOW_MONITOR"
            verdict.reason = "psl_workflow_violation:" + ",".join(ids)
            verdict.rules = ids
            self.audit.write("WORKFLOW_VIOLATION", run=run.workflow_instance_id, monitor_event=event, rules=ids,
                             fields=fields, durable=True)

    def observe(self, run: RunContext, event: str, fields: dict[str, Any]) -> None:
        if WORKFLOW_SCOPE not in self.monitor.machines:
            return
        self.monitor.observe([(WORKFLOW_SCOPE, (run.workflow_instance_id,), event,
                               self.monitor.bind(WORKFLOW_SCOPE, event, fields))])

    def close_run(self, run: RunContext) -> list[str]:
        if WORKFLOW_SCOPE not in self.monitor.machines:
            return []
        violations = self.monitor.close(WORKFLOW_SCOPE, (run.workflow_instance_id,))
        ids = sorted({v.property_id for v in violations})
        if ids:
            self.audit.write("WORKFLOW_CLOSE_VIOLATION", run=run.workflow_instance_id, rules=ids, durable=True)
        return ids

    # ------------------------------------------------------------------ tool lifecycle
    async def begin_tool(self, run: RunContext, *, agent: str, tool: str, args: dict[str, Any],
                         call_id: str) -> PendingTool:
        placement = self.tool_placement(agent, tool)
        op = self.operation(agent, tool) or {}
        critical = bool(placement and placement.get("critical"))
        check = self.check_tool_call(run, agent, tool)
        if not check.allowed:
            return PendingTool(check, None, None, [], False, run, agent, tool, critical)
        idem = f"adk:{run.workflow_instance_id}:{agent}:{call_id or uuid.uuid4().hex}"
        v = await self.authorize_operation(run, placement, parameters=args, event="TOOL_AUTHORIZATION", caller=agent,
                                           target=tool, idempotency_key=idem if op.get("side_effect", True) else None,
                                           agent=agent, tool=tool)
        if v.allowed:
            self._admit(run, v, "tool_admitted", {"tool.agent": agent, "tool.name": tool})
        if not v.allowed or placement is None or v.request is None:
            return PendingTool(v, None, v.request, v.obligations, False, run, agent, tool, critical)
        pep = self._pep(placement)
        try:
            pep._check_pre_obligations(v.obligations, v.request)
            pep.idempotency_guard.reserve(v.request.idempotency_key, v.request.request_hash(), required=v.request.critical)
        except Exception as exc:
            v.allowed, v.decision, v.source, v.reason = False, "DENY", "OBLIGATION", f"{type(exc).__name__}: {exc}"
            self.audit.write("TOOL_OBLIGATION_REJECTED", run=run.workflow_instance_id, agent=agent, tool=tool,
                             reason=v.reason, durable=True)
            return PendingTool(v, pep, v.request, v.obligations, False, run, agent, tool, critical)
        return PendingTool(v, pep, v.request, v.obligations, True, run, agent, tool, critical)

    def finish_tool(self, pending: PendingTool, result: Any) -> tuple[Any, Verdict | None]:
        """Commit, observe, post-obligations, then the tool-result content check."""
        if pending.reserved and pending.pep is not None:
            pending.pep.idempotency_guard.commit(pending.request.idempotency_key)
            status = _result_status(result)
            self.observe(pending.run, "tool_succeeded", {"tool.agent": pending.agent, "tool.name": pending.tool,
                                                         "result.status": status})
            result = self.apply_post_obligations(pending.pep, result, pending.obligations)
        from .content import text_of

        check = self.check_tool_result(pending.run, pending.agent, pending.tool, text_of(result))
        self.audit.write("TOOL_EXECUTED", run=pending.run.workflow_instance_id, trace_id=pending.run.trace_id,
                         agent=pending.agent, tool=pending.tool, permit_id=pending.verdict.permit_id,
                         result_sha256=hashlib.sha256(json.dumps(result, sort_keys=True, default=str).encode()).hexdigest(),
                         result_policy=check.decision, durable=pending.critical)
        return result, check

    def deny_undeclared_call(self, run: RunContext, agent: str, name: str, args: Mapping[str, Any]) -> Verdict:
        """The model called a function ADK does not offer this agent (none of its tools, not
        a transfer it may make). Nothing can run; the attempt is refused, audited, and -- as a
        sign of a manipulated model -- taints the run like flagged content does."""
        target = str(args.get("agent_name", "") or "") if name == "transfer_to_agent" else ""
        reason = (f"UNDECLARED_FUNCTION: {agent} may not call {name}"
                  + (f" (transfer to {target!r} is not one ADK offers this agent)" if target else ""))
        v = Verdict(False, "DENY", reason, "LOCAL_DEFAULT_DENY", policy_version=self.policy_version)
        if self.profile["content"].get("taint_on_flag", True):
            run.taint(f"undeclared_function:{agent}/{name}")
        self.audit.write("UNDECLARED_FUNCTION_CALL", run=run.workflow_instance_id, trace_id=run.trace_id,
                         caller=agent, target=target or name, parameters=_param_summary(dict(args)),
                         mode=self.mode, **v.summary(), durable=True)
        return v

    def abort_tool(self, pending: PendingTool | None, error: str = "") -> None:
        if pending is None:
            return
        if pending.reserved and pending.pep is not None:
            pending.pep.idempotency_guard.abort(pending.request.idempotency_key)
            self.observe(pending.run, "tool_failed", {"tool.agent": pending.agent, "tool.name": pending.tool})
        self.audit.write("TOOL_FAILED", run=pending.run.workflow_instance_id, agent=pending.agent, tool=pending.tool,
                         error=error[:300], durable=pending.critical)

    @staticmethod
    def apply_post_obligations(pep: Any, result: Any, obligations: list[Any]) -> Any:
        direct = pep._apply_post_obligations(result, obligations)
        if direct is not result:
            return direct

        def mask_json_string(value: Any) -> Any:
            if not isinstance(value, str):
                return value
            text = value.strip()
            if not text or text[0] not in "[{":
                return value
            try:
                decoded = json.loads(text)
            except ValueError:
                return value
            masked = pep._apply_post_obligations(decoded, obligations)
            return value if masked == decoded else json.dumps(masked, ensure_ascii=False)

        if isinstance(result, dict):
            out = {k: mask_json_string(v) for k, v in result.items()}
            return out if out != result else result
        return mask_json_string(result)

    def close(self) -> None:
        try:
            close = getattr(self.pdp_client, "close", None)
            if close:
                close()
        except Exception:
            pass


def _param_summary(parameters: Mapping[str, Any]) -> dict[str, Any]:
    raw = json.dumps(parameters, sort_keys=True, default=str).encode("utf-8")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "keys": sorted(str(k) for k in parameters), "bytes": len(raw)}


def _result_status(result: Any) -> str:
    value = result
    for _ in range(3):
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                return ""
            continue
        if isinstance(value, dict):
            if "status" in value:
                return str(value["status"])[:64]
            if "result" in value:
                value = value["result"]
                continue
        return ""
    return ""
