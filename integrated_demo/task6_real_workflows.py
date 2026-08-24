from __future__ import annotations

import json
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from uuid import uuid4

from zt_task5.models import UnifiedAuthorizationRequest
from zt_task5.task3_adapter import PEPDenied, Task3PEPAdapter

from testbed_runtime import TestbedToolError, TestbedToolRuntime


class Task6IntegrationError(RuntimeError):
    pass


class DirectProtectedToolAccessDenied(PermissionError):
    pass


@dataclass(frozen=True)
class ToolStep:
    step_id: str
    subject_runtime_id: str
    tool_id: str
    parameters: dict[str, Any]
    critical: bool = False
    side_effect: bool = False
    approvals: bool = False
    change_ticket: str | None = None


@dataclass(frozen=True)
class RouteStep:
    step_id: str
    subject_runtime_id: str
    target_runtime_id: str


@dataclass(frozen=True)
class WorkflowDefinition:
    name: str
    workflow_id: str
    routes: tuple[RouteStep, ...] = ()
    tools: tuple[ToolStep, ...] = ()


@dataclass
class WorkflowRunResult:
    workflow: str
    workflow_id: str
    trace_id: str
    workflow_instance_id: str
    mode: str
    passed: bool
    duration_ms: float
    steps: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


def _json_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return value
    try:
        return json.loads(text)
    except Exception:
        return value


def _safe_summary(value: Any) -> Any:
    value = _json_value(value)
    if isinstance(value, dict):
        keep = (
            "status",
            "transaction_id",
            "batch_id",
            "report_id",
            "exception_id",
            "ready",
            "difference",
            "decision",
            "error",
        )
        compact = {key: value[key] for key in keep if key in value}
        return compact or {"type": "dict", "keys": sorted(value)[:12]}
    if isinstance(value, list):
        return {"type": "list", "length": len(value)}
    text = str(value)
    return text if len(text) <= 300 else text[:297] + "..."


def _tool_name_from_placement(placement: dict[str, Any]) -> str:
    interface_id = str(placement.get("interface_id") or "")
    if interface_id:
        return interface_id.rsplit(".", 1)[-1]
    return str(placement.get("resource_runtime_id") or "")


def find_tool_placement(
    plan_json: dict[str, Any],
    *,
    subject_runtime_id: str,
    tool_id: str,
) -> dict[str, Any]:
    candidates: list[tuple[int, dict[str, Any]]] = []
    for placement in plan_json.get("logical_peps", []):
        if str(placement.get("subject_runtime_id") or "") != subject_runtime_id:
            continue
        score = 0
        interface_id = str(placement.get("interface_id") or "")
        resource_runtime = str(placement.get("resource_runtime_id") or "")
        edge_id = str(placement.get("edge_id") or "")
        placement_id = str(placement.get("placement_id") or "")
        if interface_id.rsplit(".", 1)[-1] == tool_id:
            score += 100
        if resource_runtime == tool_id:
            score += 80
        if edge_id.endswith("_" + tool_id) or f"_{tool_id}_" in edge_id:
            score += 60
        if placement_id.endswith("." + tool_id) or placement_id.endswith("_" + tool_id):
            score += 40
        if score:
            candidates.append((score, placement))
    if not candidates:
        raise Task6IntegrationError(
            f"No Task 3 placement for runtime subject={subject_runtime_id!r}, tool={tool_id!r}"
        )
    candidates.sort(key=lambda item: (-item[0], str(item[1].get("placement_id") or "")))
    return candidates[0][1]


def find_route_placement(
    plan_json: dict[str, Any],
    *,
    subject_runtime_id: str,
    target_runtime_id: str,
) -> dict[str, Any] | None:
    candidates: list[dict[str, Any]] = []
    for placement in plan_json.get("logical_peps", []):
        if str(placement.get("subject_runtime_id") or "") != subject_runtime_id:
            continue
        if str(placement.get("resource_runtime_id") or "") != target_runtime_id:
            continue
        if str(placement.get("pep_type") or "") == "agent_route" or str(
            placement.get("resource_type") or ""
        ) == "agent":
            candidates.append(placement)
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: str(item.get("placement_id") or ""))[0]


def build_default_workflows(inputs: dict[str, Any]) -> list[WorkflowDefinition]:
    customer = dict(inputs.get("customer_transaction") or {})
    fraud = dict(inputs.get("fraud_compliance") or {})
    eod = dict(inputs.get("back_office_eod") or {})

    transfer = dict(customer.get("transfer") or {})
    transfer.setdefault("source_account", "CHK-002")
    transfer.setdefault("destination_account", "EXT-998")
    transfer.setdefault("amount", 1.25)
    transfer.setdefault("memo", "Task 6 protected workflow integration")
    transfer.setdefault("customer_id", "CUST-002")

    customer_id = str(fraud.get("customer_id") or "CUST-001")
    transaction_id = str(fraud.get("transaction_id") or "TXN-1001")
    batch_id = str(eod.get("batch_id") or "EOD-2026-04-21-CLEAN")

    return [
        WorkflowDefinition(
            name="customer_transaction",
            workflow_id="workflow.front_office.customer_transaction",
            routes=(
                RouteStep(
                    "route.customer_service_to_transaction_processing",
                    "customer_service_chatbot_workflow",
                    "transaction_processing_agent",
                ),
            ),
            tools=(
                ToolStep(
                    "transaction_processing.execute_transfer",
                    "transaction_processing_agent",
                    "execute_transfer",
                    transfer,
                    critical=True,
                    side_effect=True,
                    approvals=True,
                ),
            ),
        ),
        WorkflowDefinition(
            name="fraud_compliance",
            workflow_id="workflow.front_office.fraud_review",
            routes=(
                RouteStep(
                    "route.fraud_workflow_to_monitoring",
                    "front_office_transaction_workflow",
                    "transaction_monitoring_agent",
                ),
                RouteStep(
                    "route.fraud_workflow_to_fraud",
                    "front_office_transaction_workflow",
                    "fraud_detection_agent",
                ),
                RouteStep(
                    "route.fraud_workflow_to_compliance",
                    "front_office_transaction_workflow",
                    "compliance_agent",
                ),
                RouteStep(
                    "route.fraud_workflow_to_decision",
                    "front_office_transaction_workflow",
                    "decision_making_agent",
                ),
            ),
            tools=(
                ToolStep(
                    "monitoring.get_transaction_context",
                    "transaction_monitoring_agent",
                    "get_transaction_context",
                    {"transaction_id": transaction_id},
                ),
                ToolStep(
                    "monitoring.get_customer_context",
                    "transaction_monitoring_agent",
                    "get_customer_context",
                    {"customer_id": customer_id},
                ),
                ToolStep(
                    "monitoring.list_recent_transactions",
                    "transaction_monitoring_agent",
                    "list_recent_transactions",
                    {"customer_id": customer_id, "limit": 5},
                ),
                ToolStep(
                    "fraud.get_transaction_context",
                    "fraud_detection_agent",
                    "get_transaction_context",
                    {"transaction_id": transaction_id},
                ),
                ToolStep(
                    "compliance.search_policies",
                    "compliance_agent",
                    "search_policies",
                    {"query": "AML KYC sanctions suspicious wire transfer escalation"},
                ),
            ),
        ),
        WorkflowDefinition(
            name="back_office_eod",
            workflow_id="workflow.back_office.eod_processing",
            routes=(
                RouteStep(
                    "route.eod_workflow_to_validation",
                    "back_office_eod_workflow",
                    "validation_checkpoint_agent",
                ),
                RouteStep(
                    "route.eod_workflow_to_processing",
                    "back_office_eod_workflow",
                    "eod_processing_agent",
                ),
                RouteStep(
                    "route.eod_workflow_to_ledger",
                    "back_office_eod_workflow",
                    "ledger_update_agent",
                ),
                RouteStep(
                    "route.eod_workflow_to_reconciliation",
                    "back_office_eod_workflow",
                    "reconciliation_agent",
                ),
            ),
            tools=(
                ToolStep(
                    "validation.validate_eod_readiness",
                    "validation_checkpoint_agent",
                    "validate_eod_readiness",
                    {"batch_id": batch_id},
                ),
                ToolStep(
                    "processing.get_eod_batch",
                    "eod_processing_agent",
                    "get_eod_batch",
                    {"batch_id": batch_id},
                ),
                ToolStep(
                    "ledger.apply_ledger_updates",
                    "ledger_update_agent",
                    "apply_ledger_updates",
                    {
                        "batch_id": batch_id,
                        "posting_instructions": "Task 6 protected EOD posting",
                    },
                    critical=True,
                    side_effect=True,
                    approvals=True,
                    change_ticket="CHG-TASK6-EOD-001",
                ),
                ToolStep(
                    "reconciliation.get_reconciliation_data",
                    "reconciliation_agent",
                    "get_reconciliation_data",
                    {"batch_id": batch_id},
                ),
            ),
        ),
    ]


def build_task6_policy_bundle(
    plan_json: dict[str, Any],
    workflows: Iterable[WorkflowDefinition],
) -> dict[str, Any]:
    """Generate narrowly-scoped runtime policies for the three M6 workflows.

    Existing high-priority Task 4 DENY/MANUAL_REVIEW policies still win. The
    generated policies only fill scanner-discovered representative workflow
    operations that do not yet have a hand-authored prototype policy.
    """
    policies: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(placement: dict[str, Any], workflow_id: str, suffix: str) -> None:
        subject = str(placement["subject_canonical_id"])
        resource = str(placement["resource_canonical_id"])
        action = str(placement["action"])
        key = (subject, resource, action, workflow_id)
        if key in seen:
            return
        seen.add(key)
        clean = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in suffix)
        policies.append(
            {
                "id": f"policy.task6.{clean}",
                "description": "Task 6 representative real-testbed workflow operation.",
                # Lower than hand-authored Task 4 policies so existing DENY,
                # masking, manual-review and other obligations always take precedence.
                "priority": 120,
                "effect": "ALLOW_WITH_OBLIGATIONS",
                "match": {
                    "subjects": [subject],
                    "resources": [resource],
                    "actions": [action],
                    "workflows": [workflow_id],
                },
                "obligations": [
                    {
                        "type": "enhanced_logging",
                        "parameters": {"reason": "task6_real_workflow"},
                    }
                ],
                "enabled": True,
            }
        )

    for workflow in workflows:
        for route in workflow.routes:
            placement = find_route_placement(
                plan_json,
                subject_runtime_id=route.subject_runtime_id,
                target_runtime_id=route.target_runtime_id,
            )
            if placement is not None:
                add(placement, workflow.workflow_id, route.step_id)
        for step in workflow.tools:
            placement = find_tool_placement(
                plan_json,
                subject_runtime_id=step.subject_runtime_id,
                tool_id=step.tool_id,
            )
            add(placement, workflow.workflow_id, step.step_id)
        if workflow.name == "back_office_eod":
            for subject_runtime_id, tool_id, suffix in (
                ("report_writing_agent", "store_report", "report.store_report"),
                ("exception_agent", "create_exception_case", "exception.create_exception_case"),
            ):
                placement = find_tool_placement(
                    plan_json,
                    subject_runtime_id=subject_runtime_id,
                    tool_id=tool_id,
                )
                add(placement, workflow.workflow_id, suffix)

    return {
        "apiVersion": "ztb/v1alpha1",
        "kind": "PolicyBundle",
        "metadata": {
            "id": "bundle.task6_real_workflows",
            "version": "1.0.0",
            "domain": "integration",
            "status": "provisional",
        },
        "policies": policies,
    }


class ProtectedTestbedRuntime:
    """Runtime guard around original Citi P3 tool functions.

    A protected function can only execute while the Task 6 PEP operation context
    is active. This makes the direct-import bypass test meaningful without
    changing the original Citi P3 source files.
    """

    _authorized: ContextVar[bool] = ContextVar("zt_task6_authorized_tool_call", default=False)

    def __init__(self, base: TestbedToolRuntime) -> None:
        self.base = base
        self._guards: dict[str, tuple[Any, Any]] = {}

    def install(self, tool_ids: Iterable[str]) -> None:
        for tool_id in sorted(set(tool_ids)):
            if tool_id in self._guards or not self.base.available(tool_id):
                continue
            file_path = self.base._resolve_file(tool_id)  # integration adapter internal API
            module = self.base._load_module(file_path)
            original = getattr(module, tool_id, None)
            if original is None:
                raise TestbedToolError(f"{tool_id!r} not found in imported module {file_path}")
            original = self.base._unwrap_callable(original)

            def guarded(*args: Any, __tool=tool_id, __original=original, **kwargs: Any) -> Any:
                if not self._authorized.get():
                    raise DirectProtectedToolAccessDenied(
                        f"direct access to protected tool {__tool!r} was blocked; use a generated PEP"
                    )
                self.base._initialize_tool_runtime(__original)
                return __original(*args, **kwargs)

            guarded.__name__ = getattr(original, "__name__", tool_id)
            guarded.__doc__ = getattr(original, "__doc__", None)
            setattr(module, tool_id, guarded)
            self._guards[tool_id] = (module, original)

    def restore(self) -> None:
        for tool_id, (module, original) in list(self._guards.items()):
            setattr(module, tool_id, original)
        self._guards.clear()

    @contextmanager
    def authorized_operation(self):
        token = self._authorized.set(True)
        try:
            yield
        finally:
            self._authorized.reset(token)

    def invoke_via_pep(self, tool_id: str, parameters: dict[str, Any]) -> Any:
        with self.authorized_operation():
            return self.base.invoke(tool_id, parameters)

    def direct_invoke(self, tool_id: str, parameters: dict[str, Any]) -> Any:
        # No authorized context on purpose. Used by the direct-bypass M6 test.
        return self.base.invoke(tool_id, parameters)


class Task6WorkflowRunner:
    def __init__(
        self,
        *,
        plan_json: dict[str, Any],
        build_pep: Callable[[dict[str, Any]], Task3PEPAdapter],
        request_builder: Callable[..., UnifiedAuthorizationRequest],
        runtime: ProtectedTestbedRuntime,
        output_dir: Path,
    ) -> None:
        self.plan_json = plan_json
        self.build_pep = build_pep
        self.request_builder = request_builder
        self.runtime = runtime
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.output_dir / "task6_workflow_audit.jsonl"
        self.audit_path.write_text("", encoding="utf-8")

    def _append_audit(self, event: dict[str, Any]) -> None:
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")

    @staticmethod
    def _obligations(authorization: Any) -> list[Any]:
        if authorization.validation is not None:
            return list(authorization.validation.obligations or [])
        if authorization.decision is not None:
            return list(authorization.decision.obligations or [])
        return []

    def _execute_once(
        self,
        *,
        placement: dict[str, Any],
        request: UnifiedAuthorizationRequest,
        operation: Callable[[], Any],
        trace_id: str,
        workflow_instance_id: str,
        step_id: str,
        mode: str,
        allow_shadow_execution: bool,
    ) -> tuple[bool, Any, dict[str, Any]]:
        pep = self.build_pep(placement)
        started = time.perf_counter_ns()
        authorization = pep.authorize(request)
        auth_done = time.perf_counter_ns()
        executed = False
        execution_result: Any = None
        execution_error: str | None = None
        would_block = not authorization.allowed

        try:
            if authorization.allowed:
                obligations = self._obligations(authorization)
                pep._check_pre_obligations(obligations, request)
                pep.idempotency_guard.reserve(
                    request.idempotency_key,
                    request.request_hash(),
                    required=request.critical,
                )
                try:
                    execution_result = operation()
                except Exception:
                    pep.idempotency_guard.abort(request.idempotency_key)
                    raise
                pep.idempotency_guard.commit(request.idempotency_key)
                execution_result = pep._apply_post_obligations(execution_result, obligations)
                executed = True
            elif mode == "shadow" and allow_shadow_execution:
                execution_result = operation()
                executed = True
            elif mode == "enforce":
                raise PEPDenied(authorization.reason)
        except Exception as exc:
            execution_error = f"{type(exc).__name__}: {exc}"
            if mode == "enforce" or authorization.allowed:
                # Expected enforcement denials are represented by the caller.
                if not isinstance(exc, PEPDenied):
                    raise
        finished = time.perf_counter_ns()

        decision = (
            authorization.decision.decision.value
            if authorization.decision is not None
            else ("ALLOW" if authorization.allowed else "DENY")
        )
        policy_version = (
            authorization.decision.policy_version
            if authorization.decision is not None
            else None
        )
        permit_id = (
            authorization.validation.permit_id
            if authorization.validation is not None
            else None
        )
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "trace_id": trace_id,
            "workflow_id": request.workflow_id,
            "workflow_instance_id": workflow_instance_id,
            "step_id": step_id,
            "caller_identity": request.subject,
            "caller_runtime_id": placement.get("subject_runtime_id"),
            "target_resource": request.resource,
            "target_runtime_id": placement.get("resource_runtime_id"),
            "requested_action": request.action,
            "pep_id": placement.get("physical_pep_id"),
            "logical_pep_id": placement.get("placement_id"),
            "pdp_decision": decision,
            "authorization_allowed": bool(authorization.allowed),
            "authorization_source": authorization.source,
            "policy_version": policy_version,
            "permit_id": permit_id,
            "execution_result": "EXECUTED" if executed else "BLOCKED",
            "result_summary": _safe_summary(execution_result) if executed else None,
            "error": execution_error,
            "reason": authorization.reason,
            "mode": mode,
            "would_block": would_block,
            "authorization_latency_ms": round((auth_done - started) / 1_000_000, 6),
            "step_latency_ms": round((finished - started) / 1_000_000, 6),
        }
        self._append_audit(event)
        return authorization.allowed, execution_result, event

    def _request(
        self,
        placement: dict[str, Any],
        *,
        parameters: dict[str, Any],
        workflow_id: str,
        trace_id: str,
        workflow_instance_id: str,
        approvals: bool = False,
        change_ticket: str | None = None,
        subject_override: str | None = None,
        idempotency_key: str | None = None,
    ) -> UnifiedAuthorizationRequest:
        context: dict[str, Any] = {
            "trace_id": trace_id,
            "workflow_instance_id": workflow_instance_id,
            "risk_score": 900 if placement.get("critical") else 350,
            "auth_factors": {"workload_identity": True, "user_session": True},
        }
        if approvals:
            context["with_human_approval"] = True
            context["with_secondary_authorization"] = True
        if change_ticket:
            context["change_ticket"] = change_ticket
        request = self.request_builder(
            placement,
            parameters=parameters,
            context=context,
            idempotency_key=idempotency_key,
        )
        updates: dict[str, Any] = {"workflow_id": workflow_id}
        if subject_override:
            updates["subject"] = subject_override
        return request.model_copy(update=updates)

    def _run_route(
        self,
        workflow: WorkflowDefinition,
        route: RouteStep,
        *,
        trace_id: str,
        workflow_instance_id: str,
        mode: str,
    ) -> dict[str, Any] | None:
        placement = find_route_placement(
            self.plan_json,
            subject_runtime_id=route.subject_runtime_id,
            target_runtime_id=route.target_runtime_id,
        )
        if placement is None:
            # A workflow can still be protected at its concrete tool/API boundary.
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "trace_id": trace_id,
                "workflow_id": workflow.workflow_id,
                "workflow_instance_id": workflow_instance_id,
                "step_id": route.step_id,
                "caller_runtime_id": route.subject_runtime_id,
                "target_runtime_id": route.target_runtime_id,
                "execution_result": "NOT_DISCOVERED",
                "mode": mode,
                "note": "No agent-route placement was emitted for this custom orchestration edge.",
            }
            self._append_audit(event)
            return event
        request = self._request(
            placement,
            parameters={"target_agent": route.target_runtime_id},
            workflow_id=workflow.workflow_id,
            trace_id=trace_id,
            workflow_instance_id=workflow_instance_id,
        )
        _, _, event = self._execute_once(
            placement=placement,
            request=request,
            operation=lambda: {"route": "accepted", "target": route.target_runtime_id},
            trace_id=trace_id,
            workflow_instance_id=workflow_instance_id,
            step_id=route.step_id,
            mode=mode,
            allow_shadow_execution=True,
        )
        return event

    def run_workflow(self, workflow: WorkflowDefinition, *, mode: str = "enforce") -> WorkflowRunResult:
        if mode not in {"enforce", "shadow"}:
            raise ValueError("mode must be enforce or shadow")
        trace_id = f"trace-task6-{uuid4()}"
        workflow_instance_id = f"{workflow.name}-{uuid4()}"
        started = time.perf_counter_ns()
        step_events: list[dict[str, Any]] = []
        passed = True
        error: str | None = None
        tool_results: dict[str, Any] = {}

        try:
            for route in workflow.routes:
                event = self._run_route(
                    workflow,
                    route,
                    trace_id=trace_id,
                    workflow_instance_id=workflow_instance_id,
                    mode=mode,
                )
                if event is not None:
                    step_events.append(event)
                    if event.get("execution_result") == "NOT_DISCOVERED":
                        raise Task6IntegrationError(f"required agent-route PEP was not discovered: {route.step_id}")
                    if event.get("execution_result") == "BLOCKED" and mode == "enforce":
                        raise Task6IntegrationError(f"authorized route was blocked: {route.step_id}")

            for step in workflow.tools:
                placement = find_tool_placement(
                    self.plan_json,
                    subject_runtime_id=step.subject_runtime_id,
                    tool_id=step.tool_id,
                )
                tool_params = dict(step.parameters)
                auth_params = dict(tool_params)
                idem = None
                if placement.get("critical") or step.critical:
                    idem = f"idem-{workflow.name}-{step.step_id}-{uuid4()}"
                    auth_params.setdefault("change_ticket", step.change_ticket or f"CHG-{uuid4().hex[:10].upper()}")
                request = self._request(
                    placement,
                    parameters=auth_params,
                    workflow_id=workflow.workflow_id,
                    trace_id=trace_id,
                    workflow_instance_id=workflow_instance_id,
                    approvals=step.approvals or bool(placement.get("critical")),
                    change_ticket=auth_params.get("change_ticket"),
                    idempotency_key=idem,
                )
                allowed, value, event = self._execute_once(
                    placement=placement,
                    request=request,
                    operation=lambda tid=step.tool_id, p=tool_params: self.runtime.invoke_via_pep(tid, p),
                    trace_id=trace_id,
                    workflow_instance_id=workflow_instance_id,
                    step_id=step.step_id,
                    mode=mode,
                    allow_shadow_execution=not (step.side_effect or placement.get("side_effect")),
                )
                step_events.append(event)
                if not allowed and mode == "enforce":
                    raise Task6IntegrationError(
                        f"authorized workflow step was denied: {step.step_id}: {event.get('reason')}"
                    )
                tool_results[step.step_id] = _json_value(value)

            # The real BackOfficeEodWorkflowAgent branches to report or exception
            # after reconciliation. Mirror that deterministic branch here using the
            # original tool outputs so the business path remains repeatable.
            if workflow.name == "back_office_eod":
                rec = tool_results.get("reconciliation.get_reconciliation_data") or {}
                difference = float(rec.get("difference", 0.0)) if isinstance(rec, dict) else 0.0
                if abs(difference) < 1e-9:
                    branch = ToolStep(
                        "report.store_report",
                        "report_writing_agent",
                        "store_report",
                        {
                            "batch_id": str(workflow.tools[0].parameters["batch_id"]),
                            "report_body": "Task 6 protected EOD reconciliation report",
                        },
                        critical=True,
                        side_effect=True,
                        approvals=True,
                    )
                else:
                    branch = ToolStep(
                        "exception.create_exception_case",
                        "exception_agent",
                        "create_exception_case",
                        {
                            "batch_id": str(workflow.tools[0].parameters["batch_id"]),
                            "mismatch_summary": f"Task 6 reconciliation difference={difference}",
                        },
                        critical=True,
                        side_effect=True,
                        approvals=True,
                    )
                placement = find_tool_placement(
                    self.plan_json,
                    subject_runtime_id=branch.subject_runtime_id,
                    tool_id=branch.tool_id,
                )
                tool_params = dict(branch.parameters)
                auth_params = dict(tool_params)
                auth_params.setdefault("change_ticket", f"CHG-{uuid4().hex[:10].upper()}")
                request = self._request(
                    placement,
                    parameters=auth_params,
                    workflow_id=workflow.workflow_id,
                    trace_id=trace_id,
                    workflow_instance_id=workflow_instance_id,
                    approvals=True,
                    change_ticket=auth_params["change_ticket"],
                    idempotency_key=f"idem-{workflow.name}-{branch.step_id}-{uuid4()}",
                )
                allowed, _, event = self._execute_once(
                    placement=placement,
                    request=request,
                    operation=lambda tid=branch.tool_id, p=tool_params: self.runtime.invoke_via_pep(tid, p),
                    trace_id=trace_id,
                    workflow_instance_id=workflow_instance_id,
                    step_id=branch.step_id,
                    mode=mode,
                    allow_shadow_execution=False,
                )
                step_events.append(event)
                if not allowed and mode == "enforce":
                    raise Task6IntegrationError(
                        f"authorized EOD branch was denied: {branch.step_id}: {event.get('reason')}"
                    )
        except Exception as exc:
            passed = False
            error = f"{type(exc).__name__}: {exc}"

        finished = time.perf_counter_ns()
        return WorkflowRunResult(
            workflow=workflow.name,
            workflow_id=workflow.workflow_id,
            trace_id=trace_id,
            workflow_instance_id=workflow_instance_id,
            mode=mode,
            passed=passed,
            duration_ms=round((finished - started) / 1_000_000, 6),
            steps=step_events,
            error=error,
        )

    def run_negative_tests(self) -> list[dict[str, Any]]:
        """M6 enforcement, shadow-mode and direct-bypass checks."""
        checks: list[dict[str, Any]] = []

        # 1) Existing explicit policy: fraud agent may not execute a transfer.
        transfer = find_tool_placement(
            self.plan_json,
            subject_runtime_id="transaction_processing_agent",
            tool_id="execute_transfer",
        )
        trace = f"trace-task6-negative-{uuid4()}"
        wf_instance = f"negative-transfer-{uuid4()}"
        request = self._request(
            transfer,
            parameters={
                "source_account": "CHK-002",
                "destination_account": "EXT-998",
                "amount": 999.0,
                "memo": "must not execute",
                "customer_id": "CUST-002",
                "change_ticket": "CHG-NEGATIVE-TRANSFER",
            },
            workflow_id="workflow.front_office.customer_transaction",
            trace_id=trace,
            workflow_instance_id=wf_instance,
            subject_override="agent.front_office.fraud",
            approvals=True,
            change_ticket="CHG-NEGATIVE-TRANSFER",
            idempotency_key=f"idem-negative-{uuid4()}",
        )
        allowed, _, event = self._execute_once(
            placement=transfer,
            request=request,
            operation=lambda: {"must": "not run"},
            trace_id=trace,
            workflow_instance_id=wf_instance,
            step_id="negative.fraud_execute_transfer",
            mode="enforce",
            allow_shadow_execution=False,
        )
        checks.append({
            "name": "unauthorized_transfer_blocked",
            "passed": not allowed and event["execution_result"] == "BLOCKED",
            "event": event,
        })

        # 2) Explicit back-office protection: report agent cannot update ledger.
        ledger = find_tool_placement(
            self.plan_json,
            subject_runtime_id="ledger_update_agent",
            tool_id="apply_ledger_updates",
        )
        trace = f"trace-task6-negative-{uuid4()}"
        wf_instance = f"negative-ledger-{uuid4()}"
        request = self._request(
            ledger,
            parameters={
                "batch_id": "EOD-2026-04-21-CLEAN",
                "posting_instructions": "must not execute",
                "change_ticket": "CHG-NEGATIVE-LEDGER",
            },
            workflow_id="workflow.back_office.eod_processing",
            trace_id=trace,
            workflow_instance_id=wf_instance,
            subject_override="agent.back_office.report",
            approvals=True,
            change_ticket="CHG-NEGATIVE-LEDGER",
            idempotency_key=f"idem-negative-{uuid4()}",
        )
        allowed, _, event = self._execute_once(
            placement=ledger,
            request=request,
            operation=lambda: {"must": "not run"},
            trace_id=trace,
            workflow_instance_id=wf_instance,
            step_id="negative.report_update_ledger",
            mode="enforce",
            allow_shadow_execution=False,
        )
        checks.append({
            "name": "unauthorized_ledger_update_blocked",
            "passed": not allowed and event["execution_result"] == "BLOCKED",
            "event": event,
        })

        # 3) Shadow mode: a known but unauthorized report agent read is observed,
        # while the safe read is allowed to continue for comparison.
        read = find_tool_placement(
            self.plan_json,
            subject_runtime_id="fraud_detection_agent",
            tool_id="get_transaction_context",
        )
        trace = f"trace-task6-shadow-{uuid4()}"
        wf_instance = f"shadow-read-{uuid4()}"
        request = self._request(
            read,
            parameters={"transaction_id": "TXN-1001"},
            workflow_id="workflow.front_office.fraud_review",
            trace_id=trace,
            workflow_instance_id=wf_instance,
            subject_override="agent.back_office.report",
        )
        allowed, value, event = self._execute_once(
            placement=read,
            request=request,
            operation=lambda: self.runtime.invoke_via_pep(
                "get_transaction_context", {"transaction_id": "TXN-1001"}
            ),
            trace_id=trace,
            workflow_instance_id=wf_instance,
            step_id="shadow.unauthorized_safe_read",
            mode="shadow",
            allow_shadow_execution=True,
        )
        checks.append({
            "name": "shadow_mode_would_block_but_safe_read_continues",
            "passed": (not allowed) and event["would_block"] and event["execution_result"] == "EXECUTED" and value is not None,
            "event": event,
        })

        # 4) Direct access bypass is blocked by the runtime guard.
        bypass_blocked = False
        bypass_error = ""
        try:
            self.runtime.direct_invoke("get_transaction_context", {"transaction_id": "TXN-1001"})
        except DirectProtectedToolAccessDenied as exc:
            bypass_blocked = True
            bypass_error = str(exc)
        except TestbedToolError as exc:
            if "DirectProtectedToolAccessDenied" in str(exc) or "direct access to protected tool" in str(exc):
                bypass_blocked = True
                bypass_error = str(exc)
            else:
                bypass_error = f"unexpected TestbedToolError: {exc}"
        except Exception as exc:
            bypass_error = f"unexpected {type(exc).__name__}: {exc}"
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "trace_id": f"trace-task6-bypass-{uuid4()}",
            "workflow_id": "task6.direct_bypass_test",
            "workflow_instance_id": f"bypass-{uuid4()}",
            "step_id": "negative.direct_tool_bypass",
            "caller_identity": "direct_python_caller",
            "target_resource": "get_transaction_context",
            "requested_action": "direct_invoke",
            "pdp_decision": "NOT_REACHED",
            "execution_result": "BLOCKED" if bypass_blocked else "UNEXPECTED_EXECUTION",
            "reason": bypass_error,
            "mode": "enforce",
        }
        self._append_audit(event)
        checks.append({"name": "direct_protected_tool_bypass_blocked", "passed": bypass_blocked, "event": event})
        return checks


def workflow_agents(workflows: Iterable[WorkflowDefinition]) -> set[str]:
    values: set[str] = set()
    for workflow in workflows:
        for route in workflow.routes:
            values.add(route.subject_runtime_id)
            values.add(route.target_runtime_id)
        for step in workflow.tools:
            values.add(step.subject_runtime_id)
    return values


def required_tool_ids(workflows: Iterable[WorkflowDefinition]) -> set[str]:
    values: set[str] = {"get_transaction_context"}
    for workflow in workflows:
        values.update(step.tool_id for step in workflow.tools)
    values.update({"store_report", "create_exception_case"})
    return values


def verify_unique_workload_identities(plan_json: dict[str, Any], agents: Iterable[str]) -> dict[str, Any]:
    wanted = set(agents)
    runtime_to_canonical: dict[str, set[str]] = {name: set() for name in wanted}
    for placement in plan_json.get("logical_peps", []):
        runtime = str(placement.get("subject_runtime_id") or "")
        canonical = str(placement.get("subject_canonical_id") or "")
        if runtime in runtime_to_canonical and canonical:
            runtime_to_canonical[runtime].add(canonical)
        resource_runtime = str(placement.get("resource_runtime_id") or "")
        resource_canonical = str(placement.get("resource_canonical_id") or "")
        if resource_runtime in runtime_to_canonical and resource_canonical.startswith("agent."):
            runtime_to_canonical[resource_runtime].add(resource_canonical)

    missing = sorted(name for name, values in runtime_to_canonical.items() if not values)
    ambiguous = {
        name: sorted(values)
        for name, values in runtime_to_canonical.items()
        if len(values) > 1
    }
    canonical_values = [next(iter(values)) for values in runtime_to_canonical.values() if len(values) == 1]
    duplicate_canonical = sorted({value for value in canonical_values if canonical_values.count(value) > 1})
    return {
        "passed": not missing and not ambiguous and not duplicate_canonical,
        "checked_agents": len(wanted),
        "missing_runtime_identities": missing,
        "ambiguous_runtime_identities": ambiguous,
        "duplicate_canonical_identities": duplicate_canonical,
        "bindings": {name: sorted(values) for name, values in sorted(runtime_to_canonical.items())},
    }


def audit_completeness(audit_path: Path) -> dict[str, Any]:
    required = {
        "trace_id",
        "workflow_id",
        "caller_identity",
        "target_resource",
        "requested_action",
        "pdp_decision",
        "policy_version",
        "permit_id",
        "execution_result",
    }
    events: list[dict[str, Any]] = []
    if audit_path.exists():
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
    sensitive = [event for event in events if event.get("pdp_decision") != "NOT_REACHED" and event.get("logical_pep_id")]
    incomplete: list[dict[str, Any]] = []
    for event in sensitive:
        missing = sorted(key for key in required if key not in event)
        # DENY has no permit by design, but the field must still be present.
        if missing:
            incomplete.append({"step_id": event.get("step_id"), "missing": missing})
    return {
        "passed": bool(sensitive) and not incomplete,
        "sensitive_event_count": len(sensitive),
        "incomplete_events": incomplete,
        "required_fields": sorted(required),
    }
