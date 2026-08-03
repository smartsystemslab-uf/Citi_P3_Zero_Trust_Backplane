from __future__ import annotations

import inspect
import json
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

import httpx


class PDPUnavailable(RuntimeError):
    pass


class InvalidPDPDecision(RuntimeError):
    pass


class PEPDenied(PermissionError):
    pass


class ObligationError(PermissionError):
    pass


class Task4PDPClient:
    """Exact bridge to the security-hardened Task 4 prototype.

    It deliberately imports Task 4's own signed-evidence builder and decision
    verifier. This avoids implementing a second, subtly different security
    protocol in Task 3.
    """

    def __init__(
        self,
        *,
        pdp_url: str = "http://127.0.0.1:8080",
        pdp_public_key: str | Path,
        timeout_seconds: float = 2.0,
        http_client: Any | None = None,
    ):
        self.pdp_url = pdp_url.rstrip("/")
        self.pdp_public_key = Path(pdp_public_key)
        self.timeout_seconds = timeout_seconds
        self.http_client = http_client or httpx.Client(timeout=timeout_seconds)

    def authorize(
        self,
        placement: Mapping[str, Any],
        *,
        parameters: dict[str, Any] | None = None,
        risk_score: int = 300,
        auth_factors: dict[str, bool] | None = None,
        workflow_instance_id: str | None = None,
        with_human_approval: bool = False,
        with_secondary_authorization: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            from zt_backplane.decision_signing import verify_decision_headers
            from zt_backplane.dev_evidence import build_signed_request
        except ImportError as exc:
            raise RuntimeError(
                "Task 4 package is not importable. Install it with: "
                "pip install -e /path/to/zero_trust_pdp_task4_secure"
            ) from exc

        subject_runtime_id = placement.get("subject_runtime_id")
        if not subject_runtime_id:
            raise ValueError(f"missing runtime subject binding for {placement['placement_id']}")

        try:
            challenge = self.http_client.post(
                f"{self.pdp_url}/v1/challenge",
                json={
                    "subject_canonical_id": placement["subject_canonical_id"],
                    "subject_runtime_id": subject_runtime_id,
                },
            )
            challenge.raise_for_status()
            nonce = challenge.json()["nonce"]

            request = build_signed_request(
                nonce=nonce,
                subject_canonical_id=placement["subject_canonical_id"],
                subject_runtime_id=subject_runtime_id,
                resource_canonical_id=placement["resource_canonical_id"],
                resource_runtime_id=placement.get("resource_runtime_id"),
                action=placement["action"],
                workflow_id=placement.get("workflow_id"),
                workflow_instance_id=workflow_instance_id or f"wf-{uuid4()}",
                risk_score=risk_score,
                auth_factors=auth_factors or {"workload_identity": True, "user_session": True},
                parameters=parameters or {},
                with_human_approval=with_human_approval,
                with_secondary_authorization=with_secondary_authorization,
            )
            payload = request.model_dump(mode="json")
            response = self.http_client.post(
                f"{self.pdp_url}/v1/authorize",
                json=payload,
            )
            response.raise_for_status()
        except Exception as exc:
            if isinstance(exc, (RuntimeError, ValueError)) and not isinstance(exc, httpx.HTTPError):
                raise
            raise PDPUnavailable("Task 4 PDP unavailable or rejected the protocol request") from exc

        body = response.json()
        if not verify_decision_headers(
            body,
            response.headers,
            self.pdp_public_key,
            expected_request_hash=request.request_hash,
        ):
            raise InvalidPDPDecision("Task 4 response signature, digest, or request binding is invalid")
        if body.get("request_id") != payload.get("request_id") or body.get("trace_id") != payload.get("trace_id"):
            raise InvalidPDPDecision("Task 4 decision is not bound to the current request and trace")
        return body, payload


class PEPEnforcer:
    def __init__(
        self,
        plan: str | Path | dict[str, Any],
        *,
        pdp_client: Task4PDPClient,
        audit_path: str | Path | None = None,
    ):
        if isinstance(plan, (str, Path)):
            self.plan_path = Path(plan)
            raw = json.loads(self.plan_path.read_text(encoding="utf-8"))
        else:
            self.plan_path = None
            raw = plan
        self.plan = raw
        self.placements = {item["placement_id"]: item for item in raw.get("logical_peps", [])}
        self.pdp_client = pdp_client
        self.audit_path = Path(audit_path) if audit_path else None

    def placement(self, placement_id: str) -> dict[str, Any]:
        try:
            return self.placements[placement_id]
        except KeyError as exc:
            raise KeyError(f"unknown PEP placement: {placement_id}; direct unregistered access is blocked") from exc

    def authorize(
        self,
        placement_id: str,
        *,
        parameters: dict[str, Any] | None = None,
        risk_score: int = 300,
        auth_factors: dict[str, bool] | None = None,
        workflow_instance_id: str | None = None,
        with_human_approval: bool = False,
        with_secondary_authorization: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        placement = self.placement(placement_id)
        return self.pdp_client.authorize(
            placement,
            parameters=parameters,
            risk_score=risk_score,
            auth_factors=auth_factors,
            workflow_instance_id=workflow_instance_id,
            with_human_approval=with_human_approval,
            with_secondary_authorization=with_secondary_authorization,
        )

    def enforce(
        self,
        placement_id: str,
        operation: Callable[..., Any],
        *args: Any,
        parameters: dict[str, Any] | None = None,
        risk_score: int = 300,
        auth_factors: dict[str, bool] | None = None,
        workflow_instance_id: str | None = None,
        with_human_approval: bool = False,
        with_secondary_authorization: bool = False,
        **kwargs: Any,
    ) -> Any:
        placement = self.placement(placement_id)
        try:
            decision, request = self.authorize(
                placement_id,
                parameters=parameters,
                risk_score=risk_score,
                auth_factors=auth_factors,
                workflow_instance_id=workflow_instance_id,
                with_human_approval=with_human_approval,
                with_secondary_authorization=with_secondary_authorization,
            )
        except Exception as exc:
            if placement["mode"] == "shadow" or placement["fail_mode"] == "shadow_only":
                self._audit(placement, {}, {}, "SHADOW_ALLOW", f"PDP error in shadow mode: {exc}")
                return operation(*args, **kwargs)
            if placement["fail_mode"] == "open_for_noncritical" and not placement["critical"]:
                self._audit(placement, {}, {}, "FAIL_OPEN", f"Noncritical fail-open: {exc}")
                return operation(*args, **kwargs)
            self._audit(placement, {}, {}, "BLOCKED", str(exc))
            raise

        allowed = decision.get("decision") in {"ALLOW", "ALLOW_WITH_OBLIGATIONS"}
        if not allowed:
            if placement["mode"] == "shadow":
                self._audit(placement, request, decision, "SHADOW_ALLOW", "Denied by PDP but shadow mode executed")
                return operation(*args, **kwargs)
            self._audit(placement, request, decision, "BLOCKED", decision.get("reason", "not authorized"))
            raise PEPDenied(
                f"{placement_id} blocked: {decision.get('decision')} ({decision.get('reason')})"
            )

        self._check_pre_obligations(decision.get("obligations", []), parameters or {})
        result = operation(*args, **kwargs)
        result = self._apply_post_obligations(result, decision.get("obligations", []))
        self._audit(placement, request, decision, "EXECUTED", "authorized")
        return result

    async def enforce_async(
        self,
        placement_id: str,
        operation: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        placement = self.placement(placement_id)
        parameters = kwargs.pop("parameters", None)
        try:
            decision, request = self.authorize(
                placement_id,
                parameters=parameters,
                risk_score=kwargs.pop("risk_score", 300),
                auth_factors=kwargs.pop("auth_factors", None),
                workflow_instance_id=kwargs.pop("workflow_instance_id", None),
                with_human_approval=kwargs.pop("with_human_approval", False),
                with_secondary_authorization=kwargs.pop("with_secondary_authorization", False),
            )
        except Exception as exc:
            if placement["mode"] == "shadow" or placement["fail_mode"] == "shadow_only":
                self._audit(placement, {}, {}, "SHADOW_ALLOW", f"PDP error in shadow mode: {exc}")
                value = operation(*args, **kwargs)
                return await value if inspect.isawaitable(value) else value
            if placement["fail_mode"] == "open_for_noncritical" and not placement["critical"]:
                self._audit(placement, {}, {}, "FAIL_OPEN", f"Noncritical fail-open: {exc}")
                value = operation(*args, **kwargs)
                return await value if inspect.isawaitable(value) else value
            self._audit(placement, {}, {}, "BLOCKED", str(exc))
            raise

        if decision.get("decision") not in {"ALLOW", "ALLOW_WITH_OBLIGATIONS"}:
            if placement["mode"] == "shadow":
                self._audit(placement, request, decision, "SHADOW_ALLOW", "Denied by PDP but shadow mode executed")
                value = operation(*args, **kwargs)
                return await value if inspect.isawaitable(value) else value
            self._audit(placement, request, decision, "BLOCKED", decision.get("reason", "not authorized"))
            raise PEPDenied(
                f"{placement_id} blocked: {decision.get('decision')} ({decision.get('reason')})"
            )
        self._check_pre_obligations(decision.get("obligations", []), parameters or {})
        value = operation(*args, **kwargs)
        if inspect.isawaitable(value):
            value = await value
        value = self._apply_post_obligations(value, decision.get("obligations", []))
        self._audit(placement, request, decision, "EXECUTED", "authorized")
        return value

    def wrap_sync(self, placement_id: str, operation: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(operation)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            zt = kwargs.pop("zt_context", {}) or {}
            return self.enforce(placement_id, operation, *args, **zt, **kwargs)
        return wrapper

    def wrap_async(self, placement_id: str, operation: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(operation)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            zt = kwargs.pop("zt_context", {}) or {}
            return await self.enforce_async(placement_id, operation, *args, **zt, **kwargs)
        return wrapper

    @staticmethod
    def _check_pre_obligations(obligations: list[dict[str, Any]], parameters: dict[str, Any]) -> None:
        for obligation in obligations:
            kind = obligation.get("type")
            if kind == "require_idempotency_key" and not parameters.get("idempotency_key"):
                raise ObligationError("PDP allowed the action, but idempotency_key obligation is unsatisfied")
            if kind == "require_change_ticket" and not parameters.get("change_ticket"):
                raise ObligationError("PDP allowed the action, but change_ticket obligation is unsatisfied")

    @staticmethod
    def _apply_post_obligations(value: Any, obligations: list[dict[str, Any]]) -> Any:
        fields: set[str] = set()
        for obligation in obligations:
            if obligation.get("type") == "data_masking":
                fields.update(obligation.get("parameters", {}).get("fields", []))
        if not fields:
            return value

        def mask(item: Any) -> Any:
            if isinstance(item, dict):
                return {key: ("***MASKED***" if key in fields else mask(child)) for key, child in item.items()}
            if isinstance(item, list):
                return [mask(child) for child in item]
            return item

        return mask(value)

    def _audit(
        self,
        placement: Mapping[str, Any],
        request: Mapping[str, Any],
        decision: Mapping[str, Any],
        outcome: str,
        reason: str,
    ) -> None:
        if not self.audit_path:
            return
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "schema_version": "1.0",
            "event_id": f"pep-{uuid4()}",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "trace_id": request.get("trace_id", f"trace-{uuid4()}"),
            "request_id": request.get("request_id"),
            "decision_id": decision.get("decision_id"),
            "component": placement["physical_pep_id"],
            "event_type": "pep_enforcement",
            "subject_id": placement["subject_canonical_id"],
            "runtime_subject_id": placement.get("subject_runtime_id"),
            "resource_id": placement["resource_canonical_id"],
            "runtime_resource_id": placement.get("resource_runtime_id"),
            "action": placement["action"],
            "workflow_id": placement.get("workflow_id"),
            "decision": decision.get("decision", "NO_DECISION"),
            "policy_version": decision.get("policy_version", "unknown"),
            "permit_id": None,
            "outcome": outcome,
            "reason": reason,
            "obligations": decision.get("obligations", []),
            "environment": self.plan.get("environment_binding", "prototype"),
            "details": {"placement_id": placement["placement_id"], "edge_id": placement["edge_id"]},
        }
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
