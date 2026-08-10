from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Mapping, TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .errors import Task5Error
from .idempotency_guard import IdempotencyGuard
from .models import UnifiedAuthorizationRequest
from .pdp_timeout_state_machine import PDPTimeoutStateMachine, RuntimeAuthorization
from .task4_adapter import Task4DecisionEnvelope

T = TypeVar("T")


class PEPDenied(PermissionError):
    pass


class Task3PEPAdapter:
    """Drop-in runtime helper for Task 3 generated PEP middleware/wrappers."""

    def __init__(
        self,
        state_machine: PDPTimeoutStateMachine,
        task4_call: Callable[[UnifiedAuthorizationRequest], Task4DecisionEnvelope],
        *,
        pep_identity: str,
        pep_private_key: Ed25519PrivateKey,
        idempotency_guard: IdempotencyGuard | None = None,
    ) -> None:
        self.state_machine = state_machine
        self.task4_call = task4_call
        self.pep_identity = pep_identity
        self.pep_private_key = pep_private_key
        self.idempotency_guard = idempotency_guard or IdempotencyGuard()

    def authorize(
        self,
        raw_request: UnifiedAuthorizationRequest | Mapping[str, Any],
        *,
        session_id: str | None = None,
    ) -> RuntimeAuthorization:
        request = (
            raw_request
            if isinstance(raw_request, UnifiedAuthorizationRequest)
            else UnifiedAuthorizationRequest.from_mapping(raw_request)
        )
        return self.state_machine.authorize(
            request,
            self.task4_call,
            pep_identity=self.pep_identity,
            pep_private_key=self.pep_private_key,
            session_id=session_id,
        )

    def execute(
        self,
        raw_request: UnifiedAuthorizationRequest | Mapping[str, Any],
        operation: Callable[[], T],
        *,
        session_id: str | None = None,
    ) -> T:
        request = (
            raw_request
            if isinstance(raw_request, UnifiedAuthorizationRequest)
            else UnifiedAuthorizationRequest.from_mapping(raw_request)
        )
        authorization = self.authorize(request, session_id=session_id)
        if not authorization.allowed:
            raise PEPDenied(authorization.reason)
        self.idempotency_guard.reserve(
            request.idempotency_key,
            request.request_hash(),
            required=request.critical,
        )
        try:
            result = operation()
        except Exception:
            self.idempotency_guard.abort(request.idempotency_key)
            raise
        self.idempotency_guard.commit(request.idempotency_key)
        return result

    def protect(self, request_builder: Callable[..., Mapping[str, Any]]):
        """Decorator hook that generated Task 3 Python wrappers can emit."""
        def decorator(function: Callable[..., T]) -> Callable[..., T]:
            @wraps(function)
            def wrapped(*args: Any, **kwargs: Any) -> T:
                raw = request_builder(*args, **kwargs)
                return self.execute(raw, lambda: function(*args, **kwargs))
            return wrapped
        return decorator


def augment_generated_pep_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Adds Task 5 runtime contract fields while preserving Task 3 stable IDs."""
    output = dict(plan)
    raw_peps = output.get("peps") or output.get("generated_peps") or output.get("placements") or []
    enhanced: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_peps):
        pep = dict(raw)
        pep_id = str(pep.get("pep_id") or pep.get("id") or f"pep-{index + 1}")
        stable_resource = str(pep.get("resource_id") or pep.get("resource") or "")
        stable_action = str(pep.get("action_id") or pep.get("action") or "")
        critical = bool(pep.get("critical") or pep.get("risk") in {"high", "critical"})
        pep["task5"] = {
            "interface_version": str(output.get("interface_version") or "1.0"),
            "pep_id": pep_id,
            "resource_id": stable_resource,
            "action_id": stable_action,
            "permit_required": True,
            "request_hash_required": True,
            "sender_constraint_required": True,
            "pdp_timeout_mode": "VALID_MATCHING_LEASE_ONLY",
            "max_uses": 1 if critical else int(pep.get("permit_max_uses") or 3),
            "critical": critical,
            "fail_closed": True,
            "clear_cache_on_restart": True,
        }
        enhanced.append(pep)
    if "peps" in output:
        output["peps"] = enhanced
    elif "generated_peps" in output:
        output["generated_peps"] = enhanced
    elif "placements" in output:
        output["placements"] = enhanced
    else:
        output["peps"] = enhanced
    output["task5_contract"] = {
        "interface_version": str(output.get("interface_version") or "1.0"),
        "authorization_artifact": "signed_permit_lease",
        "stable_id_source": "unified_interface",
    }
    return output
