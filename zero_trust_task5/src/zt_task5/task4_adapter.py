from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Protocol
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .context_binding import build_context_bindings
from .errors import DecisionVerificationError
from .key_rotation import Ed25519KeyRing, b64url_encode
from .models import Decision, Task4Decision, UnifiedAuthorizationRequest
from .request_hash import canonical_json_bytes


@dataclass
class Task4DecisionEnvelope:
    body: Mapping[str, Any]
    headers: Mapping[str, str]


class DecisionVerifier(Protocol):
    def verify(
        self,
        envelope: Task4DecisionEnvelope,
        decision: Task4Decision,
        request: UnifiedAuthorizationRequest,
    ) -> None: ...


def _header(headers: Mapping[str, str], *names: str) -> str:
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return ""


def _first(mapping: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        value = mapping.get(name)
        if value is not None:
            return value
    return default


class Task4DecisionAdapter:
    """Normalizes Task 4 response aliases without changing the unified stable IDs."""

    def normalize(
        self,
        envelope: Task4DecisionEnvelope,
        request: UnifiedAuthorizationRequest,
    ) -> Task4Decision:
        body = dict(envelope.body)
        nested = body.get("result") or body.get("authorization") or body.get("response")
        if isinstance(nested, Mapping):
            merged = dict(body)
            merged.update(nested)
            body = merged

        raw_decision = str(
            _first(body, "decision", "outcome", "effect", default="DENY")
        ).upper()
        try:
            decision = Decision(raw_decision)
        except ValueError as exc:
            raise DecisionVerificationError(f"Unsupported Task 4 decision: {raw_decision}") from exc

        context = dict(body.get("context") or {})
        request_hash = str(
            _first(body, "request_hash", "requestHash")
            or _header(envelope.headers, "X-ZT-Request-Hash", "X-Request-Hash")
            or ""
        )
        policy_version = str(
            _first(body, "policy_version", "policyVersion")
            or _header(envelope.headers, "X-ZT-Policy-Version")
            or ""
        )
        decision_key_id = str(
            _first(body, "decision_key_id", "key_id", "kid")
            or _header(
                envelope.headers,
                "X-ZT-Decision-Key-Id",
                "X-ZT-Key-Id",
            )
            or ""
        )
        if not request_hash or not policy_version:
            raise DecisionVerificationError(
                "Task 4 response is missing request_hash or policy_version"
            )

        raw_bindings = body.get("context_bindings")
        if raw_bindings:
            bindings = raw_bindings
        else:
            bindings = build_context_bindings(request.evidence)

        issued_at = _first(body, "issued_at", "iat") or datetime.now(timezone.utc)
        expires_at = _first(body, "expires_at", "exp")
        obligations = _first(body, "obligations", "required_obligations", default=[])
        if isinstance(obligations, Mapping):
            obligations = [dict(obligations)]

        return Task4Decision(
            interface_version=str(body.get("interface_version") or request.interface_version),
            decision_id=str(
                _first(body, "decision_id", "id")
                or _header(envelope.headers, "X-ZT-Decision-Id")
                or uuid4()
            ),
            decision=decision,
            subject=str(_first(body, "subject", "subject_id", default=request.subject)),
            resource=str(_first(body, "resource", "resource_id", default=request.resource)),
            action=str(_first(body, "action", "operation", default=request.action)),
            workflow_id=str(
                _first(body, "workflow_id", "workflow", default=request.workflow_id)
                or context.get("workflow_id")
                or request.workflow_id
            ),
            request_hash=request_hash,
            policy_version=policy_version,
            identity_version=str(
                _first(body, "identity_version", "identity_epoch", default="1")
            ),
            risk_version=str(_first(body, "risk_version", "risk_epoch", default="1")),
            obligations=list(obligations or []),
            context_bindings=bindings,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=str(_first(body, "nonce", default="")),
            jti=str(_first(body, "jti", "request_jti", default=uuid4())),
            decision_key_id=decision_key_id,
        )


def task4_signed_material(decision: Task4Decision) -> bytes:
    return canonical_json_bytes(decision.model_dump(mode="json"))


class HeaderEd25519DecisionVerifier:
    """Verifies the signed Task 4 decision proof carried in HTTP headers."""

    def __init__(
        self,
        trust_store: Ed25519KeyRing,
        *,
        material_builder: Callable[[Task4Decision], bytes] = task4_signed_material,
    ) -> None:
        self.trust_store = trust_store
        self.material_builder = material_builder

    def verify(
        self,
        envelope: Task4DecisionEnvelope,
        decision: Task4Decision,
        request: UnifiedAuthorizationRequest,
    ) -> None:
        signature = _header(
            envelope.headers,
            "X-ZT-Decision-Signature",
            "X-Decision-Signature",
        ) or str(envelope.body.get("decision_signature") or "")
        key_id = decision.decision_key_id
        if not signature or not key_id:
            raise DecisionVerificationError("Task 4 signed decision proof is missing")
        if decision.request_hash != request.request_hash():
            raise DecisionVerificationError("Task 4 decision is bound to a different request")
        try:
            self.trust_store.verify(key_id, self.material_builder(decision), signature)
        except Exception as exc:
            raise DecisionVerificationError("Task 4 decision signature verification failed") from exc


class CallbackDecisionVerifier:
    """Bridge to an existing Task 4 decision_permit_verifier implementation."""

    def __init__(
        self,
        callback: Callable[
            [Task4DecisionEnvelope, Task4Decision, UnifiedAuthorizationRequest], bool | None
        ],
    ) -> None:
        self.callback = callback

    def verify(
        self,
        envelope: Task4DecisionEnvelope,
        decision: Task4Decision,
        request: UnifiedAuthorizationRequest,
    ) -> None:
        result = self.callback(envelope, decision, request)
        if result is False:
            raise DecisionVerificationError("The external Task 4 verifier rejected the decision")


def sign_demo_task4_decision(
    decision: Task4Decision,
    private_key: Ed25519PrivateKey,
) -> Task4DecisionEnvelope:
    signature = b64url_encode(private_key.sign(task4_signed_material(decision)))
    return Task4DecisionEnvelope(
        body=decision.model_dump(mode="json"),
        headers={
            "X-ZT-Decision-Key-Id": decision.decision_key_id,
            "X-ZT-Decision-Signature": signature,
            "X-ZT-Request-Hash": decision.request_hash,
            "X-ZT-Policy-Version": decision.policy_version,
            "X-ZT-Decision-Id": decision.decision_id,
        },
    )


def build_demo_allow_decision(
    request: UnifiedAuthorizationRequest,
    *,
    key_id: str,
    policy_version: str = "1",
    identity_version: str = "1",
    risk_version: str = "1",
    obligations: list[Any] | None = None,
    lifetime_seconds: int = 30,
) -> Task4Decision:
    now = datetime.now(timezone.utc)
    return Task4Decision(
        decision=Decision.ALLOW_WITH_OBLIGATIONS if obligations else Decision.ALLOW,
        subject=request.subject,
        resource=request.resource,
        action=request.action,
        workflow_id=request.workflow_id,
        request_hash=request.request_hash(),
        policy_version=policy_version,
        identity_version=identity_version,
        risk_version=risk_version,
        obligations=obligations or [],
        context_bindings=build_context_bindings(request.evidence),
        issued_at=now,
        expires_at=now + timedelta(seconds=lifetime_seconds),
        nonce=str(uuid4()),
        jti=str(uuid4()),
        decision_key_id=key_id,
    )
