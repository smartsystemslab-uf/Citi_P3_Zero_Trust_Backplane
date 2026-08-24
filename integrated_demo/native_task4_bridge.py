from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from zt_task5.context_binding import build_context_bindings
from zt_task5.errors import DecisionVerificationError
from zt_task5.models import Task4Decision, UnifiedAuthorizationRequest
from zt_task5.task4_adapter import Task4DecisionEnvelope


_RISK_SCORE = {
    "low": 150,
    "medium": 350,
    "high": 700,
    "critical": 900,
}


def _header(headers: Mapping[str, str], name: str) -> str:
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    return lowered.get(name.lower(), "")


def _parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class NativeTask4InProcessBridge:
    """Use the real Task 4 protocol while presenting Task 5's verifier interface.

    Task 4 signs its own PDP request hash, while Task 5 binds leases to a slightly
    different unified operation hash. This bridge never substitutes one for the
    other before verification. It first verifies the *native Task 4* signature and
    native request hash, proves that the translated Task 4 operation is identical
    to the Task 5 request, and only then normalizes the verified decision to the
    Task 5 operation hash used by Permit Lease issuance.
    """

    def __init__(
        self,
        *,
        http_client: Any,
        task4_root: Path,
        subject_runtime_ids: Mapping[str, str],
        resource_runtime_ids: Mapping[str, str],
    ) -> None:
        self.http_client = http_client
        self.task4_root = Path(task4_root)
        self.subject_runtime_ids = dict(subject_runtime_ids)
        self.resource_runtime_ids = dict(resource_runtime_ids)
        self._pending: dict[str, Any] = {}

        # Imports are intentionally lazy: Task 5 remains independently testable.
        from zt_backplane.decision_signing import verify_decision_headers
        from zt_backplane.dev_evidence import build_signed_request
        from zt_backplane.canonical import request_proof_payload
        from zt_backplane.crypto import load_private_key, sign_mapping

        self._verify_decision_headers = verify_decision_headers
        self._build_signed_request = build_signed_request
        self._request_proof_payload = request_proof_payload
        self._sign_mapping = sign_mapping
        self._dev_pep_private_key = load_private_key(
            self.task4_root / "security" / "dev_keys" / "pep_private.pem"
        )
        self.public_key = self.task4_root / "security" / "dev_keys" / "pdp_signing_public.pem"

    def __call__(self, request: UnifiedAuthorizationRequest) -> Task4DecisionEnvelope:
        subject_runtime = self.subject_runtime_ids.get(request.subject)
        resource_runtime = self.resource_runtime_ids.get(request.resource)
        if not subject_runtime:
            raise ConnectionError(f"no Task 4 runtime binding for subject {request.subject}")

        challenge = self.http_client.post(
            "/v1/challenge",
            json={
                "subject_canonical_id": request.subject,
                "subject_runtime_id": subject_runtime,
            },
        )
        if challenge.status_code >= 400:
            raise ConnectionError(f"Task 4 challenge failed: {challenge.text}")
        nonce = challenge.json()["nonce"]

        with_human_approval = bool(
            request.context.get("with_human_approval")
            or request.context.get("human_approval") is True
        )
        with_secondary_authorization = bool(
            request.context.get("with_secondary_authorization")
            or request.context.get("secondary_authorization") is True
        )
        auth_factors = dict(
            request.context.get("auth_factors")
            or {"workload_identity": True, "user_session": True}
        )
        risk_score = int(
            request.context.get("risk_score")
            or _RISK_SCORE.get(str(request.risk).lower(), 350)
        )
        workflow_instance_id = str(
            request.context.get("workflow_instance_id")
            or request.context.get("workflow_instance")
            or f"{request.workflow_id}:demo-instance"
        )

        native = self._build_signed_request(
            nonce=nonce,
            subject_canonical_id=request.subject,
            subject_runtime_id=subject_runtime,
            resource_canonical_id=request.resource,
            resource_runtime_id=resource_runtime,
            action=request.action,
            workflow_id=request.workflow_id or None,
            workflow_instance_id=workflow_instance_id,
            risk_score=risk_score,
            auth_factors=auth_factors,
            parameters=request.parameters,
            with_human_approval=with_human_approval,
            with_secondary_authorization=with_secondary_authorization,
        )

        # Task 6 supplies one trace identifier for the full workflow. Preserve
        # that trace inside the signed native Task 4 request so PDP audit records,
        # Task 6 workflow audit, and later Task 7 latency traces can be correlated.
        task6_trace_id = str(request.context.get("trace_id") or "").strip()
        if task6_trace_id:
            native.trace_id = task6_trace_id
            proof = dict(native.subject.identity_evidence or {})
            proof["signature"] = self._sign_mapping(
                self._dev_pep_private_key, self._request_proof_payload(native)
            )
            native.subject.identity_evidence = proof

        # Bind Task 5's Permit Lease to the exact signed context assertions that
        # Task 4 evaluated. Evidence is excluded from Task 5's operation hash and
        # is validated separately by context-binding hashes.
        extra = dict(native.context.__pydantic_extra__ or {})
        evidence: dict[str, Any] = {
            "identity": extra.get("auth_evidence", {}),
            "risk": extra.get("risk_evidence", {}),
        }
        if extra.get("workflow_evidence"):
            evidence["workflow"] = extra["workflow_evidence"]
        if native.context.human_approval:
            evidence["human_approval"] = native.context.human_approval
        if extra.get("secondary_authorization"):
            evidence["secondary_authorization"] = extra["secondary_authorization"]
        request.evidence = evidence

        response = self.http_client.post("/v1/authorize", json=native.model_dump(mode="json"))
        if response.status_code >= 400:
            raise ConnectionError(f"Task 4 authorize failed: {response.text}")
        envelope = Task4DecisionEnvelope(body=response.json(), headers=dict(response.headers))
        self._pending[request.request_id] = native
        return envelope

    def verify(
        self,
        envelope: Task4DecisionEnvelope,
        decision: Task4Decision,
        request: UnifiedAuthorizationRequest,
    ) -> None:
        native = self._pending.pop(request.request_id, None)
        if native is None:
            raise DecisionVerificationError("missing native Task 4 request for verification")

        body = dict(envelope.body)
        if not self._verify_decision_headers(
            body,
            envelope.headers,
            self.public_key,
            expected_request_hash=native.request_hash,
        ):
            raise DecisionVerificationError("native Task 4 signed decision verification failed")
        if body.get("request_id") != native.request_id or body.get("trace_id") != native.trace_id:
            raise DecisionVerificationError("Task 4 decision is not bound to its native request/trace")

        semantic_checks = (
            (native.subject.canonical_id, request.subject, "subject"),
            (native.resource.canonical_id, request.resource, "resource"),
            (native.action, request.action, "action"),
            (native.context.workflow_id or "", request.workflow_id or "", "workflow_id"),
            (native.parameters, request.parameters, "parameters"),
        )
        for native_value, unified_value, field in semantic_checks:
            if native_value != unified_value:
                raise DecisionVerificationError(
                    f"Task 4 native request and Task 5 request differ in {field}"
                )

        # Now that the native signed request and response are verified, normalize
        # security epochs and the operation hash for Task 5 lease issuance.
        extra = dict(native.context.__pydantic_extra__ or {})
        identity_evidence = dict(extra.get("auth_evidence") or {})
        risk_evidence = dict(extra.get("risk_evidence") or {})
        proof = dict(native.subject.identity_evidence or {})

        decision.subject = request.subject
        decision.resource = request.resource
        decision.action = request.action
        decision.workflow_id = request.workflow_id
        decision.request_hash = request.request_hash()
        decision.identity_version = str(identity_evidence.get("identity_version") or "1")
        decision.risk_version = str(risk_evidence.get("risk_version") or "1")
        decision.nonce = str(proof.get("nonce") or "")
        decision.jti = str(proof.get("jti") or "")
        decision.decision_key_id = _header(envelope.headers, "X-ZT-Decision-Key-Id")
        decision.context_bindings = build_context_bindings(request.evidence)

        decided_at = _parse_time(body.get("decided_at"))
        if decided_at is not None:
            decision.issued_at = decided_at
        expirations = [
            _parse_time(identity_evidence.get("expires_at")),
            _parse_time(risk_evidence.get("expires_at")),
        ]
        workflow_evidence = dict(extra.get("workflow_evidence") or {})
        if workflow_evidence:
            expirations.append(_parse_time(workflow_evidence.get("expires_at")))
        expirations = [item for item in expirations if item is not None]
        if expirations:
            decision.expires_at = min(expirations)
