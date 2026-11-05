from __future__ import annotations

from typing import Any, Mapping

from .models import ContextBinding, PermitLeaseClaims, UnifiedAuthorizationRequest
from .request_hash import sha256_digest
from .errors import LeaseValidationError


def build_context_bindings(evidence: Mapping[str, Any] | None) -> list[ContextBinding]:
    bindings: list[ContextBinding] = []
    for kind, raw in sorted(dict(evidence or {}).items()):
        if isinstance(raw, Mapping):
            assertion_id = str(
                raw.get("assertion_id")
                or raw.get("id")
                or raw.get("jti")
                or f"{kind}:{sha256_digest(raw)[7:19]}"
            )
            issuer = str(raw.get("issuer") or raw.get("iss") or "")
            issuer_version = str(
                raw.get("issuer_version")
                or raw.get("model_version")
                or raw.get("rule_version")
                or raw.get("version")
                or ""
            )
        else:
            assertion_id = f"{kind}:{sha256_digest(raw)[7:19]}"
            issuer = ""
            issuer_version = ""
        bindings.append(
            ContextBinding(
                kind=str(kind),
                assertion_id=assertion_id,
                issuer=issuer,
                issuer_version=issuer_version,
                evidence_hash=sha256_digest(raw),
            )
        )
    return bindings


def validate_context_bindings(
    claims: PermitLeaseClaims,
    request: UnifiedAuthorizationRequest,
) -> None:
    current = {b.kind: b for b in build_context_bindings(request.evidence)}
    expected = {b.kind: b for b in claims.context_bindings}
    if set(current) != set(expected):
        raise LeaseValidationError("Context assertion set does not match the Permit Lease")
    for kind, lease_binding in expected.items():
        request_binding = current[kind]
        if request_binding.evidence_hash != lease_binding.evidence_hash:
            raise LeaseValidationError(f"Context assertion changed: {kind}")
        if request_binding.assertion_id != lease_binding.assertion_id:
            raise LeaseValidationError(f"Context assertion ID changed: {kind}")
        if lease_binding.issuer and request_binding.issuer != lease_binding.issuer:
            raise LeaseValidationError(f"Context issuer changed: {kind}")
        if (
            lease_binding.issuer_version
            and request_binding.issuer_version != lease_binding.issuer_version
        ):
            raise LeaseValidationError(f"Context issuer version changed: {kind}")
