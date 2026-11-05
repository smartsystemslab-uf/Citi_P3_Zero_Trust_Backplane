"""Field values of the ``pdp_request`` scope, computed by the PDP from verified data.

Sources (see policy_store/policy_fields.yaml): the PEP-signed request, the evidence
verifier's VerifiedSecurityContext, the identity registry, the resource catalogue,
the PDP clock, and PDP checkers over the request parameters (the tool arguments,
which are bound by the request hash). Nothing here trusts an unverified claim.

Argument checkers are generic over the declared field names:

  args.well_formed          parameters are a JSON object without null values at any depth
  args.<p>                  str(parameters[p]), '' when absent
  args.<p>.length           len(parameters[p]) when it is text, else 0
  args.<p>.nonempty         parameters[p] is text with non-blank content
  args.<p>.finite_nonzero   parameters[p] is a finite number != 0 (int/float, or text that
                            parses as a decimal number; booleans are not numbers)
"""
from __future__ import annotations

import math
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

from .models import IdentityRecord, PDPRequest, ResourceRecord, VerifiedSecurityContext

SCOPE = "pdp_request"


def _well_formed(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, Mapping):
        return all(isinstance(k, str) and _well_formed(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return all(_well_formed(v) for v in value)
    if isinstance(value, float):
        return math.isfinite(value)
    return isinstance(value, (str, int, bool))


def _finite_nonzero(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, (int, float)):
        return math.isfinite(float(value)) and value != 0
    if isinstance(value, str):
        try:
            d = Decimal(value.strip())
        except (InvalidOperation, ValueError):
            return False
        return d.is_finite() and d != 0
    return False


def args_field(name: str, parameters: Mapping[str, Any]) -> Any:
    if name == "args.well_formed":
        return isinstance(parameters, Mapping) and _well_formed(dict(parameters))
    parts = name.split(".")
    if len(parts) == 2:
        v = parameters.get(parts[1])
        return "" if v is None else str(v)
    if len(parts) == 3:
        v = parameters.get(parts[1])
        check = parts[2]
        if check == "length":
            return len(v) if isinstance(v, str) else 0
        if check == "nonempty":
            return isinstance(v, str) and v.strip() != ""
        if check == "finite_nonzero":
            return _finite_nonzero(v)
    raise ValueError(f"no PDP argument checker for field {name}")


def request_fields(
    request: PDPRequest,
    identity: IdentityRecord,
    resource: ResourceRecord,
    security: VerifiedSecurityContext,
    store: Any,
) -> dict[str, Any]:
    """Verified facts of one request, named as in the signed field catalogue."""
    fields: dict[str, Any] = {
        "subject.id": request.subject.canonical_id,
        "subject.runtime_id": request.subject.runtime_id,
        "subject.type": identity.type,
        "subject.domain": identity.domain or "",
        "resource.id": request.resource.canonical_id,
        "resource.runtime_id": request.resource.runtime_id or "",
        "resource.domain": resource.domain or "",
        "resource.classification": resource.classification,
        "resource.critical": bool(resource.critical),
        "resource.target_type": str((resource.attributes or {}).get("scanner_target_type") or ""),
        "action": request.action,
        "workflow.id": request.context.workflow_id or "",
        "workflow.verified": bool(security.workflow_verified),
        "environment": request.context.environment,
        "risk.level": security.risk_level.value,
        "risk.score": int(security.risk_score),
        "auth.strength": int(security.auth_strength),
        "approval.valid": bool(security.approval_valid),
        "approval.secondary_valid": bool(security.secondary_authorization_valid),
        "approval.issuer": security.approval_issuer or "",
        "approval.secondary_issuer": security.secondary_authorization_issuer or "",
        "identity.verified": bool(security.identity_verified),
        "auth.scheme": security.auth_scheme,
        "auth.subject_kind": security.auth_subject_kind,
        "auth.agent_bound": security.auth_agent_id is not None
        and security.auth_agent_id == request.subject.runtime_id,
        "request.cross_domain": (identity.domain or "") != (resource.domain or ""),
    }
    for role in identity.roles:
        fields[f"subject.role.{role}"] = True
    for factor in security.auth_factors:
        fields[f"auth.factor.{factor}"] = True
    fields.update(store.catalog.windows_at(security.decision_time))
    params = request.parameters if isinstance(request.parameters, Mapping) else {}
    for name in store.engine.fields_needed:
        if name.startswith("args."):
            fields[name] = args_field(name, params)
    return fields
