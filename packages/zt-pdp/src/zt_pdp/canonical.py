from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import PDPRequest


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def operation_payload(request: PDPRequest) -> dict[str, Any]:
    """Security-relevant operation bound to request_hash and approvals."""

    return {
        "schema_version": request.schema_version,
        "subject": {
            "canonical_id": request.subject.canonical_id,
            "runtime_id": request.subject.runtime_id,
        },
        "resource": {
            "canonical_id": request.resource.canonical_id,
            "runtime_id": request.resource.runtime_id,
        },
        "action": request.action,
        "workflow_id": request.context.workflow_id,
        "workflow_instance_id": request.context.workflow_instance_id,
        "environment": request.context.environment,
        "parameters": request.parameters,
    }


def compute_request_hash(request: PDPRequest) -> str:
    return sha256_hex(operation_payload(request))


def request_proof_payload(request: PDPRequest) -> dict[str, Any]:
    """Full request signed by the verified PEP, excluding only the signature."""

    data = request.model_dump(mode="json")
    evidence = dict(data["subject"]["identity_evidence"])
    evidence.pop("signature", None)
    data["subject"]["identity_evidence"] = evidence
    return data


def assertion_payload(assertion: dict[str, Any]) -> dict[str, Any]:
    data = dict(assertion)
    data.pop("signature", None)
    return data
