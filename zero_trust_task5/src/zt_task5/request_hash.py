from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any, Mapping


_VOLATILE_CONTEXT_KEYS = {
    "nonce",
    "jti",
    "issued_at",
    "expires_at",
    "signature",
    "request_signature",
    "proof",
    "request_proof",
    "caller_time",
    "event_time",
}


def _normalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _normalize(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, float):
        # Avoid platform-dependent scientific notation for common financial values.
        return format(Decimal(str(value)), "f")
    if value is None or isinstance(value, (str, int, bool)):
        return value
    return str(value)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def stable_security_context(context: Mapping[str, Any] | None) -> dict[str, Any]:
    context = dict(context or {})
    return {
        key: value
        for key, value in context.items()
        if key not in _VOLATILE_CONTEXT_KEYS and key not in {"evidence", "assertions"}
    }


def operation_payload(request: Mapping[str, Any]) -> dict[str, Any]:
    context = dict(request.get("context") or {})
    workflow_id = (
        request.get("workflow_id")
        or context.get("workflow_id")
        or context.get("workflow_instance")
        or context.get("workflow")
        or ""
    )
    parameters = request.get("parameters")
    if parameters is None:
        parameters = request.get("params")
    if parameters is None:
        parameters = request.get("input")
    if parameters is None:
        parameters = {}

    return {
        "interface_version": str(request.get("interface_version") or "1.0"),
        "subject": str(request.get("subject") or request.get("subject_id") or ""),
        "resource": str(request.get("resource") or request.get("resource_id") or ""),
        "action": str(request.get("action") or ""),
        "parameters": parameters,
        "workflow_id": str(workflow_id),
        "audience": str(request.get("audience") or context.get("audience") or ""),
        "endpoint": str(request.get("endpoint") or context.get("endpoint") or ""),
        "idempotency_key": request.get("idempotency_key")
        or context.get("idempotency_key"),
        "security_context": stable_security_context(context),
    }


def calculate_request_hash(request: Mapping[str, Any]) -> str:
    """Return the deterministic hash used by Task 3, Task 4, and Task 5."""
    return sha256_digest(operation_payload(request))
