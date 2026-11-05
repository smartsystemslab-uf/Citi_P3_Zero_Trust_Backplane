from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from .canonical import sha256_hex
from .models import PDPRequest, PDPResponse, VerifiedSecurityContext


class ChainedAuditLogger:
    """Schema-compatible JSONL audit records with a tamper-evident hash chain.

    TODO(CITI-AUDIT): mirror records to Citi's independent append-only SIEM or
    audit pipeline. A local file must not be the only evidence source.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._previous_hash = self._load_last_hash()

    def write(
        self,
        request: PDPRequest,
        response: PDPResponse,
        security: VerifiedSecurityContext | None,
        *,
        started_ns: int,
    ) -> None:
        latency_ms = max(0.0, (time.perf_counter_ns() - started_ns) / 1_000_000)
        details: dict[str, Any] = {
            "request_hash": request.request_hash,
            "previous_record_hash": self._previous_hash,
            "identity_verified": bool(security and security.identity_verified),
            "risk_verified": bool(security and security.risk_verified),
            "auth_verified": bool(security and security.auth_verified),
            "workflow_verified": bool(security and security.workflow_verified),
            "evidence_ids": security.evidence_ids if security else [],
        }
        event: dict[str, Any] = {
            "schema_version": "1.0",
            "event_id": str(uuid4()),
            "timestamp": response.decided_at.isoformat(),
            "trace_id": request.trace_id,
            "request_id": request.request_id,
            "decision_id": response.decision_id,
            "component": "pdp",
            "event_type": "authorization_decision",
            "subject_id": request.subject.canonical_id,
            "runtime_subject_id": request.subject.runtime_id,
            "resource_id": request.resource.canonical_id,
            "runtime_resource_id": request.resource.runtime_id,
            "action": request.action,
            "workflow_id": request.context.workflow_id,
            "decision": response.decision.value,
            "policy_version": response.policy_version,
            "permit_id": None,
            "outcome": _outcome(response),
            "reason": response.reason,
            "obligations": [item.model_dump(mode="json") for item in response.obligations],
            "latency_ms": latency_ms,
            "environment": request.context.environment,
            "details": details,
        }
        hash_input = dict(event)
        record_hash = sha256_hex(hash_input)
        event["details"]["record_hash"] = record_hash
        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(encoded + "\n")
            self._previous_hash = record_hash

    def verify_chain(self) -> bool:
        previous: str | None = None
        if not self.path.exists():
            return True
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            details = event.get("details", {})
            record_hash = details.pop("record_hash", None)
            if details.get("previous_record_hash") != previous:
                return False
            if record_hash != sha256_hex(event):
                return False
            details["record_hash"] = record_hash
            previous = record_hash
        return True

    def _load_last_hash(self) -> str | None:
        if not self.path.exists():
            return None
        lines = [line for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return None
        return json.loads(lines[-1]).get("details", {}).get("record_hash")


def _outcome(response: PDPResponse) -> str:
    if response.decision.value in {"ALLOW", "ALLOW_WITH_OBLIGATIONS"}:
        return "success"
    if response.decision.value == "MANUAL_REVIEW":
        return "manual_review"
    return "blocked"
