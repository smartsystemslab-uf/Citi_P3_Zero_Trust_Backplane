from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

from .models import PDPRequest, PDPResponse


class DecisionAuditLogger:
    """Append-only JSONL decision logger for the prototype.

    TODO(CITI-AUDIT): Replace or mirror this sink into Citi's approved audit/SIEM
    pipeline. Do not log raw account numbers, tokens, or other secrets.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, request: PDPRequest, response: PDPResponse) -> None:
        record: dict[str, Any] = {
            "decision_id": response.decision_id,
            "request_id": request.request_id,
            "trace_id": request.trace_id,
            "subject": request.subject,
            "resource": request.resource,
            "action": request.action,
            "workflow": request.context.workflow,
            "workflow_id": request.context.workflow_id,
            "risk": request.context.risk.value,
            "decision": response.decision.value,
            "reason": response.reason,
            "policy_id": response.policy_id,
            "matched_policy_ids": response.matched_policy_ids,
            "policy_version": response.policy_version,
            "obligations": [item.model_dump(mode="json") for item in response.obligations],
            "request_fingerprint": _fingerprint(request.parameters),
            "decided_at": response.decided_at.isoformat(),
        }
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"))
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(encoded + "\n")


def _fingerprint(parameters: dict[str, Any]) -> str:
    payload = json.dumps(parameters, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
