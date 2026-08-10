from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from threading import RLock
from typing import Any


@dataclass
class AuditEvent:
    timestamp: str
    event_type: str
    request_id: str
    subject: str
    resource: str
    action: str
    workflow_id: str
    decision: str
    source: str
    permit_id: str | None
    policy_version: str | None
    reason: str
    previous_hash: str
    record_hash: str
    details: dict[str, Any]


class HashChainedAuditLog:
    """Append-only, hash-chained prototype audit sink used by Task 3/4/5 integration."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._events: list[AuditEvent] = []
        self._last_hash = "0" * 64

    def append(self, **fields: Any) -> AuditEvent:
        with self._lock:
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "previous_hash": self._last_hash,
                **fields,
            }
            material = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
            payload["record_hash"] = sha256(material.encode("utf-8")).hexdigest()
            event = AuditEvent(**payload)
            self._events.append(event)
            self._last_hash = event.record_hash
            return event

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(event) for event in self._events]

    def verify(self) -> bool:
        previous = "0" * 64
        for event in self.events():
            record_hash = event.pop("record_hash")
            if event["previous_hash"] != previous:
                return False
            material = json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)
            if sha256(material.encode("utf-8")).hexdigest() != record_hash:
                return False
            previous = record_hash
        return True
