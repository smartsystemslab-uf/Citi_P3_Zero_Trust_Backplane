from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock

from .errors import ReplayError


def _now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


@dataclass
class UseRecord:
    uses: int
    expires_at: float


class ReplayCache:
    """Thread-safe in-memory replay state for the prototype."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._once: dict[tuple[str, str], float] = {}
        self._uses: dict[str, UseRecord] = {}

    def _purge(self) -> None:
        now = _now_ts()
        self._once = {k: exp for k, exp in self._once.items() if exp > now}
        self._uses = {k: v for k, v in self._uses.items() if v.expires_at > now}

    def consume_once(self, namespace: str, value: str, expires_at: datetime) -> None:
        if not value:
            return
        with self._lock:
            self._purge()
            key = (namespace, value)
            if key in self._once:
                raise ReplayError(f"Replay detected for {namespace}")
            self._once[key] = expires_at.timestamp()

    def consume_use(self, permit_id: str, max_uses: int, expires_at: datetime) -> int:
        with self._lock:
            self._purge()
            record = self._uses.get(permit_id)
            uses = 0 if record is None else record.uses
            if uses >= max_uses:
                raise ReplayError("Permit Lease use limit exceeded")
            uses += 1
            self._uses[permit_id] = UseRecord(uses=uses, expires_at=expires_at.timestamp())
            return max_uses - uses

    def clear(self) -> None:
        with self._lock:
            self._once.clear()
            self._uses.clear()
