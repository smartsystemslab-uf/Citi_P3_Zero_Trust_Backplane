from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from .errors import IdempotencyError


@dataclass
class IdempotencyRecord:
    request_hash: str
    status: str


class IdempotencyGuard:
    """Business-level duplicate prevention for critical financial writes."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._records: dict[str, IdempotencyRecord] = {}

    def reserve(self, key: str | None, request_hash: str, *, required: bool) -> None:
        if not key:
            if required:
                raise IdempotencyError("Critical operation requires an idempotency key")
            return
        with self._lock:
            existing = self._records.get(key)
            if existing is not None:
                if existing.request_hash != request_hash:
                    raise IdempotencyError(
                        "Idempotency key was reused for a different request"
                    )
                raise IdempotencyError("Duplicate financial execution blocked")
            self._records[key] = IdempotencyRecord(request_hash=request_hash, status="RESERVED")

    def commit(self, key: str | None) -> None:
        if not key:
            return
        with self._lock:
            if key in self._records:
                self._records[key].status = "COMMITTED"

    def abort(self, key: str | None) -> None:
        if not key:
            return
        with self._lock:
            record = self._records.get(key)
            if record and record.status == "RESERVED":
                self._records.pop(key, None)
