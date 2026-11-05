from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import RLock

from .errors import LeaseValidationError


class TrustedClock:
    """Detects significant wall-clock rollback within the running process."""

    def __init__(self, *, maximum_rollback_seconds: float = 1.0) -> None:
        self.maximum_rollback = timedelta(seconds=maximum_rollback_seconds)
        self._last_seen: datetime | None = None
        self._lock = RLock()

    def now(self) -> datetime:
        current = datetime.now(timezone.utc)
        with self._lock:
            if self._last_seen and current + self.maximum_rollback < self._last_seen:
                raise LeaseValidationError("Trusted clock rollback detected")
            if self._last_seen is None or current > self._last_seen:
                self._last_seen = current
        return current

    def observe(self, current: datetime) -> None:
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        with self._lock:
            if self._last_seen and current + self.maximum_rollback < self._last_seen:
                raise LeaseValidationError("Trusted clock rollback detected")
            if self._last_seen is None or current > self._last_seen:
                self._last_seen = current
