from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from uuid import uuid4

from .models import PermitLeaseClaims


@dataclass
class CachedLease:
    token: str
    claims: PermitLeaseClaims
    boot_id: str


class LeaseCache:
    """Local PEP cache. Restart clears all leases and disables timeout fallback."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._items: dict[tuple[str, str, str, str], CachedLease] = {}
        self.boot_id = str(uuid4())
        self.recovery_required = False

    @staticmethod
    def _key(
        request_hash: str,
        pep_key_thumbprint: str,
        audience: str,
        endpoint: str,
    ) -> tuple[str, str, str, str]:
        return request_hash, pep_key_thumbprint, audience, endpoint

    def put(self, token: str, claims: PermitLeaseClaims) -> None:
        with self._lock:
            key = self._key(
                claims.request_hash,
                claims.pep_key_thumbprint,
                claims.audience,
                claims.endpoint,
            )
            self._items[key] = CachedLease(token=token, claims=claims, boot_id=self.boot_id)

    def get_matching(
        self,
        *,
        request_hash: str,
        pep_key_thumbprint: str,
        audience: str,
        endpoint: str,
        now: datetime | None = None,
    ) -> CachedLease | None:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            if self.recovery_required:
                return None
            key = self._key(request_hash, pep_key_thumbprint, audience, endpoint)
            item = self._items.get(key)
            if item is None:
                return None
            if item.boot_id != self.boot_id or item.claims.expires_at <= now:
                self._items.pop(key, None)
                return None
            return item

    def remove(self, permit_id: str) -> None:
        with self._lock:
            for key in list(self._items):
                if self._items[key].claims.permit_id == permit_id:
                    self._items.pop(key, None)

    def restart(self) -> None:
        with self._lock:
            self._items.clear()
            self.boot_id = str(uuid4())
            self.recovery_required = True

    def mark_synchronized(self) -> None:
        with self._lock:
            self.recovery_required = False

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
