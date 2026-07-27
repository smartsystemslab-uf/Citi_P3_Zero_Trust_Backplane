from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe


@dataclass(frozen=True)
class Challenge:
    nonce: str
    subject_canonical_id: str
    subject_runtime_id: str
    issued_at: datetime
    expires_at: datetime


class InMemoryReplayGuard:
    """Prototype nonce/JTI guard.

    TODO(CITI-REPLAY): replace with a shared, atomic Redis/database store when
    multiple PDP replicas are deployed. A per-process cache is not sufficient in
    a horizontally scaled production deployment.
    """

    def __init__(self, nonce_ttl_seconds: int = 30, jti_ttl_seconds: int = 120):
        self.nonce_ttl_seconds = nonce_ttl_seconds
        self.jti_ttl_seconds = jti_ttl_seconds
        self._challenges: dict[str, Challenge] = {}
        self._used_jti: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def issue(self, subject_canonical_id: str, subject_runtime_id: str, now: datetime | None = None) -> Challenge:
        now = now or datetime.now(timezone.utc)
        challenge = Challenge(
            nonce=token_urlsafe(32),
            subject_canonical_id=subject_canonical_id,
            subject_runtime_id=subject_runtime_id,
            issued_at=now,
            expires_at=now + timedelta(seconds=self.nonce_ttl_seconds),
        )
        with self._lock:
            self._purge(now)
            self._challenges[challenge.nonce] = challenge
        return challenge

    def consume(
        self,
        *,
        nonce: str,
        jti: str,
        subject_canonical_id: str,
        subject_runtime_id: str,
        now: datetime,
    ) -> None:
        with self._lock:
            self._purge(now)
            if jti in self._used_jti:
                raise ValueError("request_replay_detected")
            challenge = self._challenges.pop(nonce, None)
            if challenge is None:
                raise ValueError("invalid_or_used_nonce")
            if challenge.expires_at < now:
                raise ValueError("expired_nonce")
            if (
                challenge.subject_canonical_id != subject_canonical_id
                or challenge.subject_runtime_id != subject_runtime_id
            ):
                raise ValueError("nonce_subject_binding_mismatch")
            self._used_jti[jti] = now + timedelta(seconds=self.jti_ttl_seconds)

    def _purge(self, now: datetime) -> None:
        self._challenges = {k: v for k, v in self._challenges.items() if v.expires_at >= now}
        self._used_jti = {k: v for k, v in self._used_jti.items() if v >= now}
