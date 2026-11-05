from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from .replay_cache import ReplayCache


class NonceService:
    def __init__(self, replay_cache: ReplayCache | None = None) -> None:
        self.replay_cache = replay_cache or ReplayCache()

    def issue(self, bytes_length: int = 24) -> str:
        return secrets.token_urlsafe(bytes_length)

    def consume(self, nonce: str, ttl_seconds: int = 60) -> None:
        self.replay_cache.consume_once(
            "nonce",
            nonce,
            datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        )
