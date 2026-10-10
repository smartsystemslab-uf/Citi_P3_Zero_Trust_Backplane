import base64
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature

from zt_task6.payload_format import canonical_request_payload
from zt_task6.registry import PublicKeyRegistry


class IdentityVerificationError(ValueError):
    pass


class ReplayDetectedError(IdentityVerificationError):
    pass


class ExpiredRequestError(IdentityVerificationError):
    pass


class NonceCache:
    def __init__(self) -> None:
        self._seen: dict[str, datetime] = {}

    def check_and_store(
        self,
        nonce: str,
        *,
        now: datetime,
        lifetime: timedelta,
    ) -> None:
        expired = [
            value
            for value, expires_at in self._seen.items()
            if expires_at <= now
        ]

        for value in expired:
            del self._seen[value]

        if nonce in self._seen:
            raise ReplayDetectedError("Request nonce has already been used")

        self._seen[nonce] = now + lifetime

class RequestVerifier:
    def __init__(
        self,
        registry: PublicKeyRegistry,
        *,
        max_age_seconds: int = 60,
    ) -> None:
        self.registry = registry
        self.max_age = timedelta(seconds=max_age_seconds)
        self.nonces = NonceCache()

    def verify(
        self,
        request: dict[str, str],
        *,
        now: datetime | None = None,
    ) -> None:
        required = {
            "caller_runtime_id",
            "target_tool",
            "nonce",
            "timestamp",
            "key_id",
            "signature",
        }

        if set(request) != required:
            raise IdentityVerificationError(
                "Signed request contains missing or unexpected fields"
            )

        current_time = now or datetime.now(timezone.utc)

        try:
            timestamp = datetime.fromisoformat(
                request["timestamp"].replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise IdentityVerificationError(
                "Invalid request timestamp"
            ) from exc

        if timestamp.tzinfo is None:
            raise IdentityVerificationError(
                "Request timestamp must include timezone information"
            )

        timestamp = timestamp.astimezone(timezone.utc)

        age = current_time - timestamp

        if age < timedelta(0) or age > self.max_age:
            raise ExpiredRequestError(
                "Request timestamp is outside the allowed validity window"
            )

        payload = {
            "caller_runtime_id": request["caller_runtime_id"],
            "target_tool": request["target_tool"],
            "nonce": request["nonce"],
            "timestamp": request["timestamp"],
        }

        payload_bytes = canonical_request_payload(payload)

        records = self.registry.lookup(
            request["caller_runtime_id"],
            key_id=request["key_id"],
            at=current_time,
        )

        if not records:
            raise IdentityVerificationError(
                "No eligible public key exists for caller identity"
            )

        try:
            signature = base64.b64decode(
                request["signature"],
                validate=True,
            )
        except ValueError as exc:
            raise IdentityVerificationError(
                "Invalid Base64 request signature"
            ) from exc

        verified = False

        for record in records:
            try:
                record.as_public_key().verify(
                    signature,
                    payload_bytes,
                )
                verified = True
                break
            except InvalidSignature:
                continue

        if not verified:
            raise IdentityVerificationError(
                "Request signature verification failed"
            )

        self.nonces.check_and_store(
            request["nonce"],
            now=current_time,
            lifetime=self.max_age,
        )