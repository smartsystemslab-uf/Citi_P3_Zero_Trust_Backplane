from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import LeaseValidationError


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_thumbprint(public_key: Ed25519PublicKey) -> str:
    return "sha256:" + hashlib.sha256(public_key_bytes(public_key)).hexdigest()


@dataclass
class KeyRecord:
    key_id: str
    public_key: Ed25519PublicKey
    private_key: Ed25519PrivateKey | None = None
    revoked: bool = False


class Ed25519KeyRing:
    """Small prototype key ring with overlap and emergency revocation support."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyRecord] = {}
        self._active_key_id: str | None = None

    @classmethod
    def with_generated_key(cls, key_id: str = "task5-permit-key-v1") -> "Ed25519KeyRing":
        ring = cls()
        ring.add_private_key(key_id, Ed25519PrivateKey.generate(), make_active=True)
        return ring

    @property
    def active_key_id(self) -> str:
        if not self._active_key_id:
            raise RuntimeError("No active signing key is configured")
        return self._active_key_id

    def add_private_key(
        self,
        key_id: str,
        private_key: Ed25519PrivateKey,
        *,
        make_active: bool = False,
    ) -> None:
        self._keys[key_id] = KeyRecord(
            key_id=key_id,
            private_key=private_key,
            public_key=private_key.public_key(),
        )
        if make_active or self._active_key_id is None:
            self._active_key_id = key_id

    def add_public_key(self, key_id: str, public_key: Ed25519PublicKey) -> None:
        self._keys[key_id] = KeyRecord(key_id=key_id, public_key=public_key)

    def rotate(self, key_id: str, private_key: Ed25519PrivateKey | None = None) -> None:
        self.add_private_key(key_id, private_key or Ed25519PrivateKey.generate(), make_active=True)

    def revoke(self, key_id: str) -> None:
        if key_id in self._keys:
            self._keys[key_id].revoked = True
        if self._active_key_id == key_id:
            self._active_key_id = None

    def sign(self, data: bytes) -> tuple[str, str]:
        record = self._keys[self.active_key_id]
        if record.revoked or record.private_key is None:
            raise RuntimeError("The active signing key is unavailable or revoked")
        return record.key_id, b64url_encode(record.private_key.sign(data))

    def verify(self, key_id: str, data: bytes, signature: str) -> None:
        record = self._keys.get(key_id)
        if record is None:
            raise LeaseValidationError(f"Unknown signing key: {key_id}")
        if record.revoked:
            raise LeaseValidationError(f"Revoked signing key: {key_id}")
        try:
            record.public_key.verify(b64url_decode(signature), data)
        except InvalidSignature as exc:
            raise LeaseValidationError("Invalid Ed25519 signature") from exc

    def get_public_key(self, key_id: str) -> Ed25519PublicKey:
        record = self._keys.get(key_id)
        if record is None or record.revoked:
            raise LeaseValidationError(f"Unknown or revoked key: {key_id}")
        return record.public_key

    def export_public_key_pem(self, key_id: str) -> bytes:
        return self.get_public_key(key_id).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
