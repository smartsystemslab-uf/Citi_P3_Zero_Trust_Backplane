from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import sha256_hex
from .crypto import load_private_key, load_public_key, sign_mapping, verify_mapping
from .models import PDPResponse


class DecisionSigner:
    """Signs an envelope while keeping the JSON response schema unchanged."""

    def __init__(self, private_key: Ed25519PrivateKey, *, issuer: str, key_id: str):
        self.private_key = private_key
        self.issuer = issuer
        self.key_id = key_id

    @classmethod
    def from_file(cls, path: str | Path, *, issuer: str, key_id: str) -> "DecisionSigner":
        return cls(load_private_key(path), issuer=issuer, key_id=key_id)

    def headers(self, response: PDPResponse, *, request_hash: str) -> dict[str, str]:
        body = response.model_dump(mode="json")
        envelope = {"response": body, "request_hash": request_hash}
        return {
            "X-ZT-Decision-Issuer": self.issuer,
            "X-ZT-Decision-Key-Id": self.key_id,
            "X-ZT-Request-Hash": request_hash,
            "X-ZT-Decision-Digest": sha256_hex(envelope),
            "X-ZT-Decision-Signature": sign_mapping(self.private_key, envelope),
        }


def verify_decision_headers(
    body: dict[str, Any],
    headers: dict[str, str] | Any,
    public_key: Ed25519PublicKey | str | Path,
    *,
    expected_request_hash: str | None = None,
) -> bool:
    key = load_public_key(public_key) if isinstance(public_key, (str, Path)) else public_key
    digest = headers.get("X-ZT-Decision-Digest") or headers.get("x-zt-decision-digest")
    signature = headers.get("X-ZT-Decision-Signature") or headers.get("x-zt-decision-signature")
    request_hash = headers.get("X-ZT-Request-Hash") or headers.get("x-zt-request-hash")
    if not request_hash or (expected_request_hash is not None and request_hash != expected_request_hash):
        return False
    envelope = {"response": body, "request_hash": request_hash}
    return bool(digest == sha256_hex(envelope) and signature and verify_mapping(key, envelope, signature))
