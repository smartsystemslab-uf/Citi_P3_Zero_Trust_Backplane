import base64
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from zt_task6.payload_format import canonical_request_payload


def load_private_key(path: Path) -> Ed25519PrivateKey:
    encoded = Path(path).read_text(encoding="utf-8").strip()

    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ValueError("Private key is not valid Base64") from exc

    if len(raw) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")

    return Ed25519PrivateKey.from_private_bytes(raw)


def key_id_for_private_key(private_key: Ed25519PrivateKey) -> str:
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return hashlib.sha256(public_bytes).hexdigest()


def sign_request(
    caller_runtime_id: str,
    target_tool: str,
    private_key_path: Path,
    *,
    nonce: str | None = None,
    timestamp: str | None = None,
) -> dict[str, str]:
    private_key = load_private_key(private_key_path)

    if nonce is None:
        nonce = secrets.token_urlsafe(24)

    if timestamp is None:
        timestamp = (
            datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    payload = {
        "caller_runtime_id": caller_runtime_id,
        "target_tool": target_tool,
        "nonce": nonce,
        "timestamp": timestamp,
    }

    payload_bytes = canonical_request_payload(payload)

    signature = private_key.sign(payload_bytes)

    return {
        **payload,
        "key_id": key_id_for_private_key(private_key),
        "signature": base64.b64encode(signature).decode("ascii"),
    }