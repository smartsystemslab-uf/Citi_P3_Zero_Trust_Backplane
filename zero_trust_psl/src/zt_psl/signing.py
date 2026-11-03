"""Detached Ed25519 signatures for PSL policy files.

Same sidecar format and canonical JSON as the Task 4 YAML bundles
(``NAME.sig.json`` next to ``NAME.psl``). The signed mapping binds the file name
and the SHA-256 of its exact bytes::

    {"kind": "zt_psl_policy", "file": "ledger_access.psl", "sha256": "<hex>"}

so any edit of a policy (including whitespace or annotations) invalidates the
signature. Verification needs the issuer's public key from the caller's trust
store; nothing here trusts a key found next to the file.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIDECAR_SUFFIX = ".sig.json"


class PolicySignatureError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def signed_payload(path: Path) -> dict[str, str]:
    return {"kind": "zt_psl_policy", "file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def sidecar_path(path: Path) -> Path:
    return path.with_name(path.name + SIDECAR_SUFFIX) if path.suffix != ".psl" else path.with_suffix(SIDECAR_SUFFIX)


def sign_file(path: str | Path, private_key: Ed25519PrivateKey, *, issuer: str, key_id: str) -> Path:
    p = Path(path)
    payload = signed_payload(p)
    sidecar = {
        "schema_version": "1.0",
        "kind": "zt_psl_policy",
        "issuer": issuer,
        "key_id": key_id,
        "algorithm": "Ed25519",
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "file": payload["file"],
        "file_sha256": payload["sha256"],
        "signature": _b64url(private_key.sign(canonical_json(payload))),
    }
    out = sidecar_path(p)
    out.write_text(json.dumps(sidecar, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def verify_file(path: str | Path, public_key_for: Callable[[str, str], Ed25519PublicKey]) -> dict[str, Any]:
    """Verify ``path`` against its sidecar. ``public_key_for(issuer, key_id)`` must
    return a key from the caller's trust store (and raise if it does not trust it)."""
    p = Path(path)
    sc = sidecar_path(p)
    if not sc.exists():
        raise PolicySignatureError(f"missing signature sidecar for {p.name}: {sc.name}")
    meta = json.loads(sc.read_text(encoding="utf-8"))
    payload = signed_payload(p)
    if meta.get("kind") != "zt_psl_policy" or meta.get("file") != p.name:
        raise PolicySignatureError(f"signature sidecar of {p.name} does not belong to this file")
    if meta.get("file_sha256") != payload["sha256"]:
        raise PolicySignatureError(f"policy file changed after signing: {p.name}")
    key = public_key_for(str(meta.get("issuer")), str(meta.get("key_id")))
    try:
        key.verify(_b64url_decode(str(meta.get("signature", ""))), canonical_json(payload))
    except (InvalidSignature, ValueError) as exc:
        raise PolicySignatureError(f"invalid policy signature: {p.name}") from exc
    return meta


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("policy signing key must be Ed25519")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("policy verification key must be Ed25519")
    return key
