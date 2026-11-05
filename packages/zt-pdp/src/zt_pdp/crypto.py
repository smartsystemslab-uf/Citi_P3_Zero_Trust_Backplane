from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    raw = Path(path).read_bytes()
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"not an Ed25519 private key: {path}")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    raw = Path(path).read_bytes()
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"not an Ed25519 public key: {path}")
    return key


def sign_mapping(private_key: Ed25519PrivateKey, value: Any) -> str:
    return b64url_encode(private_key.sign(canonical_json(value)))


def verify_mapping(public_key: Ed25519PublicKey, value: Any, signature: str) -> bool:
    try:
        public_key.verify(b64url_decode(signature), canonical_json(value))
        return True
    except (InvalidSignature, ValueError):
        return False


def generate_keypair(private_path: str | Path, public_path: str | Path) -> None:
    private_path = Path(private_path)
    public_path = Path(public_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


class TrustedKeyStore:
    def __init__(self, config_path: str | Path):
        self.config_path = Path(config_path)
        raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        base = self.config_path.parent
        self._keys: dict[tuple[str, str], Ed25519PublicKey] = {}
        self._purposes: dict[tuple[str, str], set[str]] = {}
        for issuer in raw.get("issuers", []):
            issuer_id = str(issuer["id"])
            for item in issuer.get("keys", []):
                key_id = str(item["key_id"])
                key_path = Path(str(item["public_key_file"]))
                if not key_path.is_absolute():
                    key_path = (base / key_path).resolve()
                self._keys[(issuer_id, key_id)] = load_public_key(key_path)
                self._purposes[(issuer_id, key_id)] = set(item.get("purposes", []))

    def get(self, issuer: str, key_id: str, purpose: str) -> Ed25519PublicKey:
        key = self._keys.get((issuer, key_id))
        if key is None:
            raise ValueError(f"untrusted issuer/key: {issuer}/{key_id}")
        purposes = self._purposes[(issuer, key_id)]
        if purpose not in purposes:
            raise ValueError(f"key {issuer}/{key_id} not trusted for {purpose}")
        return key
