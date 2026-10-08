"""Root-signed agent public keys, independent of policy authorization packages."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class RegistryError(ValueError):
    """Malformed registry, invalid registration, or unavailable verified state."""


class RegistryIntegrityError(RegistryError):
    """The configured trust anchor did not authenticate the registry."""


class _RegistryLoader(yaml.SafeLoader):
    """Keep timestamp scalars as strings and reject duplicate YAML keys."""

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise RegistryError("Registry contains an invalid or duplicate mapping key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


# Keep SafeLoader's strict scalar types but disable timestamp conversion only.
_RegistryLoader.yaml_implicit_resolvers = {
    key: [(tag, regex) for tag, regex in rules if tag != "tag:yaml.org,2002:timestamp"]
    for key, rules in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def canonical_payload(payload: Mapping[str, Any]) -> bytes:
    """Shared signed representation; unsupported objects and NaN are errors."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _fields(value: Any, expected: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise RegistryError("Registry has missing or unexpected fields")
    return value


def _text(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise RegistryError("Registry identifiers must be non-empty strings without surrounding whitespace")
    return value


def _decode(value: Any, length: int) -> bytes:
    try:
        if not isinstance(value, str):
            raise ValueError
        raw = base64.b64decode(value, validate=True)
        if len(raw) != length or base64.b64encode(raw).decode("ascii") != value:
            raise ValueError
        return raw
    except (ValueError, UnicodeError) as exc:
        raise RegistryError("Invalid Base64 encoding or key/signature length") from exc


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise RegistryError("A timezone-aware datetime is required")
    return value.astimezone(timezone.utc)


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value
    ):
        raise RegistryError("Registry timestamps must be RFC 3339 UTC strings")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RegistryError("Invalid registry timestamp") from exc


@dataclass(frozen=True)
class AgentKeyRecord:
    """Immutable authenticated metadata; only lookup returns eligible records."""

    key_id: str
    public_key: str
    status: str
    valid_from: datetime
    valid_until: datetime | None

    def as_public_key(self) -> Ed25519PublicKey:
        """Obtain the key object used by AUTHN-3 to verify request signatures."""
        return Ed25519PublicKey.from_public_bytes(_decode(self.public_key, 32))


def _validate_payload(payload: Any) -> dict[str, tuple[AgentKeyRecord, ...]]:
    payload = _fields(payload, {"schema_version", "signing_key_id", "identities"})
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise RegistryError("Unsupported registry schema version")
    _text(payload["signing_key_id"])
    identities = payload["identities"]
    if not isinstance(identities, dict) or not identities:
        raise RegistryError("Registry identities must be a non-empty mapping")
    result = {}
    for identity, entries in identities.items():
        _text(identity)
        if not isinstance(entries, list) or not entries:
            raise RegistryError("Each identity requires a non-empty list of key records")
        records = []
        seen = set()
        for entry in entries:
            entry = _fields(entry, {"key_id", "public_key", "status", "valid_from", "valid_until"})
            raw = _decode(entry["public_key"], 32)
            key_id = hashlib.sha256(raw).hexdigest()
            if entry["key_id"] != key_id or key_id in seen:
                raise RegistryError("Duplicate or inconsistent agent key ID")
            seen.add(key_id)
            if entry["status"] not in ("active", "revoked"):
                raise RegistryError("Unsupported agent key status")
            start = _parse_time(entry["valid_from"])
            end = None if entry["valid_until"] is None else _parse_time(entry["valid_until"])
            if end is not None and end <= start:
                raise RegistryError("Key validity end must be after its start")
            records.append(AgentKeyRecord(key_id, entry["public_key"], entry["status"], start, end))
        result[identity] = tuple(records)
    return result


def _private_key(path: Path) -> Ed25519PrivateKey:
    raw = Path(path).read_bytes()
    try:
        if not raw.startswith(b"-----BEGIN PRIVATE KEY-----"):
            raise ValueError
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError
        return key
    except (ValueError, TypeError) as exc:
        raise RegistryError("Registry root must be an unencrypted PEM PKCS8 Ed25519 private key") from exc


def _public_key(path: Path) -> Ed25519PublicKey:
    raw = Path(path).read_bytes()
    try:
        if not raw.startswith(b"-----BEGIN PUBLIC KEY-----"):
            raise ValueError
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError
        return key
    except (ValueError, TypeError) as exc:
        raise RegistryError("Registry root must be a PEM SubjectPublicKeyInfo Ed25519 public key") from exc


def _verified_payload(path: Path, root: Ed25519PublicKey, root_id: str) -> tuple[dict, dict]:
    try:
        envelope = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=_RegistryLoader)
    except (yaml.YAMLError, RecursionError, UnicodeError) as exc:
        raise RegistryError("Cannot parse registry YAML") from exc
    envelope = _fields(envelope, {"payload", "signature"})
    payload = envelope["payload"]
    records = _validate_payload(payload)
    if payload["signing_key_id"] != root_id:
        raise RegistryIntegrityError("Registry signing key ID does not match configured trust anchor")
    signature = _decode(envelope["signature"], 64)
    try:
        root.verify(signature, canonical_payload(payload))
    except InvalidSignature as exc:
        raise RegistryIntegrityError("Registry root signature verification failed") from exc
    return payload, records


class PublicKeyRegistry:
    """Pinned-root registry snapshot. Call reload explicitly to observe changes."""

    def __init__(self, path: Path, root: Ed25519PublicKey, root_id: str):
        self._path = Path(path)
        self._root = root
        self._root_id = _text(root_id)
        self._records: Mapping[str, tuple[AgentKeyRecord, ...]] | None = None
        self.reload()

    @classmethod
    def from_yaml(cls, path: Path, *, root_public_key_path: Path,
                  expected_root_key_id: str) -> "PublicKeyRegistry":
        """Authenticate a registry against an independently provisioned PEM root."""
        return cls(path, _public_key(root_public_key_path), expected_root_key_id)

    def reload(self) -> None:
        """Publish a fully verified snapshot; any failure invalidates old state."""
        self._records = None
        _, records = _verified_payload(self._path, self._root, self._root_id)
        self._records = MappingProxyType(records)

    def lookup(self, agent_identity: str, *, key_id: str | None = None,
               at: datetime | None = None) -> tuple[AgentKeyRecord, ...]:
        """Return all eligible keys, or an empty tuple; never supply a fallback."""
        records = self._records
        if records is None:
            raise RegistryIntegrityError("Registry unavailable until a verified reload succeeds")
        now = _utc(at if at is not None else datetime.now(timezone.utc))
        return tuple(record for record in records.get(agent_identity, ())
                     if record.status == "active"
                     and (key_id is None or record.key_id == key_id)
                     and record.valid_from <= now
                     and (record.valid_until is None or now < record.valid_until))


def validate_bootstrap_registry(registry_path: Path, *, root_private_key_path: Path,
                                root_key_id: str, agent_identities: list[str]) -> None:
    """Preflight signing and disallow rebootstrap of any registered identity."""
    root = _private_key(root_private_key_path)
    _text(root_key_id)
    if Path(registry_path).exists():
        _, records = _verified_payload(registry_path, root.public_key(), root_key_id)
        if any(identity in records for identity in agent_identities):
            raise RegistryError("Identity already registered; use the future rotation workflow, not rebootstrap")


def write_signed_registry(public_keys: Mapping[str, str], registry_path: Path, *,
                          root_private_key_path: Path, root_key_id: str,
                          valid_from: datetime) -> None:
    """Verify and merge registrations, then atomically publish one signed file.

    Writers must be externally serialized. Key replacement is reserved for the
    future rotation workflow; existing lifecycle metadata is never overwritten.
    """
    root = _private_key(root_private_key_path)
    root_id = _text(root_key_id)
    start = _utc(valid_from).isoformat().replace("+00:00", "Z")
    if not isinstance(public_keys, Mapping) or not public_keys:
        raise RegistryError("Registration requires a non-empty public-key mapping")
    additions = {}
    for identity, public_key in public_keys.items():
        _text(identity)
        raw = _decode(public_key, 32)
        additions[identity] = [{"key_id": hashlib.sha256(raw).hexdigest(),
                                "public_key": public_key, "status": "active",
                                "valid_from": start, "valid_until": None}]
    path = Path(registry_path)
    if path.resolve() == Path(root_private_key_path).resolve():
        raise RegistryError("Registry destination cannot overwrite its root private key")
    payload = {"schema_version": 1, "signing_key_id": root_id, "identities": {}}
    if path.exists():
        payload, _ = _verified_payload(path, root.public_key(), root_id)
    changed = False
    for identity, entries in additions.items():
        existing = payload["identities"].get(identity)
        if existing is not None:
            if not any(record["public_key"] == entries[0]["public_key"] for record in existing):
                raise RegistryError("Agent key replacement requires the future rotation workflow")
            continue
        payload["identities"][identity] = entries
        changed = True
    _validate_payload(payload)
    if not changed:
        return
    envelope = {"payload": payload,
                "signature": base64.b64encode(root.sign(canonical_payload(payload))).decode("ascii")}
    contents = yaml.safe_dump(envelope, sort_keys=True, allow_unicode=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=".registry-", suffix=".tmp",
                                         delete=False) as file:
            temp_path = Path(file.name)
            file.write(contents)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()
