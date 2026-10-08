"""Shared ephemeral keys for AUTHN unit and integration tests."""

import base64
import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zt_task6.registry import PublicKeyRegistry, canonical_payload, write_signed_registry


NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)


@pytest.fixture
def env(tmp_path):
    root = Ed25519PrivateKey.generate()
    private = tmp_path / "root-private.pem"
    public = tmp_path / "root-public.pem"
    private.write_bytes(root.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    public.write_bytes(root.public_key().public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo))
    agent = Ed25519PrivateKey.generate()
    raw = agent.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = base64.b64encode(raw).decode("ascii")
    return SimpleNamespace(root=root, private=private, public=public, agent=agent,
                           key=key, key_id=hashlib.sha256(raw).hexdigest(),
                           path=tmp_path / "registry.yaml", dir=tmp_path)


def publish(env, keys=None, at=NOW):
    write_signed_registry(keys or {"agent": env.key}, env.path,
                          root_private_key_path=env.private, root_key_id="root-v1", valid_from=at)


def load(env, **kwargs):
    return PublicKeyRegistry.from_yaml(env.path, root_public_key_path=kwargs.get("root", env.public),
                                      expected_root_key_id=kwargs.get("root_id", "root-v1"))


def read_envelope(env):
    return yaml.safe_load(env.path.read_text(encoding="utf-8"))


def put_envelope(env, envelope, sign=True):
    if sign:
        envelope["signature"] = base64.b64encode(
            env.root.sign(canonical_payload(envelope["payload"]))
        ).decode("ascii")
    env.path.write_text(yaml.safe_dump(envelope), encoding="utf-8")
