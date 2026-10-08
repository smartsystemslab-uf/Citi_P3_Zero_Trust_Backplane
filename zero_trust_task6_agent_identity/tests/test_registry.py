import base64
import copy
import hashlib
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from zt_task6 import registry
from zt_task6.registry import RegistryError, RegistryIntegrityError
from conftest import NOW, load, publish, put_envelope, read_envelope


def test_known_unknown_and_exact_lookup(env):
    publish(env, at=NOW - timedelta(days=1))
    store = load(env)
    records = store.lookup("agent", at=NOW)
    assert len(records) == 1
    record = records[0]
    assert record.key_id == env.key_id and record.public_key == env.key
    record.as_public_key().verify(env.agent.sign(b"request"), b"request")
    assert store.lookup("agent", key_id=env.key_id, at=NOW) == records
    assert store.lookup("agent", key_id="missing", at=NOW) == ()
    assert store.lookup("missing", at=NOW) == ()
    assert store.lookup(" agent", at=NOW) == ()
    assert store.lookup("agent")
    with pytest.raises(FrozenInstanceError):
        record.status = "revoked"
    with pytest.raises(RegistryError, match="timezone-aware"):
        store.lookup("agent", at=datetime(2026, 10, 8))


def test_multiple_keys_status_and_validity_boundaries(env):
    publish(env)
    envelope = read_envelope(env)
    records = envelope["payload"]["identities"]["agent"]
    records[0]["valid_until"] = (NOW + timedelta(seconds=1)).isoformat()
    for status, start, end in [
        ("active", NOW, None), ("revoked", NOW, None),
        ("active", NOW + timedelta(days=1), None),
        ("active", NOW - timedelta(days=2), NOW - timedelta(days=1)),
    ]:
        key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        records.append(dict(key_id=hashlib.sha256(key).hexdigest(),
                            public_key=base64.b64encode(key).decode(), status=status,
                            valid_from=start.isoformat(), valid_until=end.isoformat() if end else None))
    put_envelope(env, envelope)
    store = load(env)
    assert store.lookup("agent", at=NOW - timedelta(microseconds=1)) == ()
    assert len(store.lookup("agent", at=NOW)) == 2
    assert len(store.lookup("agent", at=NOW + timedelta(seconds=1))) == 1
    assert store.lookup("agent", key_id=records[2]["key_id"], at=NOW) == ()


@pytest.mark.parametrize("part", ["status", "public_key", "valid_from"])
def test_valid_shaped_tampering_rejected(env, part):
    publish(env)
    envelope = read_envelope(env)
    record = envelope["payload"]["identities"]["agent"][0]
    if part == "public_key":
        raw = b"x" * 32
        record["public_key"] = base64.b64encode(raw).decode()
        record["key_id"] = hashlib.sha256(raw).hexdigest()
    else:
        record[part] = "revoked" if part == "status" else "2026-10-09T00:00:00Z"
    put_envelope(env, envelope, sign=False)
    with pytest.raises(RegistryIntegrityError):
        load(env)


def test_wrong_signature_root_and_key_id(env):
    publish(env)
    with pytest.raises(RegistryIntegrityError):
        load(env, root_id="other")
    other = env.dir / "other.pem"
    other.write_bytes(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(RegistryIntegrityError):
        load(env, root=other)
    envelope = read_envelope(env)
    envelope["signature"] = base64.b64encode(b"x" * 64).decode()
    put_envelope(env, envelope, sign=False)
    with pytest.raises(RegistryIntegrityError):
        load(env)


@pytest.mark.parametrize("raw", [
    "public_keys: {agent: abc}", "{}", "[]", "payload: [", "!!python/object:danger {}",
    "payload: {}\npayload: {}\nsignature: abc", "? [a, b]\n: x",
    "payload: {}\nsignature: abc\nextra: true",
    "payload: {schema_version: 1, signing_key_id: root-v1, identities: {agent: [], agent: []}}\nsignature: abc",
])
def test_bad_envelope_and_yaml(env, raw):
    env.path.write_text(raw, encoding="utf-8")
    with pytest.raises(RegistryError):
        load(env)


@pytest.mark.parametrize("field,value", [
    ("schema_version", 2), ("schema_version", True), ("schema_version", "1"),
    ("signing_key_id", ""), ("identities", []), ("identities", {}),
    ("identities", {" agent": []}), ("identities", {"agent": {}}),
    ("identities", {"agent": []}),
])
def test_bad_payload(env, field, value):
    publish(env)
    envelope = read_envelope(env)
    envelope["payload"][field] = value
    put_envelope(env, envelope)
    with pytest.raises(RegistryError):
        load(env)


@pytest.mark.parametrize("field,value", [
    ("key_id", "wrong"), ("public_key", "!bad"), ("public_key", "é"),
    ("public_key", 12), ("public_key", base64.b64encode(b"x").decode()),
    ("public_key", base64.b64encode(b"x" * 32).decode() + "="),
    ("status", "unknown"), ("status", None),
    ("valid_from", "2026-10-08"), ("valid_from", "2026-99-08T00:00:00Z"),
    ("valid_from", "2026-10-08T00:00:00+01:00"), ("valid_from", 12),
    ("valid_until", "2026-10-08T00:00:00Z"),
    ("valid_until", "2026-10-07T00:00:00Z"),
])
def test_bad_record(env, field, value):
    publish(env)
    envelope = read_envelope(env)
    envelope["payload"]["identities"]["agent"][0][field] = value
    put_envelope(env, envelope)
    with pytest.raises(RegistryError):
        load(env)


@pytest.mark.parametrize("kind", ["duplicate", "missing", "extra", "missing_signature", "bad_signature"])
def test_incomplete_and_duplicate_records(env, kind):
    publish(env)
    envelope = read_envelope(env)
    records = envelope["payload"]["identities"]["agent"]
    if kind == "duplicate":
        records.append(copy.deepcopy(records[0]))
    elif kind == "missing":
        del records[0]["status"]
    elif kind == "extra":
        records[0]["private_key"] = "forbidden"
    elif kind == "missing_signature":
        del envelope["signature"]
    else:
        envelope["signature"] = "bad"
    put_envelope(env, envelope, sign=False)
    with pytest.raises(RegistryError):
        load(env)


def test_reload_and_failed_reload_recovery(env):
    publish(env)
    store = load(env)
    publish(env, {"new_agent": env.key})
    assert store.lookup("new_agent", at=NOW) == ()
    store.reload()
    assert store.lookup("new_agent", at=NOW)
    valid = env.path.read_bytes()
    env.path.write_text("{}", encoding="utf-8")
    with pytest.raises(RegistryError):
        store.reload()
    with pytest.raises(RegistryIntegrityError, match="unavailable"):
        store.lookup("agent", at=NOW)
    env.path.unlink()
    with pytest.raises(OSError):
        store.reload()
    with pytest.raises(RegistryIntegrityError):
        store.lookup("agent")
    env.path.write_bytes(valid)
    store.reload()
    assert store.lookup("agent", at=NOW)


def test_idempotence_preserves_revocation_expiry_and_unrelated(env):
    publish(env)
    envelope = read_envelope(env)
    record = envelope["payload"]["identities"]["agent"][0]
    record.update(status="revoked", valid_until="2026-10-09T00:00:00Z")
    put_envelope(env, envelope)
    before = env.path.read_bytes()
    publish(env, at=NOW + timedelta(days=1))
    assert env.path.read_bytes() == before
    publish(env, {"other": env.key})
    assert read_envelope(env)["payload"]["identities"]["agent"][0] == record
    assert load(env).lookup("agent", at=NOW) == ()
    assert load(env).lookup("other", at=NOW)


def test_replacement_invalid_input_and_tampered_existing_preserve_file(env):
    publish(env)
    before = env.path.read_bytes()
    other = base64.b64encode(b"x" * 32).decode()
    with pytest.raises(RegistryError, match="rotation"):
        publish(env, {"agent": other})
    assert env.path.read_bytes() == before
    for keys in ({}, [], {"": env.key}, {"agent": "bad"}, {" agent": env.key}):
        with pytest.raises(RegistryError):
            registry.write_signed_registry(keys, env.path, root_private_key_path=env.private,
                                           root_key_id="root-v1", valid_from=NOW)
        assert env.path.read_bytes() == before
    env.path.write_text("public_keys: {}", encoding="utf-8")
    with pytest.raises(RegistryError):
        publish(env)
    assert env.path.read_text() == "public_keys: {}"


def test_atomic_failure_preserves_old_file_and_cleans_temp(env, monkeypatch):
    publish(env)
    before = env.path.read_bytes()
    def fail(*args):
        raise OSError("simulated replacement failure")
    monkeypatch.setattr(registry.os, "replace", fail)
    with pytest.raises(OSError):
        publish(env, {"new": env.key})
    assert env.path.read_bytes() == before
    assert not list(env.dir.glob(".registry-*.tmp"))


@pytest.mark.parametrize("kind", ["private", "public"])
@pytest.mark.parametrize("encoding", ["wrong_type", "invalid", "wrong_header"])
def test_invalid_root_keys(env, kind, encoding):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = env.private if kind == "private" else env.public
    if encoding == "wrong_type":
        raw = (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()) if kind == "private" else
               key.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo))
    elif encoding == "invalid":
        raw = b"-----BEGIN PRIVATE KEY-----\nbad" if kind == "private" else b"-----BEGIN PUBLIC KEY-----\nbad"
    else:
        raw = b"not PEM"
    if kind == "public":
        publish(env)
    path.write_bytes(raw)
    with pytest.raises(RegistryError):
        publish(env) if kind == "private" else load(env)


def test_strict_canonicalization_and_utc_conversion(env):
    assert registry.canonical_payload({"b": "é", "a": 1}) == '{"a":1,"b":"é"}'.encode()
    with pytest.raises(TypeError):
        registry.canonical_payload({"value": object()})
    with pytest.raises(ValueError):
        registry.canonical_payload({"value": float("nan")})
    with pytest.raises(RegistryError):
        publish(env, at=NOW.replace(tzinfo=None))
    publish(env, at=NOW.astimezone(timezone(timedelta(hours=2))))
    assert load(env).lookup("agent", at=NOW)
    with pytest.raises(RegistryError):
        registry.write_signed_registry({"agent": env.key}, env.private,
                                       root_private_key_path=env.private,
                                       root_key_id="root-v1", valid_from=NOW)


def test_bootstrap_preflight(env):
    kwargs = dict(root_private_key_path=env.private, root_key_id="root-v1")
    registry.validate_bootstrap_registry(env.path, agent_identities=["agent"], **kwargs)
    publish(env)
    registry.validate_bootstrap_registry(env.path, agent_identities=["new"], **kwargs)
    with pytest.raises(RegistryError, match="rotation"):
        registry.validate_bootstrap_registry(env.path, agent_identities=["agent"], **kwargs)
    with pytest.raises(RegistryError):
        registry.validate_bootstrap_registry(env.path, agent_identities=["new"],
                                             root_private_key_path=env.private, root_key_id="")
