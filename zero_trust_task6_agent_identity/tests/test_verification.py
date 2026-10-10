import base64
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import NOW, load, publish
from zt_task6.signing import sign_request
from zt_task6.verification import (
    ExpiredRequestError,
    IdentityVerificationError,
    ReplayDetectedError,
    RequestVerifier,
)


def write_private_key(private_key, path):
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    path.write_text(
        base64.b64encode(raw).decode("ascii"),
        encoding="utf-8",
    )

    return path


def timestamp(value):
    return value.isoformat().replace("+00:00", "Z")


def test_valid_signed_request_is_accepted(env, tmp_path):
    publish(env, at=NOW - timedelta(days=1))
    registry = load(env)

    key_path = write_private_key(
        env.agent,
        tmp_path / "agent.key",
    )

    request = sign_request(
        "agent",
        "test_tool",
        key_path,
        nonce="nonce-valid",
        timestamp=timestamp(NOW),
    )

    verifier = RequestVerifier(
        registry,
        max_age_seconds=60,
    )

    verifier.verify(request, now=NOW)


def test_impersonation_is_rejected(env, tmp_path):
    publish(env, at=NOW - timedelta(days=1))
    registry = load(env)

    attacker_key = Ed25519PrivateKey.generate()

    attacker_path = write_private_key(
        attacker_key,
        tmp_path / "attacker.key",
    )

    request = sign_request(
        "agent",
        "test_tool",
        attacker_path,
        nonce="nonce-attacker",
        timestamp=timestamp(NOW),
    )

    # Pretend the attacker is using the legitimate agent's key ID.
    # The registry will therefore return the legitimate public key,
    # but the attacker's signature will not verify against it.
    request["key_id"] = env.key_id

    verifier = RequestVerifier(
        registry,
        max_age_seconds=60,
    )

    with pytest.raises(
        IdentityVerificationError,
        match="signature verification failed",
    ):
        verifier.verify(request, now=NOW)


def test_replayed_nonce_is_rejected(env, tmp_path):
    publish(env, at=NOW - timedelta(days=1))
    registry = load(env)

    key_path = write_private_key(
        env.agent,
        tmp_path / "agent.key",
    )

    request = sign_request(
        "agent",
        "test_tool",
        key_path,
        nonce="nonce-replay",
        timestamp=timestamp(NOW),
    )

    verifier = RequestVerifier(
        registry,
        max_age_seconds=60,
    )

    verifier.verify(request, now=NOW)

    with pytest.raises(
        ReplayDetectedError,
        match="already been used",
    ):
        verifier.verify(request, now=NOW)


def test_expired_request_is_rejected(env, tmp_path):
    publish(env, at=NOW - timedelta(days=1))
    registry = load(env)

    key_path = write_private_key(
        env.agent,
        tmp_path / "agent.key",
    )

    old_time = NOW - timedelta(seconds=61)

    request = sign_request(
        "agent",
        "test_tool",
        key_path,
        nonce="nonce-expired",
        timestamp=timestamp(old_time),
    )

    verifier = RequestVerifier(
        registry,
        max_age_seconds=60,
    )

    with pytest.raises(
        ExpiredRequestError,
        match="outside the allowed validity window",
    ):
        verifier.verify(request, now=NOW)


def test_tampered_target_tool_is_rejected(env, tmp_path):
    publish(env, at=NOW - timedelta(days=1))
    registry = load(env)

    key_path = write_private_key(
        env.agent,
        tmp_path / "agent.key",
    )

    request = sign_request(
        "agent",
        "safe_tool",
        key_path,
        nonce="nonce-tamper",
        timestamp=timestamp(NOW),
    )

    # Alter the request after it was signed.
    request["target_tool"] = "different_tool"

    verifier = RequestVerifier(
        registry,
        max_age_seconds=60,
    )

    with pytest.raises(
        IdentityVerificationError,
        match="signature verification failed",
    ):
        verifier.verify(request, now=NOW)