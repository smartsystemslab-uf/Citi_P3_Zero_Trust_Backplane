"""Tool identity failures must never become executable shadow decisions."""

import base64
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from native_mas_runtime.engine import NativeAuthorization, NativeMasBackplane
from zt_task6.registry import PublicKeyRegistry, RegistryError, write_signed_registry
from zt_task6.signing import sign_request
from zt_task6.verification import IdentityVerificationError, RequestVerifier


def authorization(*, allowed=False, mode="shadow"):
    return NativeAuthorization(
        allowed=allowed,
        would_block=not allowed,
        mode=mode,
        reason="ALLOW" if allowed else "POLICY_DENIED",
        source="PDP",
        placement=None,
        request=None,
        runtime_authorization=None,
        authorization_latency_ms=0.0,
    )


def make_engine(mode="shadow", shadow_allow_critical=False):
    # Avoid starting the full policy service: these tests exercise the identity
    # gate before that service and the final execution decision after the gate.
    engine = object.__new__(NativeMasBackplane)
    engine.mode = mode
    engine.shadow_allow_critical = shadow_allow_critical
    engine.identity_verifier = Mock()
    engine.authorize = Mock(return_value=authorization(allowed=True, mode=mode))
    engine.append_runtime_event = Mock()
    return engine


def begin_tool(engine, signed_request):
    return engine.begin_tool(
        None,
        tool_args={"customer_id": "customer-1"},
        trace_id="trace-1",
        workflow_instance_id="workflow-1",
        workflow_id=None,
        idempotency_key="operation-1",
        caller_runtime_id="agent",
        tool_name="read_customer",
        signed_identity_request=signed_request,
    )


@pytest.mark.parametrize("mode,shadow_allow_critical", [
    ("enforce", False), ("shadow", False), ("shadow", True),
])
@pytest.mark.parametrize("critical", [False, True])
@pytest.mark.parametrize("failure", [
    "missing_verifier", "missing_request", "wrong_caller", "wrong_tool",
    "invalid_signature", "registry_error", "key_io_error",
])
def test_identity_failure_never_executes_or_reaches_pdp(
    mode, shadow_allow_critical, critical, failure,
):
    engine = make_engine(mode, shadow_allow_critical)
    signed_request = {"caller_runtime_id": "agent", "target_tool": "read_customer"}
    if failure == "missing_verifier":
        engine.identity_verifier = None
    elif failure == "missing_request":
        signed_request = None
    elif failure == "wrong_caller":
        signed_request["caller_runtime_id"] = "other_agent"
    elif failure == "wrong_tool":
        signed_request["target_tool"] = "write_customer"
    else:
        errors = {
            "invalid_signature": IdentityVerificationError,
            "registry_error": RegistryError,
            "key_io_error": OSError,
        }
        engine.identity_verifier.verify.side_effect = errors[failure]("rejected")

    pending = begin_tool(engine, signed_request)

    assert pending.authorization.reason == "IDENTITY_VERIFICATION_FAILED"
    assert pending.authorization.source == "AUTHN-3"
    assert pending.authorization.allowed is False
    assert engine.should_execute(pending.authorization, critical=critical) is False
    assert pending.pep is None
    assert pending.request is None
    assert pending.idempotency_reserved is False
    engine.authorize.assert_not_called()
    engine.append_runtime_event.assert_called_once()
    assert engine.append_runtime_event.call_args.args == ("IDENTITY_VERIFICATION_FAILED",)
    if failure in {"missing_request", "wrong_caller", "wrong_tool"}:
        engine.identity_verifier.verify.assert_not_called()


@pytest.mark.parametrize("mode,critical,shadow_allow_critical,expected", [
    ("enforce", False, False, False),
    ("enforce", True, True, False),
    ("shadow", False, False, True),
    ("shadow", True, False, False),
    ("shadow", True, True, True),
])
def test_policy_denial_retains_existing_shadow_semantics(
    mode, critical, shadow_allow_critical, expected,
):
    engine = make_engine(mode, shadow_allow_critical)
    assert engine.should_execute(authorization(mode=mode), critical=critical) is expected


@pytest.fixture
def signed_identity(tmp_path):
    root_key = Ed25519PrivateKey.generate()
    agent_key = Ed25519PrivateKey.generate()
    root_private = tmp_path / "root-private.pem"
    root_public = tmp_path / "root-public.pem"
    root_private.write_bytes(root_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    root_public.write_bytes(root_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    agent_private = tmp_path / "agent.key"
    agent_private.write_text(base64.b64encode(agent_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )).decode("ascii"), encoding="utf-8")
    agent_public = base64.b64encode(agent_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )).decode("ascii")
    registry_path = tmp_path / "registry.yaml"
    write_signed_registry(
        {"agent": agent_public},
        registry_path,
        root_private_key_path=root_private,
        root_key_id="test-root",
        valid_from=datetime.now(timezone.utc) - timedelta(days=1),
    )
    registry = PublicKeyRegistry.from_yaml(
        registry_path,
        root_public_key_path=root_public,
        expected_root_key_id="test-root",
    )
    return agent_private, RequestVerifier(registry)


def test_signed_request_reaches_pdp_and_replay_remains_blocked_in_shadow(signed_identity):
    key_path, verifier = signed_identity
    engine = make_engine("shadow", shadow_allow_critical=True)
    engine.identity_verifier = verifier
    request = sign_request("agent", "read_customer", key_path)

    pending = begin_tool(engine, request)

    engine.authorize.assert_called_once()
    assert engine.authorize.call_args.kwargs["caller_runtime_id"] == "agent"
    assert engine.should_execute(pending.authorization) is True
    engine.authorize.reset_mock()

    replayed = begin_tool(engine, request)

    assert replayed.authorization.reason == "IDENTITY_VERIFICATION_FAILED"
    assert engine.should_execute(replayed.authorization) is False
    assert engine.should_execute(replayed.authorization, critical=True) is False
    engine.authorize.assert_not_called()


@pytest.mark.parametrize("tampering", ["signature", "timestamp"])
def test_invalid_signed_request_is_blocked_before_pdp(signed_identity, tampering):
    key_path, verifier = signed_identity
    engine = make_engine("shadow", shadow_allow_critical=True)
    engine.identity_verifier = verifier
    if tampering == "timestamp":
        request = sign_request(
            "agent", "read_customer", key_path,
            timestamp=(datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        )
    else:
        request = sign_request("agent", "read_customer", key_path)
        request["signature"] = base64.b64encode(bytes(64)).decode("ascii")

    pending = begin_tool(engine, request)

    assert pending.authorization.reason == "IDENTITY_VERIFICATION_FAILED"
    assert engine.should_execute(pending.authorization) is False
    engine.authorize.assert_not_called()
