import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zt_task6.payload_format import canonical_request_payload
from zt_task6.signing import sign_request


def test_sign_request(tmp_path):
    # Generate a temporary key for this test
    private_key = Ed25519PrivateKey.generate()

    raw_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    key_path = tmp_path / "agent.key"
    key_path.write_text(
        base64.b64encode(raw_private_key).decode("ascii"),
        encoding="utf-8",
    )

    # Sign a request with that key
    request = sign_request(
        "test_agent",
        "test_tool",
        key_path,
        nonce="test-nonce",
        timestamp="2026-10-09T00:00:00Z",
    )

    assert request["caller_runtime_id"] == "test_agent"
    assert request["target_tool"] == "test_tool"
    assert request["nonce"] == "test-nonce"
    assert request["timestamp"] == "2026-10-09T00:00:00Z"

    # Verify that the signature is valid
    payload = {
        "caller_runtime_id": request["caller_runtime_id"],
        "target_tool": request["target_tool"],
        "nonce": request["nonce"],
        "timestamp": request["timestamp"],
    }

    signature = base64.b64decode(request["signature"], validate=True)

    private_key.public_key().verify(
        signature,
        canonical_request_payload(payload),
    )

    # Check that the key ID matches the public key
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    assert request["key_id"] == hashlib.sha256(public_bytes).hexdigest()