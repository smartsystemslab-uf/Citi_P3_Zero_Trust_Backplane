from __future__ import annotations

from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .errors import SenderConstraintError
from .key_rotation import b64url_decode, b64url_encode, public_key_thumbprint
from .models import PermitLeaseClaims, ProofOfPossession
from .request_hash import canonical_json_bytes
from .sender_constraint import SenderConstraintRegistry


def _pop_material(pop: ProofOfPossession | dict) -> bytes:
    raw = pop.model_dump(mode="json") if isinstance(pop, ProofOfPossession) else dict(pop)
    raw.pop("signature", None)
    return canonical_json_bytes(raw)


def create_proof_of_possession(
    claims: PermitLeaseClaims,
    private_key: Ed25519PrivateKey,
    *,
    issued_at: datetime | None = None,
) -> ProofOfPossession:
    thumbprint = public_key_thumbprint(private_key.public_key())
    unsigned = ProofOfPossession(
        interface_version=claims.interface_version,
        permit_id=claims.permit_id,
        request_hash=claims.request_hash,
        nonce=claims.nonce,
        jti=claims.jti,
        audience=claims.audience,
        endpoint=claims.endpoint,
        key_thumbprint=thumbprint,
        issued_at=issued_at or datetime.now(timezone.utc),
        signature="",
    )
    signature = b64url_encode(private_key.sign(_pop_material(unsigned)))
    return unsigned.model_copy(update={"signature": signature})


def validate_proof_of_possession(
    pop: ProofOfPossession,
    claims: PermitLeaseClaims,
    registry: SenderConstraintRegistry,
    *,
    max_age_seconds: int = 30,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(timezone.utc)
    if abs((now - pop.issued_at).total_seconds()) > max_age_seconds:
        raise SenderConstraintError("Proof of possession is outside the freshness window")
    expected = {
        "permit_id": claims.permit_id,
        "request_hash": claims.request_hash,
        "nonce": claims.nonce,
        "jti": claims.jti,
        "audience": claims.audience,
        "endpoint": claims.endpoint,
        "key_thumbprint": claims.pep_key_thumbprint,
    }
    for field, value in expected.items():
        if getattr(pop, field) != value:
            raise SenderConstraintError(f"Proof of possession mismatch: {field}")
    if pop.key_thumbprint != claims.pep_key_thumbprint:
        raise SenderConstraintError("Proof of possession uses the wrong sender key")
    registry.validate_identity(pop.key_thumbprint, claims.pep_identity)
    key = registry.get_public_key(pop.key_thumbprint)
    try:
        key.verify(b64url_decode(pop.signature), _pop_material(pop))
    except InvalidSignature as exc:
        raise SenderConstraintError("Invalid proof-of-possession signature") from exc
