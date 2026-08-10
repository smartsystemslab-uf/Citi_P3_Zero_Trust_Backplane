from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import SenderConstraintError
from .key_rotation import public_key_thumbprint


class SenderConstraintRegistry:
    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._identities: dict[str, str] = {}
        self._revoked: set[str] = set()

    def register(self, pep_identity: str, public_key: Ed25519PublicKey) -> str:
        thumbprint = public_key_thumbprint(public_key)
        self._keys[thumbprint] = public_key
        self._identities[thumbprint] = pep_identity
        return thumbprint

    def revoke(self, thumbprint: str) -> None:
        self._revoked.add(thumbprint)

    def get_public_key(self, thumbprint: str) -> Ed25519PublicKey:
        if thumbprint in self._revoked:
            raise SenderConstraintError("The PEP sender key is revoked")
        key = self._keys.get(thumbprint)
        if key is None:
            raise SenderConstraintError("The PEP sender key is not trusted")
        return key

    def validate_identity(self, thumbprint: str, pep_identity: str) -> None:
        expected = self._identities.get(thumbprint)
        if expected != pep_identity:
            raise SenderConstraintError("PEP identity does not match the sender key")
