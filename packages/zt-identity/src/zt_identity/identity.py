"""Authentication result of SPIFFE scheme B.

Scheme B has two layers: the workload (X.509-SVID over mTLS, verified by OpenSSL
against the SPIRE trust bundle) and the agent credential (agent certificate bound to
that workload SPIFFE ID, RFC 9421 message signature with content digest, registry
state, replay window). ``AuthenticatedIdentity`` is only ever constructed by
server-side verification code; nothing reads an agent_id from a client header or
JSON body as proof of identity.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Protocol


class AuthenticationError(Exception):
    """Raised when authentication fails. `code` is a stable error category."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class VerifiedTransportIdentity:
    """Peer identity established by the TLS layer (never by headers)."""

    spiffe_id: str
    cert_serial: str
    not_after: datetime
    connection_id: int


@dataclass(frozen=True)
class AuthenticatedIdentity:
    auth_mode: str                       # "B"
    subject_kind: str                    # "agent" | "service"
    workload_spiffe_id: str | None       # verified SPIFFE ID of the mTLS peer
    agent_id: str                        # ADK runtime agent name (or service subject)
    agent_credential_id: str | None      # agent certificate serial (agents); None for services
    authentication_method: str
    identity_version: str
    credential_expiry: datetime | None
    details: dict[str, Any] = field(default_factory=dict)

    def as_audit(self) -> dict[str, Any]:
        out = asdict(self)
        out["credential_expiry"] = self.credential_expiry.isoformat() if self.credential_expiry else None
        return out

    def auth_factors(self) -> dict[str, bool]:
        """Factors reported to the PDP's signed auth assertion: only what THIS request
        verified (workload SVID always; the agent credential for agents)."""
        factors = {"workload_identity": self.workload_spiffe_id is not None}
        if self.subject_kind == "agent":
            factors["agent_credential"] = self.agent_credential_id is not None
        return factors


class RequestView(Protocol):
    """Minimal view of an inbound HTTP request used by authenticators."""

    method: str
    path_qs: str
    headers: Any
    body: bytes


class Authenticator(Protocol):
    mode: str

    def authenticate(
        self,
        request: RequestView,
        verified_transport_identity: VerifiedTransportIdentity | None,
        *,
        body_json: dict[str, Any],
    ) -> AuthenticatedIdentity: ...
