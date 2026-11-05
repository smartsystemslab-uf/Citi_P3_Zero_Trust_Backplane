from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .errors import LeaseError
from .models import ProofOfPossession, UnifiedAuthorizationRequest
from .permit_lease import PermitLeaseIssuer, PermitLeaseValidator
from .pdp_adapter import DecisionVerifier, PdpDecisionAdapter, PdpDecisionEnvelope


class IssueLeaseInput(BaseModel):
    request: dict[str, Any]
    pdp_body: dict[str, Any]
    pdp_headers: dict[str, str] = Field(default_factory=dict)
    pep_identity: str
    pep_key_thumbprint: str
    session_id: str | None = None


class ValidateLeaseInput(BaseModel):
    token: str
    request: dict[str, Any]
    proof_of_possession: ProofOfPossession
    consume: bool = True


def build_lease_router(
    issuer: PermitLeaseIssuer,
    validator: PermitLeaseValidator,
    decision_verifier: DecisionVerifier,
) -> APIRouter:
    router = APIRouter(prefix="/zt/v1/lease", tags=["zt-lease"])
    adapter = PdpDecisionAdapter()

    @router.post("/permit-leases/issue")
    def issue_lease(payload: IssueLeaseInput):
        try:
            request = UnifiedAuthorizationRequest.from_mapping(payload.request)
            envelope = PdpDecisionEnvelope(payload.pdp_body, payload.pdp_headers)
            decision = adapter.normalize(envelope, request)
            decision_verifier.verify(envelope, decision, request)
            signed = issuer.issue(
                request,
                decision,
                pep_identity=payload.pep_identity,
                pep_key_thumbprint=payload.pep_key_thumbprint,
                session_id=payload.session_id,
            )
            return signed.model_dump(mode="json")
        except LeaseError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @router.post("/permit-leases/validate")
    def validate_lease(payload: ValidateLeaseInput):
        try:
            request = UnifiedAuthorizationRequest.from_mapping(payload.request)
            return validator.validate(
                payload.token,
                request,
                payload.proof_of_possession,
                consume=payload.consume,
            ).model_dump(mode="json")
        except LeaseError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    return router
