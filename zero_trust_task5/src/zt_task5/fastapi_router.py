from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .errors import Task5Error
from .models import ProofOfPossession, UnifiedAuthorizationRequest
from .permit_lease import PermitLeaseIssuer, PermitLeaseValidator
from .task4_adapter import DecisionVerifier, Task4DecisionAdapter, Task4DecisionEnvelope


class IssueLeaseInput(BaseModel):
    request: dict[str, Any]
    task4_body: dict[str, Any]
    task4_headers: dict[str, str] = Field(default_factory=dict)
    pep_identity: str
    pep_key_thumbprint: str
    session_id: str | None = None


class ValidateLeaseInput(BaseModel):
    token: str
    request: dict[str, Any]
    proof_of_possession: ProofOfPossession
    consume: bool = True


def build_task5_router(
    issuer: PermitLeaseIssuer,
    validator: PermitLeaseValidator,
    decision_verifier: DecisionVerifier,
) -> APIRouter:
    router = APIRouter(prefix="/zt/v1/task5", tags=["zero-trust-task5"])
    adapter = Task4DecisionAdapter()

    @router.post("/permit-leases/issue")
    def issue_lease(payload: IssueLeaseInput):
        try:
            request = UnifiedAuthorizationRequest.from_mapping(payload.request)
            envelope = Task4DecisionEnvelope(payload.task4_body, payload.task4_headers)
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
        except Task5Error as exc:
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
        except Task5Error as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    return router
