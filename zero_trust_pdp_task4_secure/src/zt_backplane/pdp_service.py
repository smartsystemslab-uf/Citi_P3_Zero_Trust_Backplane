from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from .audit import ChainedAuditLogger
from .crypto import TrustedKeyStore
from .decision_signing import DecisionSigner
from .engine import PolicyEngine
from .evidence import EvidenceVerifier, SecurityConfig, SystemClock
from .models import ChallengeRequest, ChallengeResponse, PDPRequest
from .policy import PolicyBundle, PolicyRollbackStore
from .registry import IdentityRegistry, ResourceCatalog
from .replay import InMemoryReplayGuard


PROJECT_ROOT = Path(os.getenv("ZT_PROJECT_ROOT", Path(__file__).resolve().parents[2])).resolve()


@dataclass
class Runtime:
    engine: PolicyEngine
    signer: DecisionSigner
    replay_guard: InMemoryReplayGuard


def build_runtime() -> Runtime:
    policy_dir = Path(os.getenv("ZT_POLICY_DIR", PROJECT_ROOT / "policy_store"))
    identity_file = Path(os.getenv("ZT_IDENTITY_FILE", PROJECT_ROOT / "config" / "identities.yaml"))
    resource_file = Path(os.getenv("ZT_RESOURCE_FILE", PROJECT_ROOT / "config" / "resources.yaml"))
    trusted_issuers = Path(os.getenv("ZT_TRUSTED_ISSUERS", PROJECT_ROOT / "config" / "trusted_issuers.yaml"))
    security_config_file = Path(os.getenv("ZT_SECURITY_CONFIG", PROJECT_ROOT / "config" / "security_context.yaml"))
    policy_schema = Path(
        os.getenv("ZT_POLICY_SCHEMA", PROJECT_ROOT / "interface_contract" / "schemas" / "policy_bundle.schema.json")
    )
    policy_version_store = Path(
        os.getenv("ZT_POLICY_VERSION_STORE", PROJECT_ROOT / "runtime" / "policy_versions.json")
    )
    audit_file = Path(os.getenv("ZT_AUDIT_LOG", PROJECT_ROOT / "runtime" / "decision_log.jsonl"))
    pdp_private_key = Path(
        os.getenv("ZT_PDP_PRIVATE_KEY", PROJECT_ROOT / "security" / "dev_keys" / "pdp_signing_private.pem")
    )

    keys = TrustedKeyStore(trusted_issuers)
    identities = IdentityRegistry.from_yaml(identity_file)
    resources = ResourceCatalog.from_yaml(resource_file)
    replay = InMemoryReplayGuard(
        nonce_ttl_seconds=int(os.getenv("ZT_NONCE_TTL_SECONDS", "30")),
        jti_ttl_seconds=int(os.getenv("ZT_JTI_TTL_SECONDS", "120")),
    )
    verifier = EvidenceVerifier(
        identities=identities,
        keys=keys,
        replay_guard=replay,
        security_config=SecurityConfig(security_config_file),
        clock=SystemClock(),
    )
    bundle = PolicyBundle.load(
        policy_dir,
        schema_path=policy_schema,
        keys=keys,
        rollback_store=PolicyRollbackStore(policy_version_store),
    )
    engine = PolicyEngine(
        bundle=bundle,
        identities=identities,
        resources=resources,
        evidence_verifier=verifier,
        audit_logger=ChainedAuditLogger(audit_file),
    )
    signer = DecisionSigner.from_file(
        pdp_private_key,
        issuer=os.getenv("ZT_PDP_DECISION_ISSUER", "pdp.prototype"),
        key_id=os.getenv("ZT_PDP_DECISION_KEY_ID", "pdp-decision-1"),
    )
    return Runtime(engine=engine, signer=signer, replay_guard=replay)


class RuntimeHolder:
    def __init__(self, runtime: Runtime):
        self._runtime = runtime
        self._lock = RLock()

    def get(self) -> Runtime:
        with self._lock:
            return self._runtime

    def reload(self) -> Runtime:
        replacement = build_runtime()
        with self._lock:
            self._runtime = replacement
            return replacement


def create_app(runtime: Runtime | None = None) -> FastAPI:
    holder = RuntimeHolder(runtime or build_runtime())
    app = FastAPI(
        title="Zero Trust Backplane PDP — Security-Hardened Task 4",
        version="1.0.0",
        description=(
            "Uses the unchanged reusable interface standard v1.0 and adds verified context, "
            "request signatures, replay protection, signed policies, and signed decisions."
        ),
    )
    app.state.runtime_holder = holder

    def get_runtime() -> Runtime:
        return holder.get()

    @app.get("/health")
    def health(current: Runtime = Depends(get_runtime)) -> dict[str, object]:
        return {
            "status": "ok",
            "interface_schema_version": "1.0",
            "policy_version": current.engine.bundle.version,
            "policy_count": len(current.engine.bundle.policies),
            "identity_count": len(current.engine.identities),
            "resource_count": len(current.engine.resources),
            "policy_files": current.engine.bundle.source_files,
            "security": {
                "signed_policy_bundles": True,
                "signed_requests": True,
                "nonce_and_jti_replay_protection": True,
                "verified_context_assertions": True,
                "signed_decisions": True,
                "permit_cache": False,
            },
        }

    @app.post("/v1/challenge", response_model=ChallengeResponse)
    def challenge(request: ChallengeRequest, current: Runtime = Depends(get_runtime)) -> ChallengeResponse:
        identity = current.engine.identities.resolve(request.subject_canonical_id, request.subject_runtime_id)
        if identity is None or not identity.enabled:
            raise HTTPException(status_code=404, detail="unknown or disabled subject binding")
        item = current.replay_guard.issue(
            request.subject_canonical_id,
            request.subject_runtime_id,
            now=current.engine.evidence_verifier.clock.now(),
        )
        return ChallengeResponse(
            nonce=item.nonce,
            subject_canonical_id=item.subject_canonical_id,
            subject_runtime_id=item.subject_runtime_id,
            issued_at=item.issued_at,
            expires_at=item.expires_at,
        )

    @app.post("/v1/authorize")
    def authorize(request: PDPRequest, current: Runtime = Depends(get_runtime)) -> JSONResponse:
        response = current.engine.evaluate(request)
        headers = current.signer.headers(response, request_hash=request.request_hash or "")
        return JSONResponse(content=jsonable_encoder(response), headers=headers)

    @app.post("/v1/admin/reload")
    def reload_policies(
        x_zt_admin_token: str | None = Header(default=None),
    ) -> JSONResponse:
        if os.getenv("ZT_ENABLE_ADMIN_RELOAD", "false").lower() != "true":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="hot reload disabled; deploy a verified policy bundle through the release pipeline",
            )
        expected = os.getenv("ZT_ADMIN_TOKEN")
        if not expected or not x_zt_admin_token or not secrets.compare_digest(x_zt_admin_token, expected):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid admin authorization")
        current = holder.reload()
        return JSONResponse(
            {
                "status": "reloaded",
                "policy_version": current.engine.bundle.version,
                "policy_count": len(current.engine.bundle.policies),
                "signed_policy_verification": "passed",
            }
        )

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("zt_backplane.pdp_service:app", host="127.0.0.1", port=8080, reload=False)
