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
from .policy import PolicyRollbackStore
from .psl_policy import PslPolicyStore
from .registry import IdentityRegistry, ResourceCatalog
from .replay import InMemoryReplayGuard


PROJECT_ROOT = Path(os.getenv("ZT_PROJECT_ROOT", Path(__file__).resolve().parents[2])).resolve()


@dataclass
class Runtime:
    engine: PolicyEngine
    signer: DecisionSigner
    replay_guard: InMemoryReplayGuard


@dataclass(frozen=True)
class PdpConfig:
    """Every file and setting the PDP needs. ``from_env`` reads the ZT_* variables (defaults:
    the development configuration of this checkout); deployments pass explicit paths."""

    policy_dir: Path
    identity_file: Path
    resource_file: Path
    trusted_issuers: Path
    security_config: Path
    policy_version_store: Path
    audit_file: Path
    pdp_private_key: Path
    decision_issuer: str = "pdp.prototype"
    decision_key_id: str = "pdp-decision-1"
    nonce_ttl_seconds: int = 30
    jti_ttl_seconds: int = 120
    uses_dev_trust_store: bool = False

    @classmethod
    def from_env(cls) -> "PdpConfig":
        dev = not os.getenv("ZT_TRUSTED_ISSUERS") or not os.getenv("ZT_PDP_PRIVATE_KEY")
        return cls(
            policy_dir=Path(os.getenv("ZT_POLICY_DIR", PROJECT_ROOT / "policy_store")),
            identity_file=Path(os.getenv("ZT_IDENTITY_FILE", PROJECT_ROOT / "config" / "identities.yaml")),
            resource_file=Path(os.getenv("ZT_RESOURCE_FILE", PROJECT_ROOT / "config" / "resources.yaml")),
            trusted_issuers=Path(os.getenv("ZT_TRUSTED_ISSUERS", PROJECT_ROOT / "config" / "trusted_issuers.yaml")),
            security_config=Path(os.getenv("ZT_SECURITY_CONFIG", PROJECT_ROOT / "config" / "security_context.yaml")),
            policy_version_store=Path(
                os.getenv("ZT_POLICY_VERSION_STORE", PROJECT_ROOT / "runtime" / "policy_versions.json")),
            audit_file=Path(os.getenv("ZT_AUDIT_LOG", PROJECT_ROOT / "runtime" / "decision_log.jsonl")),
            pdp_private_key=Path(
                os.getenv("ZT_PDP_PRIVATE_KEY", PROJECT_ROOT / "security" / "dev_keys" / "pdp_signing_private.pem")),
            decision_issuer=os.getenv("ZT_PDP_DECISION_ISSUER", "pdp.prototype"),
            decision_key_id=os.getenv("ZT_PDP_DECISION_KEY_ID", "pdp-decision-1"),
            nonce_ttl_seconds=int(os.getenv("ZT_NONCE_TTL_SECONDS", "30")),
            jti_ttl_seconds=int(os.getenv("ZT_JTI_TTL_SECONDS", "120")),
            uses_dev_trust_store=dev,
        )


def build_runtime(config: PdpConfig | None = None) -> Runtime:
    config = config or PdpConfig.from_env()
    if config.uses_dev_trust_store:
        # the development trust store of this checkout is in use: create its local keys
        # and store signatures on first use (zt_pdp.dev_material)
        from .dev_material import ensure_dev_material

        ensure_dev_material(PROJECT_ROOT)
    keys = TrustedKeyStore(config.trusted_issuers)
    identities = IdentityRegistry.from_yaml(config.identity_file)
    resources = ResourceCatalog.from_yaml(config.resource_file)
    replay = InMemoryReplayGuard(
        nonce_ttl_seconds=config.nonce_ttl_seconds,
        jti_ttl_seconds=config.jti_ttl_seconds,
    )
    verifier = EvidenceVerifier(
        identities=identities,
        keys=keys,
        replay_guard=replay,
        security_config=SecurityConfig(config.security_config),
        clock=SystemClock(),
    )
    bundle = PslPolicyStore.load(
        config.policy_dir,
        keys=keys,
        rollback_store=PolicyRollbackStore(config.policy_version_store),
    )
    engine = PolicyEngine(
        bundle=bundle,
        identities=identities,
        resources=resources,
        evidence_verifier=verifier,
        audit_logger=ChainedAuditLogger(config.audit_file),
    )
    signer = DecisionSigner.from_file(
        config.pdp_private_key,
        issuer=config.decision_issuer,
        key_id=config.decision_key_id,
    )
    return Runtime(engine=engine, signer=signer, replay_guard=replay)


class RuntimeHolder:
    def __init__(self, runtime: Runtime, config: PdpConfig | None = None):
        self._runtime = runtime
        self._config = config
        self._lock = RLock()

    def get(self) -> Runtime:
        with self._lock:
            return self._runtime

    def reload(self) -> Runtime:
        replacement = build_runtime(self._config)
        with self._lock:
            self._runtime = replacement
            return replacement


def create_app(runtime: Runtime | None = None, config: PdpConfig | None = None) -> FastAPI:
    holder = RuntimeHolder(runtime or build_runtime(config), config)
    app = FastAPI(
        title="Zero Trust Backplane PDP — Security-Hardened PDP",
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
            "policy_language": "PSL (IEEE 1850-2010), deny-overrides",
            "policy_sets": current.engine.bundle.bundle_versions,
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
                detail="hot reload disabled; deploy signed PSL policies through the release pipeline",
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



def __getattr__(name: str) -> FastAPI:
    """``zt_pdp.pdp_service:app`` (uvicorn): the service of the environment's
    configuration, built on first access -- importing this module has no side effects."""
    if name == "app":
        global app
        app = create_app()
        return app
    raise AttributeError(name)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("zt_pdp.pdp_service:app", host="127.0.0.1", port=8080, reload=False)
