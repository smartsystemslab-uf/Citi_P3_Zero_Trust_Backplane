from __future__ import annotations

import os
from pathlib import Path
from threading import RLock

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import JSONResponse

from .audit import DecisionAuditLogger
from .identity import IdentityRegistry, ResourceCatalog
from .models import PDPRequest, PDPResponse
from .policy_engine import PolicyEngine
from .policy_store import PolicyBundle


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def build_engine() -> PolicyEngine:
    policy_dir = Path(os.getenv("ZT_POLICY_DIR", PROJECT_ROOT / "policy_store"))
    identity_file = Path(os.getenv("ZT_IDENTITY_FILE", PROJECT_ROOT / "config" / "identities.yaml"))
    resource_file = Path(os.getenv("ZT_RESOURCE_FILE", PROJECT_ROOT / "config" / "resources.yaml"))
    audit_file = Path(os.getenv("ZT_AUDIT_LOG", PROJECT_ROOT / "runtime" / "decision_log.jsonl"))

    return PolicyEngine(
        bundle=PolicyBundle.load(policy_dir),
        identities=IdentityRegistry.from_yaml(identity_file),
        resources=ResourceCatalog.from_yaml(resource_file),
        audit_logger=DecisionAuditLogger(audit_file),
    )


class EngineHolder:
    def __init__(self, engine: PolicyEngine):
        self._engine = engine
        self._lock = RLock()

    def get(self) -> PolicyEngine:
        with self._lock:
            return self._engine

    def reload(self) -> PolicyEngine:
        replacement = build_engine()
        with self._lock:
            self._engine = replacement
            return self._engine


def create_app(engine: PolicyEngine | None = None) -> FastAPI:
    holder = EngineHolder(engine or build_engine())
    app = FastAPI(
        title="Zero Trust Backplane PDP Prototype",
        version="0.1.0",
        description="Task 4 central PDP and YAML policy engine prototype.",
    )
    app.state.engine_holder = holder

    def get_engine() -> PolicyEngine:
        return holder.get()

    @app.get("/health")
    def health(current: PolicyEngine = Depends(get_engine)) -> dict[str, object]:
        return {
            "status": "ok",
            "policy_version": current.bundle.version,
            "policy_count": len(current.bundle.policies),
            "identity_count": len(current.identities),
            "resource_count": len(current.resources),
            "policy_files": current.bundle.source_files,
        }

    @app.post("/v1/authorize", response_model=PDPResponse)
    def authorize(request: PDPRequest, current: PolicyEngine = Depends(get_engine)) -> PDPResponse:
        return current.evaluate(request)

    @app.post("/v1/admin/reload")
    def reload_policies(
        x_zt_admin_token: str | None = Header(default=None),
    ) -> JSONResponse:
        expected = os.getenv("ZT_ADMIN_TOKEN")
        if not expected:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="policy reload endpoint disabled; set ZT_ADMIN_TOKEN",
            )
        if x_zt_admin_token != expected:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid admin token")
        current = holder.reload()
        return JSONResponse(
            {
                "status": "reloaded",
                "policy_version": current.bundle.version,
                "policy_count": len(current.bundle.policies),
            }
        )

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("zt_backplane.pdp_service:app", host="127.0.0.1", port=8080, reload=False)
