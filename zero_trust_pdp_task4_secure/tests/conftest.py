from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from zt_backplane.audit import ChainedAuditLogger
from zt_backplane.crypto import TrustedKeyStore
from zt_backplane.decision_signing import DecisionSigner
from zt_backplane.engine import PolicyEngine
from zt_backplane.evidence import EvidenceVerifier, FixedClock, SecurityConfig
from zt_backplane.pdp_service import Runtime
from zt_backplane.policy import PolicyBundle, PolicyRollbackStore
from zt_backplane.registry import IdentityRegistry, ResourceCatalog
from zt_backplane.replay import InMemoryReplayGuard


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NOW = datetime(2026, 7, 27, 14, 0, tzinfo=timezone.utc)


def make_runtime(tmp_path: Path, now: datetime = DEFAULT_NOW) -> Runtime:
    keys = TrustedKeyStore(ROOT / "config" / "trusted_issuers.yaml")
    identities = IdentityRegistry.from_yaml(ROOT / "config" / "identities.yaml")
    resources = ResourceCatalog.from_yaml(ROOT / "config" / "resources.yaml")
    replay = InMemoryReplayGuard(nonce_ttl_seconds=60, jti_ttl_seconds=300)
    verifier = EvidenceVerifier(
        identities=identities,
        keys=keys,
        replay_guard=replay,
        security_config=SecurityConfig(ROOT / "config" / "security_context.yaml"),
        clock=FixedClock(now),
    )
    bundle = PolicyBundle.load(
        ROOT / "policy_store",
        schema_path=ROOT / "interface_contract" / "schemas" / "policy_bundle.schema.json",
        keys=keys,
        rollback_store=PolicyRollbackStore(tmp_path / "policy_versions.json"),
    )
    engine = PolicyEngine(
        bundle=bundle,
        identities=identities,
        resources=resources,
        evidence_verifier=verifier,
        audit_logger=ChainedAuditLogger(tmp_path / "audit.jsonl"),
    )
    signer = DecisionSigner.from_file(
        ROOT / "security" / "dev_keys" / "pdp_signing_private.pem",
        issuer="pdp.prototype",
        key_id="pdp-decision-1",
    )
    return Runtime(engine=engine, signer=signer, replay_guard=replay)


@pytest.fixture()
def runtime(tmp_path: Path) -> Runtime:
    return make_runtime(tmp_path)
