from pathlib import Path

import pytest

from zt_backplane.audit import DecisionAuditLogger
from zt_backplane.identity import IdentityRegistry, ResourceCatalog
from zt_backplane.policy_engine import PolicyEngine
from zt_backplane.policy_store import PolicyBundle


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def engine(tmp_path: Path) -> PolicyEngine:
    return PolicyEngine(
        bundle=PolicyBundle.load(ROOT / "policy_store"),
        identities=IdentityRegistry.from_yaml(ROOT / "config" / "identities.yaml"),
        resources=ResourceCatalog.from_yaml(ROOT / "config" / "resources.yaml"),
        audit_logger=DecisionAuditLogger(tmp_path / "decisions.jsonl"),
    )
