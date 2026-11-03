import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parents[2]          # distributed_runtime/
BACKPLANE = RUNTIME.parent
TASK4 = BACKPLANE / "zero_trust_pdp_task4_secure"
for p in (RUNTIME, BACKPLANE / "zero_trust_identity" / "src", BACKPLANE / "zero_trust_psl" / "src", TASK4 / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


@pytest.fixture(scope="session")
def store():
    """The real signed policy store, verified exactly as the PDP loads it."""
    from zt_backplane.crypto import TrustedKeyStore
    from zt_backplane.psl_policy import PslPolicyStore

    return PslPolicyStore.load(TASK4 / "policy_store", keys=TrustedKeyStore(TASK4 / "config" / "trusted_issuers.yaml"))


@pytest.fixture(scope="session")
def policy_set(store):
    return store.policy_set
