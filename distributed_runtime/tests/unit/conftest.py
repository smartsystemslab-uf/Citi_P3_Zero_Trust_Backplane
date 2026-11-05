import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parents[2]          # distributed_runtime/
BACKPLANE = RUNTIME.parent
EXAMPLE = BACKPLANE / "examples" / "helpdesk_mas"
for p in (RUNTIME, EXAMPLE):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


@pytest.fixture(scope="session")
def bundle(tmp_path_factory):
    """A protection bundle of the example service desk (fresh deployment keys)."""
    from zt_adk.build import build
    from zt_adk.keys import init_keys
    from zt_adk.profile import profile_from_dict

    tmp = tmp_path_factory.mktemp("bundle")
    init_keys(tmp / "keys", tmp / "approvers", approvers=["alice"], secondaries=[])
    prof = profile_from_dict({"app": "helpdesk.agent:app", "keys_dir": str(tmp / "keys"),
                              "approver_keys_dir": str(tmp / "approvers"), "bundle_dir": str(tmp / "bundle"),
                              "state_dir": str(tmp / "state"),
                              "policies": {"overlays": [str(EXAMPLE / "policies" / "*.psl")]}}, base_dir=EXAMPLE)
    import helpdesk.agent as hd

    build(prof, root_agent=hd.build_root_agent(), app_name="helpdesk", skip_static=True)
    return tmp


@pytest.fixture(scope="session")
def store(bundle):
    """The bundle's signed policy store, verified exactly as the PDP loads it."""
    from zt_backplane.crypto import TrustedKeyStore
    from zt_backplane.psl_policy import PslPolicyStore

    return PslPolicyStore.load(bundle / "bundle" / "policy_store",
                               keys=TrustedKeyStore(bundle / "keys" / "trusted_issuers.yaml"))


@pytest.fixture(scope="session")
def policy_set(store):
    return store.policy_set
