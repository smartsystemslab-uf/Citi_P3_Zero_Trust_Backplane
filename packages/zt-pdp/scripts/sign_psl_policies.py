#!/usr/bin/env python3
"""Sign the PSL policies and the field catalogue of a policy directory (development key).

    python scripts/sign_psl_policies.py [--dir policy_store] [--check]

Writes NAME.sig.json next to every *.psl file and policy_fields.yaml. With --check, only
verifies (exit 1 on any missing/invalid signature) and compiles the set.
DEVELOPMENT ONLY: the development key is generated locally on first use (never committed);
deployments sign their policy store with their own key (zt-adk build).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from zt_psl.signing import load_private_key, sign_file, verify_file

ROOT = Path(__file__).resolve().parents[1]
ISSUER, KEY_ID = "policy.prototype", "policy-1"


def policy_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.psl")) + [directory / "policy_fields.yaml"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(ROOT / "policy_store"))
    ap.add_argument("--key", default=str(ROOT / "security" / "dev_keys" / "policy_private.pem"))
    ap.add_argument("--check", action="store_true")
    ns = ap.parse_args()
    directory = Path(ns.dir)
    from zt_pdp.dev_material import ensure_dev_material

    ensure_dev_material(ROOT)          # local development keys + first signatures of a fresh checkout
    if ns.check:
        from zt_pdp.crypto import TrustedKeyStore
        from zt_pdp.psl_policy import PslPolicyStore
        store = PslPolicyStore.load(directory, keys=TrustedKeyStore(ROOT / "config" / "trusted_issuers.yaml"))
        print(f"verified and compiled {len(store.source_files)} files, {len(store.policies)} rules, "
              f"policy version {store.version}")
        return 0
    key = load_private_key(ns.key)
    for path in policy_files(directory):
        sign_file(path, key, issuer=ISSUER, key_id=KEY_ID)
        print(f"signed {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
