#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from zt_backplane.crypto import generate_keypair


ROOT = Path(__file__).resolve().parents[1]
KEY_NAMES = ["pep", "risk", "idp", "workflow", "approval", "secondary", "policy"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="replace development keys")
    args = parser.parse_args()
    key_dir = ROOT / "security" / "dev_keys"
    key_dir.mkdir(parents=True, exist_ok=True)

    for name in KEY_NAMES:
        private_path = key_dir / f"{name}_private.pem"
        public_path = key_dir / f"{name}_public.pem"
        if args.force or not private_path.exists() or not public_path.exists():
            generate_keypair(private_path, public_path)

    pdp_private = key_dir / "pdp_signing_private.pem"
    pdp_public = key_dir / "pdp_signing_public.pem"
    if args.force or not pdp_private.exists() or not pdp_public.exists():
        generate_keypair(pdp_private, pdp_public)

    from zt_psl.signing import load_private_key as load_psl_key, sign_file

    psl_key = load_psl_key(key_dir / "policy_private.pem")
    for path in sorted((ROOT / "policy_store").glob("*.psl")) + [ROOT / "policy_store" / "policy_fields.yaml"]:
        sign_file(path, psl_key, issuer="policy.prototype", key_id="policy-1")
    print("Development keys generated and PSL policies signed.")


if __name__ == "__main__":
    main()
