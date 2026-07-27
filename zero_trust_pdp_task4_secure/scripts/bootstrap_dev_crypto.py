#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

from zt_backplane.canonical import sha256_hex
from zt_backplane.crypto import generate_keypair, load_private_key, sign_mapping


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

    policy_key = load_private_key(key_dir / "policy_private.pem")
    for path in sorted((ROOT / "policy_store").glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        sidecar = {
            "schema_version": "1.0",
            "issuer": "policy.prototype",
            "key_id": "policy-1",
            "algorithm": "Ed25519",
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "bundle_digest": sha256_hex(raw),
            "signature": sign_mapping(policy_key, raw),
        }
        path.with_suffix(".sig.json").write_text(
            json.dumps(sidecar, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print("Development keys generated and policy bundles signed.")


if __name__ == "__main__":
    main()
