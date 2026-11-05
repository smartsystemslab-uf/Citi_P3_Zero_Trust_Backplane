#!/usr/bin/env python3
"""Create (or with --force: replace) the local development keys of this checkout and sign the
development policy stores with the local policy key. Nothing created here is committed.

    python scripts/bootstrap_dev_crypto.py [--force]
"""
from __future__ import annotations

import argparse
from pathlib import Path

from zt_pdp.dev_material import KEY_NAMES, ensure_dev_material, key_dir, legacy_bundle_files, psl_store_files
from zt_psl.signing import sidecar_path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="replace the development keys and re-sign the stores")
    args = parser.parse_args()
    if args.force:
        for name in KEY_NAMES:
            for suffix in ("_private.pem", "_public.pem"):
                (key_dir(ROOT) / f"{name}{suffix}").unlink(missing_ok=True)
        for path in psl_store_files(ROOT):
            sidecar_path(path).unlink(missing_ok=True)
        for path in legacy_bundle_files(ROOT):
            path.with_suffix(".sig.json").unlink(missing_ok=True)
    result = ensure_dev_material(ROOT)
    print(f"keys created: {result['keys_created'] or 'none'}; signed: {len(result['signed'])} files")


if __name__ == "__main__":
    main()
