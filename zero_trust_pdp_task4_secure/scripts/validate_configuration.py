#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from zt_backplane.pdp_service import build_runtime


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    expected = json.loads((ROOT / "interface_contract" / "SCHEMA_SHA256.json").read_text(encoding="utf-8"))
    for name, digest in expected.items():
        path = ROOT / "interface_contract" / "schemas" / name
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            raise SystemExit(f"interface schema changed: {name}")
    runtime = build_runtime()
    print("Interface schemas: unchanged and verified")
    print(f"Identities: {len(runtime.engine.identities)}")
    print(f"Resources: {len(runtime.engine.resources)}")
    print(f"Signed policies: {len(runtime.engine.bundle.policies)}")
    print(f"Policy version: {runtime.engine.bundle.version}")
    print("Configuration validation: PASSED")


if __name__ == "__main__":
    main()
