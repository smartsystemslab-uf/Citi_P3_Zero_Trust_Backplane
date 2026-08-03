#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from zt_pep.compatibility import check_task4_compatibility
from zt_pep.manifest import load_manifest
from zt_pep.placement import build_pep_plan


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task4-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parents[1] / "examples" / "citi_project_baseline.yaml")
    args = parser.parse_args()
    manifest = load_manifest(args.manifest)
    plan, _ = build_pep_plan(manifest)
    report = check_task4_compatibility(
        plan,
        args.task4_root,
        Path(__file__).resolve().parents[1] / "interface_contract",
    )
    print(json.dumps(report["summary"], indent=2))
    raise SystemExit(0 if report["summary"]["compatible"] else 2)


if __name__ == "__main__":
    main()
