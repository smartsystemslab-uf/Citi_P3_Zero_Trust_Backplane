from __future__ import annotations

import argparse
import json
from pathlib import Path

from .compatibility import check_pdp_compatibility
from .generator import generate_artifacts
from .manifest import load_manifest, validate_manifest
from .placement import build_pep_plan
from .pdp_sync import sync_into_pdp


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def schema_path() -> Path:
    return project_root() / "interface_contract" / "schemas" / "zt_manifest.schema.json"


def generate(manifest_path: Path, output: Path, pdp_root: Path | None = None) -> int:
    manifest = load_manifest(manifest_path)
    errors = validate_manifest(manifest, schema_path())
    if errors:
        for error in errors:
            print(error)
        return 2
    plan, updated = build_pep_plan(manifest)
    if pdp_root:
        plan.compatibility = check_pdp_compatibility(plan, pdp_root, project_root() / "interface_contract")
    generate_artifacts(plan, updated, output)
    print(json.dumps(plan.coverage, indent=2, sort_keys=True))
    print(f"Generated PEP generator artifacts in {output.resolve()}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="PEP placement and generation")
    sub = parser.add_subparsers(dest="command", required=True)

    plan_cmd = sub.add_parser("generate", help="validate manifest and generate PEP artifacts")
    plan_cmd.add_argument("manifest", type=Path)
    plan_cmd.add_argument("--output", type=Path, default=project_root() / "generated")
    plan_cmd.add_argument("--pdp-root", type=Path)

    check_cmd = sub.add_parser("check-pdp", help="generate an explicit PEP generator/PDP compatibility report")
    check_cmd.add_argument("manifest", type=Path)
    check_cmd.add_argument("pdp_root", type=Path)
    check_cmd.add_argument("--output", type=Path, default=project_root() / "generated" / "pdp_compatibility_report.json")

    sync_cmd = sub.add_parser("sync-pdp", help="compile the unified manifest into PDP registry configuration")
    sync_cmd.add_argument("manifest", type=Path)
    sync_cmd.add_argument("pdp_root", type=Path)

    args = parser.parse_args()
    if args.command == "generate":
        raise SystemExit(generate(args.manifest, args.output, args.pdp_root))
    manifest = load_manifest(args.manifest)
    errors = validate_manifest(manifest, schema_path())
    if errors:
        raise SystemExit("\n".join(errors))
    plan, _ = build_pep_plan(manifest)
    if args.command == "check-pdp":
        report = check_pdp_compatibility(plan, args.pdp_root, project_root() / "interface_contract")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(report["summary"], indent=2, sort_keys=True))
    elif args.command == "sync-pdp":
        backup = sync_into_pdp(manifest, args.pdp_root)
        print(f"PDP config synchronized. Previous files backed up at {backup}")


if __name__ == "__main__":
    main()
