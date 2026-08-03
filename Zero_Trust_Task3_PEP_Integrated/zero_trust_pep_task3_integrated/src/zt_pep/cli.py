from __future__ import annotations

import argparse
import json
from pathlib import Path

from .compatibility import check_task4_compatibility
from .generator import generate_artifacts
from .manifest import load_manifest, validate_manifest
from .placement import build_pep_plan
from .task4_sync import sync_into_task4


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def schema_path() -> Path:
    return project_root() / "interface_contract" / "schemas" / "zt_manifest.schema.json"


def generate(manifest_path: Path, output: Path, task4_root: Path | None = None) -> int:
    manifest = load_manifest(manifest_path)
    errors = validate_manifest(manifest, schema_path())
    if errors:
        for error in errors:
            print(error)
        return 2
    plan, updated = build_pep_plan(manifest)
    if task4_root:
        plan.compatibility = check_task4_compatibility(plan, task4_root, project_root() / "interface_contract")
    generate_artifacts(plan, updated, output)
    print(json.dumps(plan.coverage, indent=2, sort_keys=True))
    print(f"Generated Task 3 artifacts in {output.resolve()}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Task 3 PEP placement and generation")
    sub = parser.add_subparsers(dest="command", required=True)

    plan_cmd = sub.add_parser("generate", help="validate manifest and generate PEP artifacts")
    plan_cmd.add_argument("manifest", type=Path)
    plan_cmd.add_argument("--output", type=Path, default=project_root() / "generated")
    plan_cmd.add_argument("--task4-root", type=Path)

    check_cmd = sub.add_parser("check-task4", help="generate an explicit Task 3/Task 4 compatibility report")
    check_cmd.add_argument("manifest", type=Path)
    check_cmd.add_argument("task4_root", type=Path)
    check_cmd.add_argument("--output", type=Path, default=project_root() / "generated" / "task4_compatibility_report.json")

    sync_cmd = sub.add_parser("sync-task4", help="compile the unified manifest into Task 4 registry configuration")
    sync_cmd.add_argument("manifest", type=Path)
    sync_cmd.add_argument("task4_root", type=Path)

    args = parser.parse_args()
    if args.command == "generate":
        raise SystemExit(generate(args.manifest, args.output, args.task4_root))
    manifest = load_manifest(args.manifest)
    errors = validate_manifest(manifest, schema_path())
    if errors:
        raise SystemExit("\n".join(errors))
    plan, _ = build_pep_plan(manifest)
    if args.command == "check-task4":
        report = check_task4_compatibility(plan, args.task4_root, project_root() / "interface_contract")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(report["summary"], indent=2, sort_keys=True))
    elif args.command == "sync-task4":
        backup = sync_into_task4(manifest, args.task4_root)
        print(f"Task 4 config synchronized. Previous files backed up at {backup}")


if __name__ == "__main__":
    main()
