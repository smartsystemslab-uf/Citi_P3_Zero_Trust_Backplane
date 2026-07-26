from __future__ import annotations
import argparse
from pathlib import Path
import sys
from .loader import load_yaml, save_yaml, deep_merge
from .validator import validate_manifest, unresolved_items
from .compiler import compile_task4

def main() -> int:
    parser = argparse.ArgumentParser(prog="zt-interface")
    sub = parser.add_subparsers(dest="command", required=True)
    p_validate = sub.add_parser("validate", help="Validate a manifest")
    p_validate.add_argument("manifest")
    p_unresolved = sub.add_parser("unresolved", help="List open information gaps")
    p_unresolved.add_argument("manifest")
    p_merge = sub.add_parser("merge", help="Merge an environment overlay")
    p_merge.add_argument("base")
    p_merge.add_argument("overlay")
    p_merge.add_argument("output")
    p_compile = sub.add_parser("compile-task4", help="Compile Task 4 identity/resource/interface configuration")
    p_compile.add_argument("manifest")
    p_compile.add_argument("output_dir")
    args = parser.parse_args()

    if args.command == "validate":
        manifest = load_yaml(args.manifest)
        errors = validate_manifest(manifest)
        if errors:
            for item in errors:
                print(f"ERROR: {item}")
            return 1
        print("VALID")
        return 0
    if args.command == "unresolved":
        for item in unresolved_items(load_yaml(args.manifest)):
            print(f"{item['id']} | {item['required_from']} | tasks={item['blocking_tasks']} | {item['question']}")
        return 0
    if args.command == "merge":
        merged = deep_merge(load_yaml(args.base), load_yaml(args.overlay))
        save_yaml(args.output, merged)
        print(args.output)
        return 0
    if args.command == "compile-task4":
        manifest = load_yaml(args.manifest)
        errors = validate_manifest(manifest)
        if errors:
            for item in errors:
                print(f"ERROR: {item}")
            return 1
        compile_task4(manifest, args.output_dir)
        print(args.output_dir)
        return 0
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
