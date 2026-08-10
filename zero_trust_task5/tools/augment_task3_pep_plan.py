#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from zt_task5.task3_adapter import augment_generated_pep_plan


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Add Task 5 Permit Lease enforcement settings to a Task 3 PEP plan."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    plan = json.loads(args.input.read_text(encoding="utf-8"))
    augmented = augment_generated_pep_plan(plan)
    args.output.write_text(json.dumps(augmented, indent=2), encoding="utf-8")
    print(f"Wrote Task 5-compatible PEP plan: {args.output}")


if __name__ == "__main__":
    main()
