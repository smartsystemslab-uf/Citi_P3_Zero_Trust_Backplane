#!/usr/bin/env python3
"""Validate policy files against the local identity and resource catalogs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zt_backplane.identity import IdentityRegistry, ResourceCatalog  # noqa: E402
from zt_backplane.policy_store import PolicyBundle  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy-dir", type=Path, default=ROOT / "policy_store")
    parser.add_argument("--identities", type=Path, default=ROOT / "config" / "identities.yaml")
    parser.add_argument("--resources", type=Path, default=ROOT / "config" / "resources.yaml")
    args = parser.parse_args()

    identities = IdentityRegistry.from_yaml(args.identities)
    resources = ResourceCatalog.from_yaml(args.resources)
    bundle = PolicyBundle.load(args.policy_dir)

    errors: list[str] = []
    for policy in bundle.policies:
        for subject in policy.match.get("subjects", []):
            if subject != "*" and identities.get(subject) is None:
                errors.append(f"{policy.id}: unknown subject {subject}")
        for resource_id in policy.match.get("resources", []):
            if resource_id == "*":
                continue
            resource = resources.get(resource_id)
            if resource is None:
                errors.append(f"{policy.id}: unknown resource {resource_id}")
                continue
            for action in policy.match.get("actions", []):
                if action != "*" and action not in resource.actions:
                    errors.append(f"{policy.id}: action {action} not declared for {resource_id}")

    if errors:
        print("Configuration validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(
        f"OK: {len(bundle.policies)} policies, {len(identities)} identities, "
        f"{len(resources)} resources, policy_version={bundle.version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
