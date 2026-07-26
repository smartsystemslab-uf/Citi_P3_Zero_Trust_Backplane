from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from .models import Decision, Obligation


SUPPORTED_MATCH_KEYS = {
    "subjects",
    "subject_roles",
    "subject_domains",
    "resources",
    "resource_domains",
    "resource_classifications",
    "actions",
    "workflows",
    "risk_levels",
    "min_risk",
    "max_risk",
    "auth_strength_gte",
    "auth_strength_lte",
    "human_approved",
    "context_equals",
    "parameter_conditions",
    "time_windows",
}


class Policy:
    def __init__(self, raw: dict[str, Any], source_file: str):
        self.id = _required_string(raw, "id")
        self.description = str(raw.get("description", ""))
        self.priority = int(raw.get("priority", 0))
        self.effect = Decision(str(raw.get("effect", "DENY")).upper())
        self.match = raw.get("match", {}) or {}
        self.obligations = [Obligation.model_validate(item) for item in raw.get("obligations", [])]
        self.source_file = source_file
        self.enabled = bool(raw.get("enabled", True))

        if not isinstance(self.match, dict):
            raise ValueError(f"policy {self.id}: match must be a mapping")
        unknown = set(self.match) - SUPPORTED_MATCH_KEYS
        if unknown:
            raise ValueError(f"policy {self.id}: unsupported match keys: {sorted(unknown)}")

    def canonical(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "priority": self.priority,
            "effect": self.effect.value,
            "match": self.match,
            "obligations": [item.model_dump(mode="json") for item in self.obligations],
            "source_file": self.source_file,
            "enabled": self.enabled,
        }


class PolicyBundle:
    def __init__(self, policies: list[Policy], source_files: list[str]):
        self.policies = policies
        self.source_files = source_files
        canonical = [p.canonical() for p in sorted(policies, key=lambda p: p.id)]
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.version = hashlib.sha256(payload).hexdigest()[:16]

    @classmethod
    def load(cls, directory: str | Path) -> "PolicyBundle":
        root = Path(directory)
        if not root.exists():
            raise FileNotFoundError(root)

        policies: list[Policy] = []
        source_files: list[str] = []
        seen: set[str] = set()
        paths = sorted([*root.glob("*.yaml"), *root.glob("*.yml")])
        if not paths:
            raise ValueError(f"no policy YAML files found in {root}")

        for path in paths:
            with path.open("r", encoding="utf-8") as handle:
                raw = yaml.safe_load(handle) or {}
            if not isinstance(raw, dict):
                raise ValueError(f"policy file root must be a mapping: {path}")
            source_files.append(path.name)
            for item in raw.get("policies", []):
                policy = Policy(item, path.name)
                if policy.id in seen:
                    raise ValueError(f"duplicate policy id: {policy.id}")
                seen.add(policy.id)
                policies.append(policy)

        return cls(policies, source_files)


def _required_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"policy field {key!r} must be a non-empty string")
    return value.strip()
