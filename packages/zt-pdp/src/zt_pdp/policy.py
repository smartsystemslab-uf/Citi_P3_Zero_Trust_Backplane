from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field

from .canonical import sha256_hex
from .crypto import TrustedKeyStore, verify_mapping
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
    "environments",
    "risk_levels",
    "min_risk",
    "max_risk",
    "min_risk_score",
    "max_risk_score",
    "auth_strength_gte",
    "auth_strength_lte",
    "approval_valid",
    "secondary_authorization_valid",
    "parameter_conditions",
    "time_windows",
}


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    priority: int = 100
    effect: Decision
    match: dict[str, Any] = Field(default_factory=dict)
    obligations: list[Obligation] = Field(default_factory=list)
    enabled: bool = True
    source_bundle_id: str = ""
    source_bundle_version: str = ""


class PolicyRollbackStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def check_and_record(self, versions: dict[str, str]) -> None:
        with self._lock:
            existing: dict[str, str] = {}
            if self.path.exists():
                existing = json.loads(self.path.read_text(encoding="utf-8") or "{}")
            for bundle_id, version in versions.items():
                previous = existing.get(bundle_id)
                if previous is not None and _version_tuple(version) < _version_tuple(previous):
                    raise ValueError(f"policy rollback rejected for {bundle_id}: {version} < {previous}")
            existing.update(versions)
            self.path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class PolicyBundle:
    def __init__(
        self,
        policies: list[Policy],
        source_files: list[str],
        bundle_versions: dict[str, str],
        bundle_digests: dict[str, str],
    ):
        self.policies = sorted(policies, key=lambda item: (-item.priority, item.id))
        self.source_files = source_files
        self.bundle_versions = bundle_versions
        self.bundle_digests = bundle_digests
        self.version = sha256_hex(
            {
                "bundles": [
                    {"id": key, "version": bundle_versions[key], "digest": bundle_digests[key]}
                    for key in sorted(bundle_versions)
                ]
            }
        )[:16]

    @classmethod
    def load(
        cls,
        directory: str | Path,
        *,
        schema_path: str | Path,
        keys: TrustedKeyStore,
        rollback_store: PolicyRollbackStore | None = None,
    ) -> "PolicyBundle":
        directory = Path(directory)
        schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        policies: list[Policy] = []
        source_files: list[str] = []
        versions: dict[str, str] = {}
        digests: dict[str, str] = {}
        seen_policy_ids: set[str] = set()

        for path in sorted(directory.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            errors = sorted(validator.iter_errors(raw), key=lambda item: list(item.path))
            if errors:
                summary = "; ".join(error.message for error in errors[:5])
                raise ValueError(f"policy schema validation failed for {path.name}: {summary}")
            metadata = raw["metadata"]
            bundle_id = str(metadata["id"])
            version = str(metadata["version"])
            if bundle_id in versions:
                raise ValueError(f"duplicate policy bundle id: {bundle_id}")
            signature_path = path.with_suffix(".sig.json")
            if not signature_path.exists():
                raise ValueError(f"missing signed policy sidecar: {signature_path.name}")
            signature = json.loads(signature_path.read_text(encoding="utf-8"))
            digest = sha256_hex(raw)
            if signature.get("bundle_digest") != digest:
                raise ValueError(f"policy bundle digest mismatch: {path.name}")
            key = keys.get(str(signature.get("issuer")), str(signature.get("key_id")), "policy_bundle")
            if not verify_mapping(key, raw, str(signature.get("signature", ""))):
                raise ValueError(f"invalid policy bundle signature: {path.name}")

            versions[bundle_id] = version
            digests[bundle_id] = digest
            source_files.append(path.name)
            for item in raw["policies"]:
                unsupported = set(item.get("match", {})) - SUPPORTED_MATCH_KEYS
                if unsupported:
                    raise ValueError(f"unsupported match keys in {item['id']}: {sorted(unsupported)}")
                item = dict(item)
                item["source_bundle_id"] = bundle_id
                item["source_bundle_version"] = version
                policy = Policy.model_validate(item)
                if policy.id in seen_policy_ids:
                    raise ValueError(f"duplicate policy id: {policy.id}")
                seen_policy_ids.add(policy.id)
                policies.append(policy)

        if not policies:
            raise ValueError(f"no policies found in {directory}")
        if rollback_store is not None:
            rollback_store.check_and_record(versions)
        return cls(policies, source_files, versions, digests)


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = re.split(r"[._-]", value)
    if not parts or any(not part.isdigit() for part in parts):
        raise ValueError(f"policy version must be numeric dotted form: {value}")
    return tuple(int(part) for part in parts)
