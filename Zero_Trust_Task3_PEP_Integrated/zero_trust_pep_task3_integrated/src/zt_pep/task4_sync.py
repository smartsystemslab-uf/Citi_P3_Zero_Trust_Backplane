from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .manifest import runtime_binding


def compile_task4_config(manifest: dict[str, Any], destination: str | Path) -> None:
    spec = manifest["spec"]
    environment = spec["defaults"]["environment_binding"]
    output = Path(destination)
    output.mkdir(parents=True, exist_ok=True)

    identities = []
    for subject in spec.get("subjects", []):
        if subject.get("type") not in {"agent", "service"}:
            continue
        binding = runtime_binding(subject, environment)
        if not binding.get("runtime_id"):
            continue
        identities.append(
            {
                "id": binding["runtime_id"],
                "canonical_id": subject["id"],
                "type": subject["type"],
                "roles": subject.get("roles", []),
                "domain": subject.get("domain"),
                "enabled": subject.get("enabled", True),
                "attributes": {"manifest_status": subject["metadata"]["status"], **subject.get("attributes", {})},
            }
        )

    resources = []
    for resource in spec.get("resources", []):
        binding = runtime_binding(resource, environment)
        if not binding.get("runtime_id"):
            continue
        resources.append(
            {
                "id": binding["runtime_id"],
                "canonical_id": resource["id"],
                "actions": [action["name"] for action in resource.get("actions", [])],
                "domain": resource.get("domain"),
                "classification": resource.get("classification", "internal"),
                "critical": any(action.get("criticality") == "critical" for action in resource.get("actions", [])),
                "attributes": {"manifest_status": resource["metadata"]["status"], **resource.get("attributes", {})},
            }
        )

    interfaces = {
        "manifest_version": manifest["metadata"]["manifest_version"],
        "environment": environment,
        "interfaces": [],
        "audit": spec.get("audit", {}),
    }
    for interface in spec.get("interfaces", []):
        interfaces["interfaces"].append(
            {
                "canonical_id": interface["id"],
                "type": interface["type"],
                "runtime": runtime_binding(interface, environment),
                "authentication": interface.get("authentication", {}),
                "request_schema_ref": interface.get("request_schema_ref"),
                "response_schema_ref": interface.get("response_schema_ref"),
                "timeout_ms": interface.get("timeout_ms"),
                "status": interface["metadata"]["status"],
            }
        )

    payloads = {
        "identities.yaml": {"identities": identities},
        "resources.yaml": {"resources": resources},
        "citi_interfaces.yaml": interfaces,
    }
    for name, payload in payloads.items():
        (output / name).write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")


def sync_into_task4(manifest: dict[str, Any], task4_root: str | Path) -> Path:
    root = Path(task4_root).resolve()
    config = root / "config"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = root / "runtime" / f"task3_config_backup_{timestamp}"
    backup.mkdir(parents=True, exist_ok=True)
    for name in ("identities.yaml", "resources.yaml", "citi_interfaces.yaml"):
        source = config / name
        if source.exists():
            shutil.copy2(source, backup / name)
    compile_task4_config(manifest, config)
    return backup
