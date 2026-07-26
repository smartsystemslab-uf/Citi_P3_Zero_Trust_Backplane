from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml

def _runtime_binding(record: dict[str, Any], environment: str) -> dict[str, Any]:
    binding = record.get("bindings", {}).get(environment) or {}
    return binding

def compile_task4(manifest: dict[str, Any], output_dir: str | Path) -> None:
    spec = manifest["spec"]
    environment = spec["defaults"]["environment_binding"]
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    identities = []
    for subject in spec.get("subjects", []):
        if subject.get("type") not in {"agent", "service"}:
            continue
        binding = _runtime_binding(subject, environment)
        runtime_id = binding.get("runtime_id")
        if not runtime_id:
            continue
        identities.append({
            "id": runtime_id,
            "canonical_id": subject["id"],
            "type": subject["type"],
            "roles": subject.get("roles", []),
            "domain": subject.get("domain"),
            "enabled": subject.get("enabled", True),
            "attributes": {"manifest_status": subject["metadata"]["status"], **subject.get("attributes", {})},
        })

    resources = []
    for resource in spec.get("resources", []):
        binding = _runtime_binding(resource, environment)
        runtime_id = binding.get("runtime_id")
        if not runtime_id:
            continue
        resources.append({
            "id": runtime_id,
            "canonical_id": resource["id"],
            "actions": [action["name"] for action in resource.get("actions", [])],
            "domain": resource.get("domain"),
            "classification": resource.get("classification", "internal"),
            "critical": any(action.get("criticality") == "critical" for action in resource.get("actions", [])),
            "attributes": {"manifest_status": resource["metadata"]["status"], **resource.get("attributes", {})},
        })

    interface_config = {
        "manifest_version": manifest["metadata"]["manifest_version"],
        "environment": environment,
        "interfaces": [],
        "audit": spec.get("audit", {}),
    }
    for interface in spec.get("interfaces", []):
        binding = _runtime_binding(interface, environment)
        interface_config["interfaces"].append({
            "canonical_id": interface["id"],
            "type": interface["type"],
            "runtime": binding,
            "authentication": interface.get("authentication", {}),
            "request_schema_ref": interface.get("request_schema_ref"),
            "response_schema_ref": interface.get("response_schema_ref"),
            "timeout_ms": interface.get("timeout_ms"),
            "status": interface["metadata"]["status"],
        })

    for name, payload in (("identities.yaml", {"identities": identities}), ("resources.yaml", {"resources": resources}), ("citi_interfaces.yaml", interface_config)):
        with (destination / name).open("w", encoding="utf-8") as handle:
            yaml.safe_dump(payload, handle, sort_keys=False, allow_unicode=True)
