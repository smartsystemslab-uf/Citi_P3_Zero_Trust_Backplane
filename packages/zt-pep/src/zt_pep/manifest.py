from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker


class ManifestError(ValueError):
    pass


def load_manifest(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ManifestError(f"manifest root must be an object: {source}")
    return raw


def save_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def validate_manifest(manifest: dict[str, Any], schema_path: str | Path) -> list[str]:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(manifest), key=lambda item: list(item.absolute_path))
    messages: list[str] = []
    for error in errors:
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        messages.append(f"{location}: {error.message}")
    messages.extend(validate_references(manifest))
    return messages


def validate_references(manifest: dict[str, Any]) -> list[str]:
    spec = manifest.get("spec", {})
    subjects = {item.get("id") for item in spec.get("subjects", [])}
    resources = {item.get("id") for item in spec.get("resources", [])}
    interfaces = {item.get("id") for item in spec.get("interfaces", [])}
    workflows = {item.get("id") for item in spec.get("workflows", [])}
    boundaries = {item.get("id") for item in spec.get("trust_boundaries", [])}
    actions = {
        item.get("id"): {action.get("name") for action in item.get("actions", [])}
        for item in spec.get("resources", [])
    }
    errors: list[str] = []
    for index, edge in enumerate(spec.get("interactions", [])):
        prefix = f"spec.interactions.{index}"
        if edge.get("caller_id") not in subjects:
            errors.append(f"{prefix}.caller_id: unknown subject {edge.get('caller_id')}")
        resource_id = edge.get("resource_id")
        if resource_id not in resources:
            errors.append(f"{prefix}.resource_id: unknown resource {resource_id}")
        elif edge.get("action") not in actions.get(resource_id, set()):
            errors.append(f"{prefix}.action: action is not declared by {resource_id}")
        interface_id = edge.get("interface_id")
        if interface_id is not None and interface_id not in interfaces:
            errors.append(f"{prefix}.interface_id: unknown interface {interface_id}")
        workflow_id = edge.get("workflow_id")
        if workflow_id is not None and workflow_id not in workflows:
            errors.append(f"{prefix}.workflow_id: unknown workflow {workflow_id}")
        boundary_id = edge.get("trust_boundary_id")
        if boundary_id is not None and boundary_id not in boundaries:
            errors.append(f"{prefix}.trust_boundary_id: unknown trust boundary {boundary_id}")
    return errors


def record_index(manifest: dict[str, Any], collection: str) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in manifest.get("spec", {}).get(collection, [])}


def runtime_binding(record: dict[str, Any] | None, environment: str) -> dict[str, Any]:
    if not record:
        return {}
    value = record.get("bindings", {}).get(environment) or {}
    return value if isinstance(value, dict) else {}
