from __future__ import annotations
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator, FormatChecker
import json

class ManifestValidationError(ValueError):
    pass

def schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / "zt_manifest.schema.json"

def validate_manifest(manifest: dict[str, Any], schema_file: str | Path | None = None) -> list[str]:
    path = Path(schema_file) if schema_file else schema_path()
    schema = json.loads(path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(manifest), key=lambda error: list(error.absolute_path))
    messages = []
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
    resource_actions = {item.get("id"): {action.get("name") for action in item.get("actions", [])} for item in spec.get("resources", [])}
    errors: list[str] = []
    all_ids: list[str] = []
    for collection in ("subjects","resources","interfaces","workflows","interactions","trust_boundaries","policy_bundles","unresolved"):
        all_ids.extend(item.get("id") for item in spec.get(collection, []) if item.get("id"))
    duplicates = sorted({item for item in all_ids if all_ids.count(item) > 1})
    for item in duplicates:
        errors.append(f"duplicate canonical id: {item}")
    for edge in spec.get("interactions", []):
        edge_id = edge.get("id", "<unknown>")
        if edge.get("caller_id") not in subjects:
            errors.append(f"{edge_id}: unknown caller_id {edge.get('caller_id')}")
        if edge.get("resource_id") not in resources:
            errors.append(f"{edge_id}: unknown resource_id {edge.get('resource_id')}")
        if edge.get("interface_id") is not None and edge.get("interface_id") not in interfaces:
            errors.append(f"{edge_id}: unknown interface_id {edge.get('interface_id')}")
        if edge.get("workflow_id") is not None and edge.get("workflow_id") not in workflows:
            errors.append(f"{edge_id}: unknown workflow_id {edge.get('workflow_id')}")
        if edge.get("trust_boundary_id") is not None and edge.get("trust_boundary_id") not in boundaries:
            errors.append(f"{edge_id}: unknown trust_boundary_id {edge.get('trust_boundary_id')}")
        if edge.get("action") not in resource_actions.get(edge.get("resource_id"), set()):
            errors.append(f"{edge_id}: action {edge.get('action')} is not declared by {edge.get('resource_id')}")
        pep = edge.get("pep", {})
        if edge.get("risk") == "critical" and pep.get("required") and pep.get("fail_mode") != "closed":
            errors.append(f"{edge_id}: critical protected edge must fail closed")
    return errors

def unresolved_items(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in manifest.get("spec", {}).get("unresolved", []) if item.get("status") == "open"]
