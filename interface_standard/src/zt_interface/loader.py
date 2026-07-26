from __future__ import annotations
from copy import deepcopy
from pathlib import Path
from typing import Any
import yaml

ID_LIST_KEYS = {"subjects", "resources", "interfaces", "workflows", "interactions", "trust_boundaries", "policy_bundles", "unresolved"}

def load_yaml(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"YAML root must be an object: {path}")
    return value

def save_yaml(path: str | Path, value: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(value, handle, sort_keys=False, allow_unicode=True)

def deep_merge(base: Any, overlay: Any, key: str | None = None) -> Any:
    if overlay is None:
        return None
    if isinstance(base, dict) and isinstance(overlay, dict):
        result = deepcopy(base)
        for child_key, child_value in overlay.items():
            if child_key in result:
                result[child_key] = deep_merge(result[child_key], child_value, child_key)
            else:
                result[child_key] = deepcopy(child_value)
        return result
    if isinstance(base, list) and isinstance(overlay, list) and key in ID_LIST_KEYS:
        result = deepcopy(base)
        positions = {item.get("id"): index for index, item in enumerate(result) if isinstance(item, dict) and item.get("id")}
        for item in overlay:
            if not isinstance(item, dict) or not item.get("id"):
                raise ValueError(f"Overlay list {key!r} requires objects with id")
            item_id = item["id"]
            if item_id in positions:
                idx = positions[item_id]
                result[idx] = deep_merge(result[idx], item)
            else:
                positions[item_id] = len(result)
                result.append(deepcopy(item))
        return result
    return deepcopy(overlay)
