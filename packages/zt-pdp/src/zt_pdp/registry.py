from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import IdentityRecord, ResourceRecord


class IdentityRegistry:
    def __init__(self, records: list[IdentityRecord], source: Path):
        self.source = source
        self._by_canonical: dict[str, IdentityRecord] = {}
        self._by_runtime: dict[str, IdentityRecord] = {}
        for record in records:
            if record.canonical_id in self._by_canonical:
                raise ValueError(f"duplicate identity canonical_id: {record.canonical_id}")
            if record.id in self._by_runtime:
                raise ValueError(f"duplicate identity runtime id: {record.id}")
            self._by_canonical[record.canonical_id] = record
            self._by_runtime[record.id] = record

    @classmethod
    def from_yaml(cls, path: str | Path) -> "IdentityRegistry":
        source = Path(path)
        raw = _load_yaml(source)
        return cls([IdentityRecord.model_validate(item) for item in raw.get("identities", [])], source)

    def resolve(self, canonical_id: str, runtime_id: str) -> IdentityRecord | None:
        record = self._by_canonical.get(canonical_id)
        if record is None or record.id != runtime_id:
            return None
        return record

    def get_canonical(self, canonical_id: str) -> IdentityRecord | None:
        return self._by_canonical.get(canonical_id)

    def __len__(self) -> int:
        return len(self._by_canonical)


class ResourceCatalog:
    def __init__(self, records: list[ResourceRecord], source: Path):
        self.source = source
        self._by_canonical: dict[str, ResourceRecord] = {}
        self._by_runtime: dict[str, ResourceRecord] = {}
        for record in records:
            if record.canonical_id in self._by_canonical:
                raise ValueError(f"duplicate resource canonical_id: {record.canonical_id}")
            if record.id in self._by_runtime:
                raise ValueError(f"duplicate resource runtime id: {record.id}")
            self._by_canonical[record.canonical_id] = record
            self._by_runtime[record.id] = record

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ResourceCatalog":
        source = Path(path)
        raw = _load_yaml(source)
        return cls([ResourceRecord.model_validate(item) for item in raw.get("resources", [])], source)

    def resolve(self, canonical_id: str, runtime_id: str | None) -> ResourceRecord | None:
        record = self._by_canonical.get(canonical_id)
        if record is None:
            return None
        if runtime_id is not None and record.id != runtime_id:
            return None
        return record

    def get_canonical(self, canonical_id: str) -> ResourceRecord | None:
        return self._by_canonical.get(canonical_id)

    def __len__(self) -> int:
        return len(self._by_canonical)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return raw
