from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import IdentityRecord, ResourceRecord


class IdentityRegistry:
    """Local prototype identity adapter.

    TODO(CITI-IDENTITY): Replace or wrap this class with Citi workload identity,
    service-mesh identity, signed JWT/SPIFFE identity, or the actual agent registry.
    """

    def __init__(self, records: dict[str, IdentityRecord], source: Path):
        self._records = records
        self.source = source

    @classmethod
    def from_yaml(cls, path: str | Path) -> "IdentityRegistry":
        source = Path(path)
        raw = _load_yaml(source)
        records: dict[str, IdentityRecord] = {}
        for item in raw.get("identities", []):
            record = IdentityRecord.model_validate(item)
            if record.id in records:
                raise ValueError(f"duplicate identity: {record.id}")
            records[record.id] = record
        return cls(records, source)

    def get(self, subject: str) -> IdentityRecord | None:
        return self._records.get(subject)

    def __len__(self) -> int:
        return len(self._records)


class ResourceCatalog:
    """Starter resource/action catalog.

    TODO(CITI-ZTIR): Replace the local YAML with Task 1 ZT-IR / Task 2 scanner output.
    """

    def __init__(self, records: dict[str, ResourceRecord], source: Path):
        self._records = records
        self.source = source

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ResourceCatalog":
        source = Path(path)
        raw = _load_yaml(source)
        records: dict[str, ResourceRecord] = {}
        for item in raw.get("resources", []):
            record = ResourceRecord.model_validate(item)
            if record.id in records:
                raise ValueError(f"duplicate resource: {record.id}")
            records[record.id] = record
        return cls(records, source)

    def get(self, resource: str) -> ResourceRecord | None:
        return self._records.get(resource)

    def __len__(self) -> int:
        return len(self._records)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return data
