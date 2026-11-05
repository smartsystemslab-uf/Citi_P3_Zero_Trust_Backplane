from __future__ import annotations

from pathlib import Path

import pytest

from zt_pep.manifest import load_manifest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def manifest():
    return load_manifest(ROOT / "examples" / "citi_project_baseline.yaml")
