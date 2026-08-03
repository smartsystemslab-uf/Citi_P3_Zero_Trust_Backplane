from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from zt_pep.generator import generate_artifacts
from zt_pep.placement import build_pep_plan


def test_all_task3_deliverables_are_generated(tmp_path, manifest):
    plan, updated = build_pep_plan(manifest)
    generate_artifacts(plan, updated, tmp_path)
    expected = [
        "generated_pep_plan.json",
        "zt_manifest.task3.yaml",
        "pep_coverage_report.json",
        "PEP_COVERAGE_REPORT.md",
        "unprotected_paths.json",
        "UNPROTECTED_PATH_REPORT.md",
        "PHYSICAL_PEP_MAP.md",
        "adapters/mcp_wrappers.py",
        "adapters/fastapi_dependencies.py",
        "adapters/data_wrappers.py",
        "adapters/event_wrappers.py",
        "adapters/agent_route_middleware.py",
        "adapters/input_output_pep.py",
        "adapters/pep_registry.py",
    ]
    assert all((tmp_path / item).exists() for item in expected)
    payload = json.loads((tmp_path / "generated_pep_plan.json").read_text(encoding="utf-8"))
    assert payload["coverage"]["sensitive_path_coverage_percent"] == 100.0

    module_path = tmp_path / "adapters" / "pep_registry.py"
    spec = importlib.util.spec_from_file_location("generated_registry", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    assert "pep.fraud_review.read_history" in module.PLACEMENTS
