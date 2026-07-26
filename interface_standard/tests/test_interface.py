from pathlib import Path
from zt_interface.loader import load_yaml, deep_merge
from zt_interface.validator import validate_manifest, unresolved_items
from zt_interface.compiler import compile_task4

ROOT = Path(__file__).resolve().parents[1]

def test_example_manifest_is_valid():
    manifest = load_yaml(ROOT / "examples" / "zt_manifest.example.yaml")
    assert validate_manifest(manifest) == []

def test_unresolved_fields_are_reported():
    manifest = load_yaml(ROOT / "examples" / "zt_manifest.example.yaml")
    ids = {item["id"] for item in unresolved_items(manifest)}
    assert "gap.citi_identity_issuer" in ids

def test_overlay_merges_records_by_id():
    base = {"spec": {"subjects": [{"id": "agent.front_office.fraud", "bindings": {"prototype": {"runtime_id": "fraud_agent"}}}]}}
    overlay = {"spec": {"subjects": [{"id": "agent.front_office.fraud", "bindings": {"citi_dev": {"runtime_id": "citi-fraud-workload"}}}]}}
    merged = deep_merge(base, overlay)
    subject = merged["spec"]["subjects"][0]
    assert subject["bindings"]["prototype"]["runtime_id"] == "fraud_agent"
    assert subject["bindings"]["citi_dev"]["runtime_id"] == "citi-fraud-workload"

def test_task4_compiler(tmp_path):
    manifest = load_yaml(ROOT / "examples" / "zt_manifest.example.yaml")
    compile_task4(manifest, tmp_path)
    identities = load_yaml(tmp_path / "identities.yaml")
    resources = load_yaml(tmp_path / "resources.yaml")
    assert any(item["id"] == "fraud_agent" for item in identities["identities"])
    assert any(item["id"] == "ledger" for item in resources["resources"])
