"""Legacy priority engine vs PSL deny-overrides engine.

The full report (552,960 requests) is produced by scripts/psl_differential_report.py;
this test runs a reduced corpus on every test run and checks that the comparison can
actually see a difference (a mutated, re-signed PSL policy must be reported)."""
from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

from zt_psl.signing import load_private_key, sign_file

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("psl_differential_report", ROOT / "scripts" / "psl_differential_report.py")
diff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diff)                                    # type: ignore[union-attr]

REDUCED = dict(risks=("low", "critical"), auths=(1, 2), approvals=((False, False), (True, True)),
               times=("business_hours", "night"))


def test_psl_policies_reproduce_every_legacy_decision(tmp_path):
    """The translated Task 4 policies (store without the intent rules) reproduce every legacy decision."""
    store = diff.store_without(ROOT / "policy_store", ("intent.psl",), tmp_path)
    r = diff.run(ROOT / "legacy_policy_store", store, ROOT / "config", **REDUCED)
    assert r["requests"] > 10_000
    assert r["different_decision"] == 0, r["differences"][:3]
    assert r["obligation_differences"] == []
    for outcome in ("ALLOW", "ALLOW_WITH_OBLIGATIONS", "MANUAL_REVIEW", "REAUTHENTICATE", "DENY"):
        assert r["outcomes"]["psl"].get(outcome, 0) > 0, outcome      # every outcome is exercised


def test_differential_detects_a_changed_policy(tmp_path):
    mutated = tmp_path / "policy_store"
    shutil.copytree(ROOT / "policy_store", mutated)
    path = mutated / "front_office.psl"
    text = path.read_text(encoding="utf-8")
    # weaken: no step-up authentication for the customer profile any more
    path.write_text(text.replace("&& auth.strength <= 1);", "&& auth.strength > 10);"), encoding="utf-8")
    sign_file(path, load_private_key(ROOT / "security" / "dev_keys" / "policy_private.pem"),
              issuer="policy.prototype", key_id="policy-1")
    r = diff.run(ROOT / "legacy_policy_store", mutated, ROOT / "config", **REDUCED)
    kinds = {(d["legacy"], d["psl"]) for d in r["differences"]}
    assert ("REAUTHENTICATE", "ALLOW_WITH_OBLIGATIONS") in kinds
    assert r["different_decision"] > 0


def test_automatic_bundle_translation_reproduces_legacy_decisions(tmp_path):
    """The generic translator (used for generated runtime bundles) must also reproduce
    every legacy decision when applied to the legacy bundles themselves."""
    import yaml
    from zt_psl.fields import FieldCatalog
    from zt_backplane.psl_translate import bundle_to_psl

    store = tmp_path / "auto"
    store.mkdir()
    shutil.copy(ROOT / "policy_store" / "policy_fields.yaml", store / "policy_fields.yaml")
    shutil.copy(ROOT / "policy_store" / "core.psl", store / "core.psl")
    windows = FieldCatalog.load(store / "policy_fields.yaml").windows
    for src in sorted((ROOT / "legacy_policy_store").glob("*.yaml")):
        raw = yaml.safe_load(src.read_text(encoding="utf-8"))
        (store / (src.stem + ".psl")).write_text(bundle_to_psl(raw, windows=windows, source=src.name),
                                                 encoding="utf-8")
    key = load_private_key(ROOT / "security" / "dev_keys" / "policy_private.pem")
    for p in sorted(store.iterdir()):
        sign_file(p, key, issuer="policy.prototype", key_id="policy-1")
    r = diff.run(ROOT / "legacy_policy_store", store, ROOT / "config", **REDUCED)
    assert r["different_decision"] == 0, r["differences"][:3]
    assert r["obligation_differences"] == []


def test_intent_rules_only_make_decisions_stricter():
    """With intent.psl enforced, every change against the legacy engine comes from an intent
    rule and is stricter (deny-overrides: adding rules never relaxes a decision)."""
    r = diff.run(ROOT / "legacy_policy_store", ROOT / "policy_store", ROOT / "config", **REDUCED)
    assert r["different_decision"] > 0                      # the intent rules do change decisions
    for d in r["differences"]:
        assert d["psl_policy"].startswith("intent."), d
        assert diff.STRICT[d["psl"]] > diff.STRICT[d["legacy"]], d
