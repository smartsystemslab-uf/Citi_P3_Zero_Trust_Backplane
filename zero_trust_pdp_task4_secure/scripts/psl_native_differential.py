#!/usr/bin/env python3
"""Differential comparison for the NATIVE MAS runtime policy store.

Rebuilds the store the native runtime used before PSL (legacy YAML bundles with the
ledger_update_agent rebinding + the generated native_mas_runtime YAML bundle, signed
the old way) and compares it with the PSL store the native runtime builds now, on the
native registries (task4_config of a bootstrap output directory).

    python scripts/psl_native_differential.py --native-out <bootstrap output dir>
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BACKPLANE = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(BACKPLANE))

from zt_backplane.canonical import sha256_hex                     # noqa: E402
from zt_backplane.crypto import load_private_key, sign_mapping      # noqa: E402

spec = importlib.util.spec_from_file_location("psl_differential_report", ROOT / "scripts" / "psl_differential_report.py")
diff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diff)                                      # type: ignore[union-attr]


def legacy_sign(path: Path, raw: dict) -> None:
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    key = load_private_key(ROOT / "security" / "dev_keys" / "policy_private.pem")
    path.with_suffix(".sig.json").write_text(json.dumps({
        "schema_version": "1.0", "issuer": "policy.prototype", "key_id": "policy-1", "algorithm": "Ed25519",
        "signed_at": datetime.now(timezone.utc).isoformat(), "bundle_digest": sha256_hex(raw),
        "signature": sign_mapping(key, raw)}, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_legacy_native_store(dest: Path, native_out: Path) -> None:
    """Exactly what NativeMasBackplane._prepare_runtime_policy_store did before PSL."""
    from native_mas_runtime.engine import NativeMasBackplane
    shutil.copytree(ROOT / "legacy_policy_store", dest)
    manifest = yaml.safe_load((native_out / "reconciled_manifest.yaml").read_text(encoding="utf-8"))
    plan = json.loads((native_out / "task3_generated" / "generated_pep_plan.json").read_text(encoding="utf-8"))
    subject_ids = {item["id"] for item in manifest["spec"].get("subjects", [])}
    if "agent.back_office.ledger_update" in subject_ids:
        ledger_path = dest / "ledger_access.yaml"
        raw = yaml.safe_load(ledger_path.read_text(encoding="utf-8"))
        for policy in raw.get("policies", []):
            match = policy.get("match", {})
            if ("resource.back_office.ledger" in match.get("resources", []) and "update" in match.get("actions", [])
                    and "agent.back_office.eod" in match.get("subjects", [])):
                match["subjects"] = ["agent.back_office.ledger_update"]
        legacy_sign(ledger_path, raw)
    legacy_sign(dest / "native_mas_runtime.yaml", NativeMasBackplane._build_native_policy_bundle(plan))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--native-out", required=True)
    ap.add_argument("--out-md", default=str(BACKPLANE / "docs" / "PSL_NATIVE_DIFFERENTIAL_REPORT.md"))
    ap.add_argument("--out-json", default=str(BACKPLANE / "docs" / "psl_differential_native.json"))
    ns = ap.parse_args()
    native_out = Path(ns.native_out)
    with tempfile.TemporaryDirectory() as tmp:
        legacy = Path(tmp) / "legacy_native_store"
        build_legacy_native_store(legacy, native_out)
        r = diff.run(legacy, native_out / "task4_policy_store", native_out / "task4_config",
                     risks=("low", "critical"), auths=(1, 2), approvals=((False, False), (True, True)),
                     times=("business_hours", "night"))
    Path(ns.out_json).write_text(json.dumps(r, indent=1, default=str) + "\n", encoding="utf-8")
    md = diff.to_markdown(r).replace("# Differential report: legacy priority engine vs PSL deny-overrides",
                                     "# Differential report (native MAS runtime store): legacy vs PSL")
    Path(ns.out_md).write_text(md, encoding="utf-8")
    print(f"{r['requests']} requests, {r['different_decision']} different decisions "
          f"({len(r['differences'])} kinds), {len(r['obligation_differences'])} obligation-difference kinds, "
          f"{r['seconds']} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
