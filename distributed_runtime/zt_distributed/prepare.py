"""Prepare step (runs once, inside the runtime image, as root, in the `ops` helper container).

Generates ONLY fresh local deployment credentials -- the committed development keys of
zero_trust_pdp_task4_secure/security/dev_keys are NOT in the image and are never used:

  /secrets  (named volume, per-owner 0400 files; mounted by sub-path so each container
             sees only its own material)
      task4-keys/      Ed25519 keys of the Task 4/5 prototype (PEP request proof, risk /
                       IdP / workflow / approval / secondary assertions, policy signing,
                       PDP decision signing) -- gateway only
      agent-ca/ca.key  Agent Identity CA private key (issuer only)
      agents/<id>/enroll.key  per-agent enrollment key (that agent only)
      spire-node/      SPIRE x509pop node key + cert (SPIRE agent only)
  /public   (bind mount runtime/public; public material only)
      task4/policy_store/   the signed PSL policy store (*.psl + policy_fields.yaml),
                            content unchanged, re-signed with the fresh policy key
      spire/node_ca.pem, spire/entries.json
      agent-ca/ca.pem
      config/identity_map.json (services), config/agent_registry.json (agents)
  /golden   (named volume) synthetic datasets restored before every run
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from zt_identity.agent_identity import certs

from . import catalog
from .backplane_adapter import BACKPLANE_ROOT

TASK4 = BACKPLANE_ROOT / "zero_trust_pdp_task4_secure"
TASK4_KEY_NAMES = ["pep", "risk", "idp", "workflow", "approval", "secondary", "policy", "pdp_signing"]


def _own(path: Path, uid: int, mode: int) -> None:
    os.chown(path, uid, uid)
    os.chmod(path, mode)


def _write_secret(path: Path, data: bytes, uid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    _own(path, uid, 0o400)


def _pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _pem_pub(key) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def task4_material(secrets: Path, public: Path) -> dict:
    from zt_backplane.crypto import generate_keypair
    from zt_psl.signing import load_private_key, sign_file

    gw_uid = catalog.SERVICES["zt-gateway"].uid
    kdir = secrets / "task4-keys"
    if kdir.exists():
        shutil.rmtree(kdir)
    kdir.mkdir(parents=True)
    for name in TASK4_KEY_NAMES:
        generate_keypair(kdir / f"{name}_private.pem", kdir / f"{name}_public.pem")
        _own(kdir / f"{name}_private.pem", gw_uid, 0o400)
        _own(kdir / f"{name}_public.pem", gw_uid, 0o444)
    _own(kdir, gw_uid, 0o500)

    # The signed PSL policy store, content unchanged, re-signed with the fresh policy key.
    src = TASK4 / "policy_store"
    out = public / "task4" / "policy_store"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    policy_key = load_private_key(kdir / "policy_private.pem")
    files = sorted(p.name for p in src.glob("*.psl")) + ["policy_fields.yaml"]
    for name in files:
        shutil.copyfile(src / name, out / name)
        sign_file(out / name, policy_key, issuer="policy.prototype", key_id="policy-1")
    return {"policy_files": files}


def spire_material(secrets: Path, public: Path) -> None:
    ca_key, ca_cert = certs.make_ca("SPIRE x509pop node CA (ztbp deployment)", days=30)
    node_key = certs.new_key()
    now = datetime.now(timezone.utc)
    node_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "node-1")]))
        .issuer_name(ca_cert.subject)
        .public_key(node_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=29))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    d = secrets / "spire-node"
    if d.exists():
        shutil.rmtree(d)
    _write_secret(d / "node.key", _pem_key(node_key), 0)
    _write_secret(d / "node.pem", node_cert.public_bytes(serialization.Encoding.PEM), 0)
    _own(d, 0, 0o500)
    sp = public / "spire"
    sp.mkdir(parents=True, exist_ok=True)
    (sp / "node_ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    entries = [{"spiffe_id": w.spiffe_id, "parent_id": catalog.NODE_ALIAS, "selectors": catalog.selectors(w),
                "workload": w.name, "uid": w.uid}
               for w in list(catalog.SERVICES.values()) + list(catalog.AGENTS.values())]
    (sp / "entries.json").write_text(json.dumps(entries, indent=1))


def agent_identity_material(secrets: Path, public: Path) -> None:
    issuer_uid = catalog.SERVICES["agent-issuer"].uid
    ca_key, ca_cert = certs.make_ca("Citi P3 ZT Backplane Agent Identity CA", days=30)
    d = secrets / "agent-ca"
    if d.exists():
        shutil.rmtree(d)
    _write_secret(d / "ca.key", _pem_key(ca_key), issuer_uid)
    _own(d, issuer_uid, 0o500)
    (public / "agent-ca").mkdir(parents=True, exist_ok=True)
    (public / "agent-ca" / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    registry = {"version": 1, "agents": {}}
    agents_dir = secrets / "agents"
    if agents_dir.exists():
        shutil.rmtree(agents_dir)
    for agent_id, w in catalog.AGENTS.items():
        key = certs.new_key()
        _write_secret(agents_dir / agent_id / "enroll.key", _pem_key(key), w.uid)
        _own(agents_dir / agent_id, w.uid, 0o500)
        registry["agents"][agent_id] = {
            "allowed_workloads": [w.spiffe_id],
            "enrollment_public_key_pem": _pem_pub(key),
            "enabled": True,
            "identity_version": 1,
        }
    os.chmod(agents_dir, 0o755)
    cfg = public / "config"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "agent_registry.json").write_text(json.dumps(registry, indent=1))


def identity_map(public: Path) -> None:
    """Controlled service map: callers of the gateway that are services, not agents."""
    entries = {}
    for w in catalog.SERVICES.values():
        if w.agent_id:                                    # services that call the gateway
            entries[w.spiffe_id] = {"kind": "service", "agent_id": w.agent_id, "identity_version": 1,
                                    "enabled": True, "user_roles": list(w.user_roles)}
    cfg = public / "config"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "identity_map.json").write_text(json.dumps(
        {"version": 1, "trust_domain": catalog.TRUST_DOMAIN, "entries": entries}, indent=1))


def golden_adk_db(golden: Path, n_clean: int, n_mismatch: int) -> None:
    from bank_adk.infra.repository import BankingRepository  # original repository code

    path = golden / "adk_banking.db"
    if path.exists():
        path.unlink()
    BankingRepository(db_path=path).initialize()      # original schema + original seed
    rows = [(f"EOD-B-{i:06d}", "2026-04-21", round(1000 + i * 0.01, 2), round(1000 + i * 0.01, 2), 1, "ready",
             json.dumps({"expected_items": 43, "source_system": "synthetic_core_banking"})) for i in range(n_clean)]
    rows += [(f"EOD-M-{i:05d}", "2026-04-21", 1000.00, 990.00, 1, "ready",
              json.dumps({"expected_items": 43, "source_system": "synthetic_core_banking"})) for i in range(n_mismatch)]
    rows += [(f"EOD-N-{i:05d}", "2026-04-21", 1000.00, 1000.00, 0, "pending",     # not ready
              json.dumps({"expected_items": 43, "source_system": "synthetic_core_banking"})) for i in range(n_mismatch)]
    with sqlite3.connect(path) as conn:
        conn.executemany("INSERT INTO eod_batches VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        conn.execute("PRAGMA journal_mode=DELETE")
    os.chmod(path, 0o644)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--secrets", default="/secrets")
    ap.add_argument("--public", default="/public")
    ap.add_argument("--golden", default="/golden")
    ap.add_argument("--eod-clean", type=int, default=2000)
    ap.add_argument("--eod-mismatch", type=int, default=200)
    ns = ap.parse_args()
    secrets, public, golden = Path(ns.secrets), Path(ns.public), Path(ns.golden)
    for p in (secrets, public, golden):
        p.mkdir(parents=True, exist_ok=True)
    os.chmod(secrets, 0o755)
    t4 = task4_material(secrets, public)
    spire_material(secrets, public)
    agent_identity_material(secrets, public)
    identity_map(public)
    golden_adk_db(golden, ns.eod_clean, ns.eod_mismatch)
    manifest = {"prepared_at": datetime.now(timezone.utc).isoformat(), "trust_domain": catalog.TRUST_DOMAIN,
                "agents": sorted(catalog.AGENTS), "services": sorted(catalog.SERVICES),
                "eod_clean": ns.eod_clean, "eod_mismatch": ns.eod_mismatch, **t4}
    (public / "prepare_manifest.json").write_text(json.dumps(manifest, indent=1))
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
