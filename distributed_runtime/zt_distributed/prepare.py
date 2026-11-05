"""Prepare step (runs once, inside the runtime image, as root, in the ``ops`` helper container).

Generates fresh deployment material only -- nothing from the source tree is a key:

  /secrets  (named volume, per-owner 0400 files; mounted by sub-path so each container sees
             only its own material)
      zt-keys/            runtime keys of the PEP / PDP side (request proof, risk / IdP /
                          workflow assertions, PDP decision signing) and the trust store --
                          gateway only; zt-keys/signing/ holds the policy signing key
      agent-ca/ca.key     Agent Identity CA private key (issuer only)
      agents/<id>/enroll.key  per-agent enrollment key (that agent's workload only)
      spire-node/         SPIRE x509pop node key + cert (SPIRE agent only)
  /approvers (bind mount runtime/approver-keys, host only): approver keys -- never mounted into
             a runtime container
  /public   (bind mount runtime/public; public material only)
      bundle/             the protection bundle, built here from the image's application and
                          signed with the fresh policy key (zt-adk build)
      spire/node_ca.pem, spire/entries.json, agent-ca/ca.pem
      config/identity_map.json (ingress service + its end-user roles), config/agent_registry.json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from zt_identity.agent_identity import certs

from . import deployment as D
from .appload import PROFILE_PATH, load_app


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


def protection_material(dep: D.Deployment, secrets: Path, approvers: Path, public: Path) -> dict:
    """Deployment keys, approver keys, and the signed protection bundle of the image's application."""
    from zt_adk.build import build
    from zt_adk.keys import init_keys

    app = load_app(resolve_toolsets=True, apply_model_override=False)
    prof = app.profile
    keys_dir = secrets / "zt-keys"
    if keys_dir.exists():
        shutil.rmtree(keys_dir)
    for p in approvers.glob("*.pem"):
        p.unlink()
    approver_names = [n.strip() for n in os.environ.get("ZT_APPROVERS", "approver").split(",") if n.strip()]
    secondary_names = [n.strip() for n in os.environ.get("ZT_SECONDARIES", "").split(",") if n.strip()]
    if prof.approvals.critical == "dual" and not secondary_names:
        secondary_names = ["secondary"]
    info = init_keys(keys_dir, approvers, approvers=approver_names, secondaries=secondary_names,
                     max_assertion_lifetime=prof.approvals.lifetime_seconds, overwrite=True)
    bundle_dir = public / "bundle"
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    prof.keys_dir = str(keys_dir)
    prof.approver_keys_dir = str(approvers)
    prof.bundle_dir = str(bundle_dir)
    result = build(prof, root_agent=app.root, app_name=app.app_name, out_dir=bundle_dir, skip_static=True)
    if result.model.fingerprint() != dep.fingerprint:
        raise RuntimeError("the application differs from the deployment descriptor: run 'ctl describe' again")
    gw = dep.gateway.uid
    for p in keys_dir.rglob("*"):
        _own(p, gw, 0o500 if p.is_dir() else 0o400)
    _own(keys_dir, gw, 0o500)
    for p in bundle_dir.rglob("*"):
        os.chmod(p, 0o755 if p.is_dir() else 0o644)
    for p in approvers.glob("*"):
        os.chmod(p, 0o600)
    return {"policy_version": result.policy_version, "logical_peps": result.logical_peps,
            "physical_peps": result.physical_peps, "rules": result.rules, "approvers": info.get("approvers")}


def spire_material(dep: D.Deployment, secrets: Path, public: Path) -> None:
    ca_key, ca_cert = certs.make_ca("SPIRE x509pop node CA (zt-adk deployment)", days=30)
    node_key = certs.new_key()
    now = datetime.now(timezone.utc)
    node_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "node-1")]))
        .issuer_name(ca_cert.subject).public_key(node_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=29))
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
    entries = [{"spiffe_id": w.spiffe_id, "parent_id": dep.node_alias, "selectors": dep.selectors(w),
                "workload": w.name, "uid": w.uid}
               for w in list(dep.services.values()) + list(dep.agents.values())]
    (sp / "entries.json").write_text(json.dumps(entries, indent=1))


def agent_identity_material(dep: D.Deployment, secrets: Path, public: Path) -> None:
    issuer_uid = dep.issuer.uid
    ca_key, ca_cert = certs.make_ca("zt-adk Agent Identity CA", days=30)
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
    for agent_id, w in dep.agents.items():
        key = certs.new_key()
        _write_secret(agents_dir / agent_id / "enroll.key", _pem_key(key), w.uid)
        _own(agents_dir / agent_id, w.uid, 0o500)
        registry["agents"][agent_id] = {"allowed_workloads": [w.spiffe_id], "enrollment_public_key_pem": _pem_pub(key),
                                        "enabled": True, "identity_version": 1}
    os.chmod(agents_dir, 0o755)
    cfg = public / "config"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "agent_registry.json").write_text(json.dumps(registry, indent=1))


def identity_map(dep: D.Deployment, public: Path) -> None:
    """Controlled service map: callers of the gateway that are services, not agents."""
    ing = dep.ingress
    entries = {ing.spiffe_id: {"kind": "service", "agent_id": ing.agent_id, "identity_version": 1, "enabled": True,
                               "user_roles": list(ing.user_roles)}}
    cfg = public / "config"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "identity_map.json").write_text(json.dumps(
        {"version": 1, "trust_domain": dep.trust_domain, "entries": entries}, indent=1))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--secrets", default="/secrets")
    ap.add_argument("--public", default="/public")
    ap.add_argument("--approvers", default="/approvers")
    ns = ap.parse_args()
    secrets, public, approvers = Path(ns.secrets), Path(ns.public), Path(ns.approvers)
    for p in (secrets, public, approvers):
        p.mkdir(parents=True, exist_ok=True)
    os.chmod(secrets, 0o755)
    dep = D.load()
    prot = protection_material(dep, secrets, approvers, public)
    spire_material(dep, secrets, public)
    agent_identity_material(dep, secrets, public)
    identity_map(dep, public)
    manifest = {"prepared_at": datetime.now(timezone.utc).isoformat(), "app": dep.app_name,
                "trust_domain": dep.trust_domain, "agents": sorted(dep.agents), "services": sorted(dep.services),
                "profile": str(PROFILE_PATH), **prot}
    (public / "prepare_manifest.json").write_text(json.dumps(manifest, indent=1))
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
