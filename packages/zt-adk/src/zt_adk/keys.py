"""Deployment key material of a protected application (generated, never shipped).

Two directories, kept apart on purpose:

``keys_dir`` (runtime: the plugin / gateway process reads it)
    pep, risk, idp, workflow   issuers of the signed PDP request and its context assertions
    pdp_signing                the PDP's decision signing key
    trusted_issuers.yaml       public keys the PDP trusts, with their purposes
    security_context.yaml      risk thresholds, authentication factor weights, lifetimes
``keys_dir/signing``           the policy signing key (used by ``zt-adk build`` only)
``approver_keys_dir``          one key per approver (human approval) and per secondary
                               authorizer; the runtime never reads this directory

Every private key file is created with mode 0600 (where the OS supports it).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

RUNTIME_ISSUERS = {
    "pep": ("pep.zt_adk", "pep-1", "request_proof"),
    "risk": ("risk.zt_adk", "risk-1", "risk_assertion"),
    "idp": ("idp.zt_adk", "idp-1", "auth_assertion"),
    "workflow": ("workflow.zt_adk", "workflow-1", "workflow_assertion"),
}
POLICY_ISSUER = ("policy.zt_adk", "policy-1", "policy_bundle")
PDP_ISSUER = ("pdp.zt_adk", "pdp-decision-1")
RISK_THRESHOLD_VERSION = "zt-adk-risk-1"
AUTH_MAPPING_VERSION = "zt-adk-auth-1"

# authentication factors the runtimes can verify
AUTH_FACTOR_WEIGHTS = {
    "workload_identity": 2,       # X.509-SVID of the calling workload verified over mTLS (gateway)
    "agent_credential": 2,        # agent certificate + RFC 9421 request signature verified (gateway)
    "process_identity": 1,        # in-process plugin: the agent runs inside the protected process
    "process_svid": 1,            # in-process plugin: the process holds a verified SPIFFE SVID
    "user_session": 1,            # the run belongs to a session of an authenticated ingress
}


class KeyError_(RuntimeError):
    pass


def _write_private(path: Path, key: Ed25519PrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_public(path: Path, key: Ed25519PublicKey) -> None:
    path.write_bytes(key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def load_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyError_(f"not an Ed25519 private key: {path}")
    return key


def fingerprint(public: Ed25519PublicKey) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return digest.finalize().hex()[:32]


def _pair(directory: Path, name: str, *, overwrite: bool) -> Ed25519PrivateKey:
    private = directory / f"{name}_private.pem"
    if private.exists() and not overwrite:
        return load_private(private)
    key = Ed25519PrivateKey.generate()
    _write_private(private, key)
    _write_public(directory / f"{name}_public.pem", key.public_key())
    return key


@dataclass
class Approver:
    name: str
    issuer: str
    key_id: str
    purpose: str            # human_approval | secondary_authorization
    public_key_file: Path
    private_key_file: Path


def approver_issuer(name: str, secondary: bool) -> str:
    return f"{'secondary' if secondary else 'approver'}.{name}"


def init_keys(keys_dir: Path, approver_dir: Path, *, approvers: list[str], secondaries: list[str],
              max_assertion_lifetime: int = 300, overwrite: bool = False) -> dict[str, Any]:
    keys_dir.mkdir(parents=True, exist_ok=True)
    approver_dir.mkdir(parents=True, exist_ok=True)
    for role in RUNTIME_ISSUERS:
        _pair(keys_dir, role, overwrite=overwrite)
    _pair(keys_dir, "pdp_signing", overwrite=overwrite)
    (keys_dir / "signing").mkdir(exist_ok=True)
    _pair(keys_dir / "signing", "policy", overwrite=overwrite)
    for name in approvers:
        add_approver(keys_dir, approver_dir, name, secondary=False, overwrite=overwrite, write_config=False)
    for name in secondaries:
        add_approver(keys_dir, approver_dir, name, secondary=True, overwrite=overwrite, write_config=False)
    write_trust_config(keys_dir, approver_dir, max_assertion_lifetime=max_assertion_lifetime)
    return describe(keys_dir, approver_dir)


def add_approver(keys_dir: Path, approver_dir: Path, name: str, *, secondary: bool, overwrite: bool = False,
                 write_config: bool = True, max_assertion_lifetime: int | None = None) -> Approver:
    if not name.replace("_", "").replace("-", "").isalnum():
        raise KeyError_(f"approver name {name!r}: letters, digits, '-' and '_' only")
    prefix = "secondary" if secondary else "approver"
    key = _pair(approver_dir, f"{prefix}_{name}", overwrite=overwrite)
    # the public half is also kept with the runtime keys (the PDP's trust store reads it)
    pub_dir = keys_dir / "approvers"
    pub_dir.mkdir(exist_ok=True)
    _write_public(pub_dir / f"{prefix}_{name}_public.pem", key.public_key())
    if write_config:
        current = _read_meta(keys_dir).get("max_assertion_lifetime_seconds", 300)
        write_trust_config(keys_dir, approver_dir, max_assertion_lifetime=max_assertion_lifetime or current)
    return Approver(name, approver_issuer(name, secondary), "key-1",
                    "secondary_authorization" if secondary else "human_approval",
                    pub_dir / f"{prefix}_{name}_public.pem", approver_dir / f"{prefix}_{name}_private.pem")


def list_approvers(keys_dir: Path) -> list[Approver]:
    out = []
    pub_dir = keys_dir / "approvers"
    for p in sorted(pub_dir.glob("*_public.pem")) if pub_dir.exists() else []:
        stem = p.name[: -len("_public.pem")]
        prefix, _, name = stem.partition("_")
        secondary = prefix == "secondary"
        out.append(Approver(name, approver_issuer(name, secondary), "key-1",
                            "secondary_authorization" if secondary else "human_approval", p, Path()))
    return out


def _read_meta(keys_dir: Path) -> dict[str, Any]:
    p = keys_dir / "keys.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def write_trust_config(keys_dir: Path, approver_dir: Path, *, max_assertion_lifetime: int) -> None:
    issuers: list[dict[str, Any]] = []
    for role, (issuer, key_id, purpose) in RUNTIME_ISSUERS.items():
        issuers.append({"id": issuer, "keys": [{"key_id": key_id, "public_key_file": f"{role}_public.pem",
                                                "purposes": [purpose]}]})
    issuers.append({"id": POLICY_ISSUER[0], "keys": [{"key_id": POLICY_ISSUER[1],
                                                      "public_key_file": "signing/policy_public.pem",
                                                      "purposes": [POLICY_ISSUER[2]]}]})
    for a in list_approvers(keys_dir):
        issuers.append({"id": a.issuer, "keys": [{"key_id": a.key_id,
                                                  "public_key_file": f"approvers/{a.public_key_file.name}",
                                                  "purposes": [a.purpose]}]})
    header = "# Generated by zt-adk keys: the public keys the PDP trusts, with their purposes.\n"
    (keys_dir / "trusted_issuers.yaml").write_text(header + yaml.safe_dump({"issuers": issuers}, sort_keys=False),
                                                   encoding="utf-8")
    security = {
        "clock_skew_seconds": 5,
        "max_assertion_lifetime_seconds": int(max(300, max_assertion_lifetime)),
        "risk_threshold_version": RISK_THRESHOLD_VERSION,
        "auth_factor_mapping_version": AUTH_MAPPING_VERSION,
        "risk_thresholds": {"low": [0, 249], "medium": [250, 499], "high": [500, 749], "critical": [750, 1000]},
        "auth_factor_weights": dict(AUTH_FACTOR_WEIGHTS),
    }
    (keys_dir / "security_context.yaml").write_text(
        "# Generated by zt-adk keys: risk thresholds and authentication factor weights.\n"
        + yaml.safe_dump(security, sort_keys=False), encoding="utf-8")
    meta = {"created_at": _read_meta(keys_dir).get("created_at") or datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "max_assertion_lifetime_seconds": int(max(300, max_assertion_lifetime)),
            "runtime_issuers": {r: v[0] for r, v in RUNTIME_ISSUERS.items()},
            "policy_issuer": POLICY_ISSUER[0], "pdp_issuer": PDP_ISSUER[0],
            "approvers": [a.issuer for a in list_approvers(keys_dir)]}
    (keys_dir / "keys.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


def describe(keys_dir: Path, approver_dir: Path) -> dict[str, Any]:
    meta = _read_meta(keys_dir)
    meta["keys_dir"] = str(keys_dir)
    meta["approver_keys_dir"] = str(approver_dir)
    return meta


def require_keys(keys_dir: Path) -> None:
    missing = [f for f in ("pep_private.pem", "risk_private.pem", "idp_private.pem", "workflow_private.pem",
                           "pdp_signing_private.pem", "trusted_issuers.yaml", "security_context.yaml")
               if not (keys_dir / f).exists()]
    if missing:
        raise KeyError_(f"deployment keys missing in {keys_dir}: {missing}; run 'zt-adk keys init'")
