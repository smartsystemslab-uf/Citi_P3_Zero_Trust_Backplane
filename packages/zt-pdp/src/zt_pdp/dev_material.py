"""Local development trust material of the PDP prototype.

Nothing created here is committed to version control:

* ``security/dev_keys/*.pem`` -- one Ed25519 key pair per prototype issuer (PEP request
  proof, risk / IdP / workflow / approval / secondary assertions, PSL policy signing, PDP
  decision signing), generated per checkout on first use;
* ``policy_store/*.sig.json`` and ``legacy_policy_store/*.sig.json`` -- detached
  signatures of the development policy store, made with the local policy key.

Signatures are written only where none exists yet, or when the policy key was generated in
this very call (then no existing signature can be valid). An existing signature is never
replaced automatically: a policy edited after signing still fails verification until it
is re-signed on purpose (``scripts/sign_psl_policies.py``).

Deployments never use this material: ``zt-adk`` deployments and the distributed runtime
generate their own keys.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterator

from cryptography.hazmat.primitives import serialization

from .crypto import generate_keypair, load_private_key

ROOT = Path(__file__).resolve().parents[2]
KEY_NAMES = ("pep", "risk", "idp", "workflow", "approval", "secondary", "policy", "pdp_signing")
POLICY_ISSUER, POLICY_KEY_ID = "policy.prototype", "policy-1"
_LOCK_STALE_S = 120.0


def key_dir(root: Path = ROOT) -> Path:
    return Path(root) / "security" / "dev_keys"


class _DirLock:
    """Exclusive lock between processes (a lock file created with O_EXCL)."""

    def __init__(self, directory: Path) -> None:
        self.path = directory / ".dev_material.lock"

    def __enter__(self) -> "_DirLock":
        deadline = time.monotonic() + _LOCK_STALE_S
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    if time.time() - self.path.stat().st_mtime > _LOCK_STALE_S:
                        self.path.unlink(missing_ok=True)       # holder died
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError(f"could not acquire {self.path}")
                time.sleep(0.05)

    def __exit__(self, *exc: object) -> None:
        self.path.unlink(missing_ok=True)


def _ensure_key(directory: Path, name: str) -> bool:
    """Create the key pair ``name`` if needed. Returns True when a new private key was made."""
    private = directory / f"{name}_private.pem"
    public = directory / f"{name}_public.pem"
    if private.exists():
        if not public.exists():
            key = load_private_key(private)
            public.write_bytes(key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        return False
    generate_keypair(private, public)
    try:
        os.chmod(private, 0o600)
    except OSError:
        pass
    return True


def psl_store_files(root: Path = ROOT) -> Iterator[Path]:
    """Signed files of the development PSL policy store."""
    store = Path(root) / "policy_store"
    yield from sorted(store.glob("*.psl"))
    if (store / "policy_fields.yaml").exists():
        yield store / "policy_fields.yaml"


def legacy_bundle_files(root: Path = ROOT) -> Iterator[Path]:
    """Signed YAML bundles of the legacy store (differential tests only)."""
    legacy = Path(root) / "legacy_policy_store"
    if legacy.is_dir():
        yield from sorted(legacy.glob("*.yaml"))


def sign_legacy_bundle(path: Path, private_key: object) -> Path:
    """Detached signature of a legacy YAML bundle (format of zt_pdp.policy.PolicyBundle)."""
    import json
    from datetime import datetime, timezone

    import yaml

    from .canonical import sha256_hex
    from .crypto import sign_mapping

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    sidecar = {
        "schema_version": "1.0",
        "algorithm": "Ed25519",
        "bundle_digest": sha256_hex(raw),
        "issuer": POLICY_ISSUER,
        "key_id": POLICY_KEY_ID,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "signature": sign_mapping(private_key, raw),          # type: ignore[arg-type]
    }
    out = Path(path).with_suffix(".sig.json")
    out.write_text(json.dumps(sidecar, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def ensure_dev_material(root: Path = ROOT) -> dict[str, list[str]]:
    """Create missing development keys and missing development-store signatures."""
    from zt_psl.signing import sidecar_path, sign_file

    root = Path(root)
    directory = key_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    signed: list[str] = []
    with _DirLock(directory):
        for name in KEY_NAMES:
            if _ensure_key(directory, name):
                created.append(name)
        new_policy_key = "policy" in created
        policy_key = None
        for path in psl_store_files(root):
            if new_policy_key or not sidecar_path(path).exists():
                if policy_key is None:
                    policy_key = load_private_key(directory / "policy_private.pem")
                sign_file(path, policy_key, issuer=POLICY_ISSUER, key_id=POLICY_KEY_ID)
                signed.append(path.name)
        for path in legacy_bundle_files(root):
            if new_policy_key or not path.with_suffix(".sig.json").exists():
                if policy_key is None:
                    policy_key = load_private_key(directory / "policy_private.pem")
                sign_legacy_bundle(path, policy_key)
                signed.append(f"legacy/{path.name}")
    return {"keys_created": created, "signed": signed}


def dev_key_path(filename: str, root: Path = ROOT) -> Path:
    """Path of a development key file, creating the development material first if needed."""
    path = key_dir(root) / filename
    if not path.exists():
        ensure_dev_material(root)
    return path
