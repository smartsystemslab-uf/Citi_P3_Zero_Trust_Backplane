"""Signed PSL policy store of the PDP.

The policy directory contains ``*.psl`` files and the field catalogue
``policy_fields.yaml``; every file has a detached signature (``NAME.sig.json``)
by a key with purpose ``policy_bundle`` in the PDP's trust store. Loading:

1. reject legacy YAML bundles (they are no longer evaluated -- refusing them is
   better than silently ignoring policies);
2. verify every signature (any change of a policy or of the catalogue, even a
   comment, invalidates it);
3. compile with ``zt_psl`` (syntax, field catalogue and type checks; unsupported
   PSL fails explicitly);
4. rollback protection per ``@policy_set`` / ``@version`` (as for the bundles).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from zt_psl import CompiledPolicySet, RequestPolicyEngine, compile_policy_set
from zt_psl.fields import FieldCatalog
from zt_psl.signing import PolicySignatureError, verify_file

from .canonical import sha256_hex
from .crypto import TrustedKeyStore
from .policy import PolicyRollbackStore

CATALOG_FILE = "policy_fields.yaml"
SCOPE = "pdp_request"


class PslPolicyStore:
    def __init__(self, policy_set: CompiledPolicySet, versions: dict[str, str], directory: Path) -> None:
        self.policy_set = policy_set
        self.bundle_versions = versions
        self.directory = directory
        self.source_files = sorted(policy_set.files) + [CATALOG_FILE]
        self.version = sha256_hex({"psl_sha256": policy_set.digest,
                                   "policy_sets": [{"id": k, "version": versions[k]} for k in sorted(versions)]})[:16]
        self.engine = RequestPolicyEngine(policy_set, scope=SCOPE, runtime="pdp")
        # compatibility with callers that count / list policies
        self.policies = [r for r in policy_set.rules if SCOPE == r.scope]

    @property
    def catalog(self) -> FieldCatalog:
        return self.policy_set.catalog

    @classmethod
    def load(cls, directory: str | Path, *, keys: TrustedKeyStore,
             rollback_store: PolicyRollbackStore | None = None) -> "PslPolicyStore":
        directory = Path(directory)
        legacy = sorted(p.name for p in directory.glob("*.yaml") if p.name != CATALOG_FILE)
        if legacy:
            raise ValueError(f"YAML policy bundles are no longer evaluated by the PDP; translate them to PSL: {legacy}")
        files = sorted(directory.glob("*.psl"))
        catalog_path = directory / CATALOG_FILE
        if not files:
            raise ValueError(f"no PSL policies found in {directory}")
        if not catalog_path.exists():
            raise ValueError(f"missing PSL field catalogue {CATALOG_FILE} in {directory}")

        def key_for(issuer: str, key_id: str) -> Any:
            try:
                return keys.get(issuer, key_id, "policy_bundle")
            except Exception as exc:  # unknown issuer / key / purpose
                raise PolicySignatureError(f"untrusted policy signer {issuer}/{key_id}: {exc}") from exc

        for path in files + [catalog_path]:
            try:
                verify_file(path, key_for)
            except PolicySignatureError as exc:
                raise ValueError(str(exc)) from exc
        catalog = FieldCatalog.load(catalog_path)
        policy_set = compile_policy_set([(p.name, p.read_text(encoding="utf-8")) for p in files], catalog)
        versions: dict[str, str] = {}
        for vu_name, meta in policy_set.vunits.items():
            set_id, version = meta.get("policy_set"), meta.get("version")
            if not set_id or not version:
                raise ValueError(f"vunit {vu_name} ({meta.get('file')}) needs @policy_set and @version annotations")
            if versions.get(set_id, version) != version:
                raise ValueError(f"policy set {set_id} has conflicting versions")
            versions[set_id] = version
        if rollback_store is not None:
            rollback_store.check_and_record(versions)
        return cls(policy_set, versions, directory)
