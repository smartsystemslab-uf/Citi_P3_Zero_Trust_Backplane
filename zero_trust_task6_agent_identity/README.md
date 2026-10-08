# Agent identity bootstrap and public key registry

AUTHN-1 generates per-agent Ed25519 keys. AUTHN-2 publishes their public keys in
a root-signed YAML registry and provides verified, fail-closed lookup for AUTHN-3.
This module does not yet sign agent requests or enforce authentication at the
gateway. The existing `zero_trust_task2/` folder is the architecture scanner,
not AUTHN-2.

## Setup and trust anchor

Use Python 3.10 or later. From this module directory:

```powershell
python -m pip install -e '.[test]'
```

Provision a dedicated Ed25519 root outside the repository using your environment's
key-management process. The signing root must be an unencrypted PEM PKCS8 private
key. Verifiers receive its PEM SubjectPublicKeyInfo public key and expected key
ID independently. Protect the root private key with filesystem permissions or
an equivalent platform access-control policy. Never commit it or use the checked-in
Backplane development keys as a production registry root.

The loader pins the configured public key in memory and requires the signed root
key ID to match the configured ID. A registry cannot supply or replace its own
trust anchor. Changing that anchor requires constructing a new registry instance.

## Bootstrap and incremental registration

The original unsigned bootstrap remains compatible:

```powershell
python bootstrap_agent_keys.py --manifest discovered-agents.yaml
```

Its `public_keys.yaml` is an interchange export only. `PublicKeyRegistry` rejects
it because it is not a signed authentication registry. Private agent keys remain
raw 32-byte Ed25519 keys encoded with standard Base64 in `keys/<agent_id>.key`.

Publish a signed registry as part of the real bootstrap flow:

```powershell
python bootstrap_agent_keys.py --manifest discovered-agents.yaml `
  --registry registry.yaml `
  --registry-root-private-key C:\secure\registry-root-private.pem `
  --registry-root-key-id registry-root-v1
```

All three registry flags are required together. The CLI checks the root, existing
registry integrity, output path collisions, and registered identities before
creating keys. `--force` does not permit replacing a registered identity. For
newly discovered agents, pass a manifest containing only those new identities;
their keys are added to the verified registry without altering prior records.

AUTHN-1's unchanged `bootstrap_agent_keys(...)` returns `{agent_id: public_key_b64}`.
Programmatic callers pass that actual mapping to:

```python
from datetime import datetime, timezone
from pathlib import Path
from zt_task6.registry import write_signed_registry

write_signed_registry(
    generated_public_keys,
    Path("registry.yaml"),
    root_private_key_path=Path("C:/secure/registry-root-private.pem"),
    root_key_id="registry-root-v1",
    valid_from=datetime.now(timezone.utc),
)
```

The writer validates the complete update and verifies the existing registry with
the public half of the configured signing root. It preserves unrelated identities
and all existing key metadata. Re-registering the same key is a no-op, including
when it is revoked or expired; it cannot reactivate the key. A different key for
an existing identity is rejected and reserved for AUTHN-4's future rotation flow.

Registry publication uses a flushed temporary file and atomic replacement in the
destination directory. Serialize concurrent writers externally; there is no
cross-process update lock. A publication failure exits nonzero and never reports
successful registration. Agent keys and the unsigned export may already have
been generated when publication fails. They are not trusted until registered;
retain those keys and retry `write_signed_registry` with the saved public-key
mapping rather than regenerating them blindly.

## AUTHN-3 lookup contract

```python
from pathlib import Path
from zt_task6.registry import PublicKeyRegistry

registry = PublicKeyRegistry.from_yaml(
    Path("registry.yaml"),
    root_public_key_path=Path("C:/secure/registry-root-public.pem"),
    expected_root_key_id="registry-root-v1",
)
records = registry.lookup("aml_investigator", key_id=request_key_id)
for record in records:
    public_key = record.as_public_key()
    # AUTHN-3 uses public_key.verify(signature, canonical_request_bytes).
```

`lookup(identity, key_id=None, at=None)` returns a tuple of immutable
`AgentKeyRecord` objects containing `key_id`, Base64 `public_key`, `status`,
and timezone-aware `valid_from` / optional `valid_until` datetimes. Omit `key_id`
to retrieve every eligible key, including future rotation overlap keys. Consumers
must not choose a default key when none match.

Identities match exactly. Unknown identities and unknown key IDs return `()`.
Revoked, not-yet-valid, and expired keys are excluded. Validity starts inclusively
and ends exclusively. `at` defaults to current UTC; supplied naive datetimes are
rejected. AUTHN-3 should use this exact production lookup interface before asking
the PDP for authorization; request signing, nonce checks, and integration remain
AUTHN-3's responsibility.

Call `registry.reload()` explicitly to read newly published keys. There is no
automatic polling or immediate cross-process revocation. Reload verifies a full
replacement snapshot before publishing it. Any reload failure invalidates the
previous snapshot; subsequent lookup raises `RegistryIntegrityError` until a
valid reload succeeds. Handle that exception by denying authentication, never by
falling back to unsigned exports or asserted agent identity strings.

`RegistryError` reports invalid schema, registration, or configuration;
`RegistryIntegrityError` (a subclass) reports trust-anchor mismatch, invalid
root signatures, or unavailable verified state. Filesystem failures propagate
as `OSError`. No successful lookup is possible before validation and verification.

## Signed envelope schema version 1

```yaml
payload:
  schema_version: 1
  signing_key_id: registry-root-v1
  identities:
    aml_investigator:
      - key_id: "<SHA-256 hex digest of raw public-key bytes>"
        public_key: "<standard Base64 of 32 raw Ed25519 public-key bytes>"
        status: active
        valid_from: "2026-10-08T00:00:00Z"
        valid_until: null
signature: "<standard Base64 of 64-byte Ed25519 root signature>"
```

This example uses placeholders and is not loadable. Each identity has a nonempty
list of records. Status is `active` or `revoked`; rotation and revocation commands
are intentionally absent. UTC timestamp strings accept `Z` or `+00:00` with up
to six fractional-second digits. Null `valid_until` means no scheduled expiration.

All envelope, payload, and record fields are required; additional fields,
duplicate YAML keys, duplicate key IDs per identity, invalid Base64, inconsistent
key IDs, invalid time ranges, and unsupported schema versions are rejected.
Private-key fields are never allowed.

The complete payload, including its signing key ID, is signed as UTF-8 JSON with
sorted keys, compact separators, `ensure_ascii=False`, and `allow_nan=False`.
Unsupported objects are not converted to strings. Writer and verifier share
`canonical_payload`; YAML whitespace and field ordering are not signed.

Signing detects unauthorized modification. It does **not** prevent replay of an
older, validly signed registry; monotonic versions or an external freshness
mechanism would be a separate addition. Root provisioning and concurrent writer
coordination are environment responsibilities.

Default agent keys, `public_keys.yaml`, `registry.yaml`, temporary publication
files, and test coverage outputs are ignored. If you choose other environment
paths, keep them outside tracked source or explicitly ignore them.

## Tests

From this directory:

```powershell
python -m pytest tests integration_tests -q
```

Tests use throwaway roots and agent keys in temporary directories. They exercise
real cryptographic verification, the production lookup, reload behavior, atomic
failure handling, the AUTHN-1 function chain, and the actual CLI subprocess.
No remote services or production credentials are used. AUTHN-1's existing POSIX
mode test is skipped on Windows because POSIX permission bits are not enforced.

To include CLI subprocesses in coverage:

```powershell
$env:AUTHN2_COVERAGE = '1'
python -m coverage run --parallel-mode --source=zt_task6,bootstrap_agent_keys -m pytest tests integration_tests -q
python -m coverage combine
python -m coverage report -m
Remove-Item Env:AUTHN2_COVERAGE
```

The subprocess flag changes only test instrumentation. A fresh coverage run
should use a clean coverage data directory so prior runs do not inflate results.
