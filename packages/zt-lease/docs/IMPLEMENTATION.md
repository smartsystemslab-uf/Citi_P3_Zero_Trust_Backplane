# Permit Lease Implementation Report

## Completed deliverables

- `permit_lease.py`: short-lived Ed25519-signed Permit Lease issuance and verification.
- `lease_cache.py`: exact-request, sender-bound local lease cache with restart clearing.
- `request_hash.py`: canonical protected-operation hash.
- `revocation_service.py`: decision, permit, identity, session, workflow, policy, key, issuer, assertion, PEP-key, and idempotency revocation.
- `pdp_timeout_state_machine.py`: required timeout state transitions and fail-closed behavior.
- Policy-version, identity-version, risk-version, signing-key, and revocation-epoch checks.
- `nonce_service.py`, `replay_cache.py`, `proof_of_possession.py`, `sender_constraint.py`, `context_binding.py`, `idempotency_guard.py`, `key_rotation.py`, and trusted-clock rollback detection.
- PEP runtime adapter and generated-plan augmentation.
- PDP signed-decision adapter, native Ed25519 header verifier, and callback bridge for an existing verifier.
- Unified Interface v1.0 normalization and JSON Schema extension.
- Hash-chained audit records.
- Runnable integration demonstration and automated security tests.

## Tested milestone criteria

| Requirement | Result |
|---|---|
| Expired permit rejected | PASS |
| Single-use permit replay rejected | PASS |
| Modified request rejected | PASS |
| Old policy version rejected | PASS |
| Revoked identity rejected | PASS |
| Different workflow rejected | PASS |
| Critical operation without valid timeout fallback rejected | PASS |
| Cached authorization after PEP restart rejected | PASS |
| Valid exact cached lease during PDP timeout accepted | PASS |
| Permit used by different sender key rejected | PASS |
| Context assertion substitution rejected | PASS |
| Duplicate critical financial execution rejected | PASS |
| Tampered PDP signed decision rejected | PASS |
| Audit hash chain verification | PASS |
| The PEP generator stable IDs retained during augmentation | PASS |

## Compatibility approach

The implementation does not require PEP generator or PDP to import Permit Lease internals. It uses adapters at their existing boundary:

- PEP generator emits/constructs the unified authorization request and invokes `GeneratedPepAdapter`.
- PDP keeps its current decision endpoint and signed headers.
- Permit Lease normalizes common aliases, verifies the PDP proof, and returns a Permit Lease for PEP generator enforcement.
- Stable canonical IDs remain unchanged and deployment overlays remain outside the security contract.
