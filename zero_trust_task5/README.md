# Zero Trust Backplane — Task 5

This package implements **Permit Lease, cache safety, revocation, request binding, replay protection, and PDP timeout handling** for the Citi Zero Trust Backplane.

It is designed to work with:

- **Task 3 generated PEPs** through `Task3PEPAdapter` and `augment_generated_pep_plan()`.
- **Task 4 PDP / Policy Engine** through `Task4DecisionAdapter` and a pluggable signed-decision verifier.
- **Unified Interface v1.0** through `UnifiedAuthorizationRequest`, stable canonical IDs, and a deterministic protected-operation hash.

## Runtime flow

```text
Task 3 PEP intercepts operation
        |
        v
UnifiedAuthorizationRequest (interface v1.0)
        |
        v
Task 4 signed decision verification
        |
        v
Task 5 issues signed, sender-constrained Permit Lease
        |
        v
Task 3 PEP validates lease + context + PoP + revocation + use count
        |
        +---- valid ------------------------> execute operation
        |
        +---- invalid / no valid fallback --> fail closed
```

On a PDP timeout, Task 5 accepts only a cached Permit Lease that is:

- unexpired;
- signed by a trusted Task 5 key;
- bound to the same subject, resource, action, parameters, workflow, audience, and endpoint;
- bound to the same PEP public-key thumbprint;
- still current for policy, identity, risk, signing-key, and revocation epochs;
- within its bounded use count;
- bound to the same signed context assertions.

A plain cached value such as `allow = true` is never stored or accepted.

## Main modules

| Module | Purpose |
|---|---|
| `models.py` | Unified request, Task 4 decision, Permit Lease, and PoP models |
| `request_hash.py` | Deterministic operation canonicalization and SHA-256 binding |
| `task4_adapter.py` | Task 4 response aliases, header signature verification, callback bridge |
| `permit_lease.py` | Ed25519 Permit Lease issuance, decoding, and validation |
| `lease_cache.py` | Local PEP cache with restart clearing and recovery lockout |
| `revocation_service.py` | Permit, decision, subject, session, workflow, policy, issuer, and key revocation |
| `proof_of_possession.py` | Sender-constrained Permit Lease proof |
| `pdp_timeout_state_machine.py` | `NO_DECISION -> WAITING_FOR_PDP -> ACTIVE_LEASE / DENIED` |
| `task3_adapter.py` | Runtime adapter/decorator for generated PEPs and plan augmentation |
| `idempotency_guard.py` | Independent duplicate prevention for critical financial writes |
| `key_rotation.py` | Permit signing-key rotation, overlap, and revocation |
| `audit.py` | Hash-chained authorization audit records |
| `fastapi_router.py` | Optional issue/validate HTTP endpoints |

## Install and test

```bash
python -m pip install -e ".[test]"
pytest
python examples/demo_integration.py
```

## Task 4 integration

The default verifier expects the existing Task 4 decision proof in headers:

```text
X-ZT-Decision-Key-Id
X-ZT-Decision-Signature
X-ZT-Request-Hash
X-ZT-Policy-Version
X-ZT-Decision-Id
```

Use the native verifier:

```python
from zt_task5.key_rotation import Ed25519KeyRing
from zt_task5.task4_adapter import HeaderEd25519DecisionVerifier

trust_store = Ed25519KeyRing()
trust_store.add_public_key("task4-decision-key-v1", task4_public_key)
verifier = HeaderEd25519DecisionVerifier(trust_store)
```

If the current Task 4 package already exposes `decision_permit_verifier`, keep it unchanged and bridge it:

```python
from zt_task5.task4_adapter import CallbackDecisionVerifier

verifier = CallbackDecisionVerifier(existing_task4_verify_callback)
```

The callback receives `(envelope, normalized_decision, unified_request)` and should return `True`/`None` on success or raise/reject on failure.

## Task 3 integration

A generated PEP can use one shared adapter without changing business logic:

```python
from zt_task5.task3_adapter import Task3PEPAdapter

pep = Task3PEPAdapter(
    components.state_machine,
    call_task4_pdp,
    pep_identity="pep://task3/generated/tool-pep-transfer",
    pep_private_key=pep_private_key,
    idempotency_guard=components.idempotency_guard,
)

result = pep.execute(unified_request, lambda: execute_transfer(**params))
```

To add Task 5 settings to Task 3's `generated_pep_plan.json`:

```bash
python tools/augment_task3_pep_plan.py \
  examples/task3_generated_pep_plan.json \
  generated_pep_plan_task5.json
```

This preserves `pep_id`, `resource_id`, and `action_id` and adds:

- `permit_required`;
- `sender_constraint_required`;
- `request_hash_required`;
- critical-operation `max_uses = 1`;
- `VALID_MATCHING_LEASE_ONLY` PDP-timeout behavior;
- fail-closed and restart-cache-clearing behavior.

## Unified Interface compatibility

Task 5 accepts canonical names and common aliases:

| Canonical | Accepted aliases |
|---|---|
| `subject` | `subject_id`, `caller` |
| `resource` | `resource_id`, `target` |
| `action` | `operation` |
| `parameters` | `params`, `input` |
| `workflow_id` | `context.workflow_id`, `workflow_instance`, `workflow` |
| `evidence` | `context.evidence`, `context.assertions` |

The operation hash deliberately excludes volatile request IDs and signed evidence contents. Evidence is separately and strictly bound through `context_bindings`. This permits a legitimate bounded retry while still rejecting modified operations or substituted context.

See `config/task5_interface_extension.schema.json` and `INTEGRATION_GUIDE.md`.

## Security behavior

- Critical operations always use single-use leases.
- Critical operations require an idempotency key at execution.
- A PEP restart clears the local cache and disables timeout fallback until a fresh verified PDP response re-synchronizes it.
- Any revocation epoch change conservatively invalidates older cached leases.
- Unknown errors fail closed.
- A stolen token is unusable without the private key of the PEP to which it was issued.
- Clock rollback beyond the configured tolerance is rejected.

## Prototype boundary

The included replay, revocation, lease, and idempotency stores are thread-safe in-memory prototype stores. A distributed deployment should replace them with a strongly consistent shared backend while retaining the same interfaces and validation order.
