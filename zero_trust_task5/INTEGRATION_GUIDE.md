# Task 3 + Task 4 + Task 5 Integration Guide

## 1. Keep the unified interface as the source of truth

Continue using the stable IDs produced by the unified interface:

- subject / agent ID;
- resource ID;
- action ID;
- workflow ID;
- PEP ID;
- audience and protected endpoint.

Environment-specific Citi names, URLs, functions, and credentials remain in the existing overlay. Task 5 never rewrites stable IDs.

## 2. Task 3 output

Run the Task 3 placement engine normally. Then augment its JSON plan:

```bash
python tools/augment_task3_pep_plan.py generated_pep_plan.json generated_pep_plan_task5.json
```

The generated PEP middleware should instantiate one `Task3PEPAdapter` per physical PEP identity. Multiple logical placements may share it when Task 3 already deduplicates them into the same middleware or sidecar.

## 3. Task 4 input and response

Send Task 4 the same `UnifiedAuthorizationRequest` or its existing equivalent. The required Task 4 response fields are:

```json
{
  "interface_version": "1.0",
  "decision_id": "...",
  "decision": "ALLOW",
  "subject": "transaction_agent",
  "resource": "banking_api.transfer",
  "action": "execute",
  "workflow_id": "wf-transfer-001",
  "request_hash": "sha256:...",
  "policy_version": "policy-v1",
  "identity_version": "identity-v1",
  "risk_version": "risk-v1",
  "obligations": [],
  "context_bindings": [],
  "issued_at": "...",
  "expires_at": "...",
  "nonce": "...",
  "jti": "...",
  "decision_key_id": "task4-decision-key-v1"
}
```

The existing signed decision can remain in HTTP headers. Task 5 verifies the signature before issuing a Permit Lease.

## 4. Permit Lease issuance

For an allowed Task 4 decision, Task 5:

1. verifies the signed Task 4 response;
2. checks exact operation binding;
3. checks policy, identity, and risk versions;
4. consumes the Task 4 decision ID/JTI/nonce so the same decision cannot mint multiple leases;
5. issues an Ed25519-signed Permit Lease;
6. binds it to the Task 3 PEP identity and public-key thumbprint;
7. stores only the signed lease in the local cache.

## 5. Runtime enforcement

Before executing the intercepted function, API, MCP tool, or data operation, Task 3 calls `Task3PEPAdapter.execute()`.

The validation order is:

1. Permit signature and signing key;
2. trusted time and expiration;
3. operation request hash;
4. subject/resource/action/workflow/audience/endpoint binding;
5. revocation epoch and scoped revocations;
6. context assertion hashes and issuers;
7. sender proof of possession;
8. bounded use count;
9. financial idempotency reservation;
10. business operation execution and idempotency commit.

## 6. PDP delay behavior

```text
NO_DECISION
    |
WAITING_FOR_PDP
    |-- signed ALLOW --> issue and validate lease --> ACTIVE_LEASE
    |-- DENY --------------------------------------> DENIED
    `-- TIMEOUT
          |-- exact valid cached lease ------------> ACTIVE_LEASE
          `-- no valid cached lease ---------------> DENIED
```

A critical lease is consumed on its first execution, so it cannot later be reused during a PDP outage.

## 7. Revocation and version updates

Call the appropriate `RevocationService` method when an external control-plane event arrives:

```python
components.revocations.revoke_subject("transaction_agent")
components.revocations.revoke_workflow("wf-transfer-001")
components.revocations.set_policy_version("policy-v2")
components.revocations.set_identity_version("transaction_agent", "identity-v2")
components.revocations.set_risk_version("transaction_agent", "risk-v2")
components.revocations.revoke_signing_key("task5-permit-key-v1")
components.revocations.revoke_context_issuer("risk-service")
```

Every change increments the revocation epoch. Old local leases fail closed.

## 8. PEP restart

On a generated PEP process restart:

```python
components.lease_cache.restart()
```

This clears all local leases and sets `recovery_required=True`. Timeout fallback remains disabled until a new signed Task 4 response succeeds; the state machine then calls `mark_synchronized()` automatically.

## 9. FastAPI integration

For a service deployment:

```python
from fastapi import FastAPI
from zt_task5.fastapi_router import build_task5_router

app = FastAPI()
app.include_router(
    build_task5_router(
        components.issuer,
        components.validator,
        task4_verifier,
    )
)
```

Endpoints:

- `POST /zt/v1/task5/permit-leases/issue`
- `POST /zt/v1/task5/permit-leases/validate`

## 10. Replacement points for deployment

Replace these in-memory prototype components without changing callers:

- `ReplayCache` -> Redis/transactional database with atomic consume;
- `RevocationService` -> control-plane epoch and revocation feed;
- `LeaseCache` -> local encrypted cache or no persistent cache;
- `IdempotencyGuard` -> banking API/ledger idempotency table;
- `HashChainedAuditLog` -> independent append-only audit/SIEM sink;
- `Ed25519KeyRing` -> KMS/HSM-backed signing and verification.
