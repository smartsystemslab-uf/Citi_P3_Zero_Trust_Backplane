# Zero Trust Backplane Task 4 — Security-Hardened PDP

This is a complete rewrite of Task 4. It keeps the previously approved Zero
Trust Backplane interface standard at **schema version 1.0** and hardens the
PDP/Policy Engine against forged context, copied requests, policy tampering, and
unsigned decisions.

## What is implemented

1. **Unchanged PDP contract**
   - Request and response JSON Schemas are byte-for-byte unchanged.
   - Canonical IDs and runtime bindings come from the existing interface package.

2. **Verified request identity**
   - The runtime subject must match the canonical subject binding.
   - A trusted PEP signs the complete request.
   - The signature binds identity, resource, action, context evidence,
     parameters, and `request_hash`.

3. **Replay protection**
   - PDP issues a short-lived nonce at `POST /v1/challenge`.
   - Every request contains a unique JTI.
   - Nonce and JTI are atomically consumed by the prototype replay guard.
   - An exact copied request is denied on its second use.

4. **Trusted quantitative context**
   - Risk score is signed by the risk service; PDP recalculates its risk level
     from versioned thresholds.
   - Authentication factors are signed by the identity provider; PDP calculates
     `auth_strength` from configured factor weights.
   - Workflow identity and instance are signed by the orchestrator.
   - Human approval and secondary authorization are signed, short-lived, and
     bound to the exact request hash.
   - Time policies use PDP server time, not the caller-provided event timestamp.

5. **Signed policy bundles**
   - Policy files comply with `policy_bundle.schema.json`.
   - Every bundle has an Ed25519 signature sidecar.
   - Tampering, missing signatures, invalid signatures, and version rollback are
     rejected before the PDP starts or reloads.

6. **Signed PDP decisions**
   - Response JSON remains unchanged.
   - Decision digest and Ed25519 signature are returned in HTTP headers.
   - The PEP client verifies the signature before enforcing an allow decision.

7. **Critical-operation safety**
   - Critical writes cannot be allowed by policy alone.
   - Ledger updates and transfers require both signed human approval and a
     signed independent authorization bound to the same operation.
   - Obligations include idempotency, enhanced logging, and independent audit.

8. **Tamper-evident audit log**
   - Audit events use the unchanged audit-event schema.
   - Records include a hash chain in `details`.
   - Production still requires an independent Citi-controlled append-only sink.

## Interface compatibility

The security rewrite does not add fields to the PDP request or response schema.
It uses existing extension locations:

```text
subject.identity_evidence  -> signed request proof, nonce, JTI
context.risk_evidence      -> signed risk score and version
context.auth_evidence      -> signed authentication factors
context.workflow_evidence  -> signed workflow state
context.human_approval     -> request-bound signed approval
context.secondary_authorization -> independent signed authorization
request_hash               -> canonical operation binding
HTTP response headers      -> signed PDP decision proof
```

See `interface_contract/UNCHANGED_INTERFACE.md` and
`interface_contract/SCHEMA_SHA256.json`.

## Run

```bash
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\Scripts\activate

pip install -e ".[test]"
PYTHONPATH=src python scripts/validate_configuration.py
pytest
uvicorn zt_backplane.pdp_service:app --host 127.0.0.1 --port 8080
```

In another terminal:

```bash
PYTHONPATH=src python examples/authorize_demo.py
```

Swagger UI:

```text
http://127.0.0.1:8080/docs
```

## Main endpoints

```text
GET  /health
POST /v1/challenge
POST /v1/authorize
POST /v1/admin/reload   (disabled by default)
```

## Tests

The test suite covers:

- interface-schema compatibility;
- fraud/report/ledger policy requirements;
- unknown subjects and undefined actions;
- exact-request replay;
- modified parameters after signing;
- forged approval evidence;
- recalculation of risk level and authentication strength;
- trusted server-time policy evaluation;
- policy tampering and rollback;
- signed response validation;
- audit hash-chain validation.

Current result:

```text
23 passed
```

## Important prototype limits

- The private keys in `security/dev_keys` are development-only and distributed
  with the source. They must never be used with Citi data.
- Replay state is in memory and works only for one PDP process. Citi integration
  needs a shared atomic store.
- The code verifies a PEP signature but does not terminate real mTLS or SPIFFE in
  this local prototype.
- The independent authorization service is represented by signed evidence; a
  physically separate Citi service must supply it in production.
- The audit file is local. Citi must mirror events to an independent append-only
  audit system.
- Permit Lease and safe cached authorization remain Task 5. All Task 4 decisions
  return `cache_control: NO_STORE`.
