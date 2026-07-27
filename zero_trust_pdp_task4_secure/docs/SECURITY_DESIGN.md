# Security design

## Authorization sequence

```text
Agent operation
    -> PEP authenticates workload
    -> PDP issues short-lived challenge nonce
    -> PEP builds canonical request and request_hash
    -> Risk/IdP/Workflow/Approval services issue signed assertions
    -> PEP signs the complete request
    -> PDP verifies identity, signatures, freshness, nonce and JTI
    -> PDP recalculates quantitative classifications
    -> Policy Engine evaluates only verified facts
    -> PDP signs the unchanged response body
    -> PEP verifies the decision signature
    -> PEP enforces obligations or blocks the operation
```

## Risk calculation boundary

The external risk service calculates the raw risk score. This PDP does not
replace Citi's fraud model. It validates that:

- the assertion came from a trusted issuer;
- the score is within 0-1000;
- the claimed level matches the configured threshold table;
- the assertion is fresh and versioned;
- the request context contains the same risk level.

Prototype thresholds are in `config/security_context.yaml`; Citi must replace
and approve them.

## Authentication-strength calculation

The identity service signs the observed authentication factors. The PDP uses the
versioned factor weights in `config/security_context.yaml` to derive an integer
strength. A caller cannot simply submit `auth_strength: 10`; a mismatch between
factors, signed strength, and context strength is denied.

## Copied-request defense

A legal request copied byte-for-byte still contains the same nonce and JTI.
The first successful verification consumes both values. A second attempt is
rejected as replay. Changing any parameter also changes `request_hash` and
invalidates the PEP signature and any approval bound to the original operation.

## Policy-engine compromise boundary

No software-only prototype can guarantee correctness after the entire PDP host
and its signing key are compromised. This design reduces that blast radius:

- PDP contains no banking-transfer or ledger-write credentials.
- Critical writes need a separate approval issuer and a separate secondary
  authorizer.
- PEP verifies a PDP decision signature.
- Resource-side idempotency and independent audit are mandatory obligations.
- Policy bundles require an external release-authority signature.

For production, the secondary authorizer, policy authority, PDP decision key,
and audit sink must be in independent administrative and compromise domains.
