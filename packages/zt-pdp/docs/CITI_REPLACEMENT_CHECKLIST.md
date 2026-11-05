# Citi replacement checklist

The interface standard remains unchanged. Replace only adapters, bindings,
thresholds, issuers, and deployment components.

## Required before Citi integration

- [ ] Replace `security/dev_keys` with Citi PKI/KMS/HSM or JWKS trust sources.
- [ ] Bind canonical agent IDs to actual Citi workload identities.
- [ ] Terminate and validate mTLS/SPIFFE or Citi workload tokens at the PDP edge.
- [ ] Connect Citi risk-engine assertion format and approved score thresholds.
- [ ] Connect Citi authentication factors and approved strength mapping.
- [ ] Connect the Citi workflow orchestrator and signed workflow-step evidence.
- [ ] Connect the human approval service with approver roles and request binding.
- [ ] Deploy an independent secondary authorizer for critical writes.
- [ ] Replace in-memory nonce/JTI state with a shared atomic replay store.
- [ ] Move policy signing to the approved release pipeline.
- [ ] Move PDP decision signing into KMS/HSM and establish key rotation.
- [ ] Mirror PDP, PEP, workflow, approval, and resource logs to independent audit.
- [ ] Enforce idempotency at actual transfer and ledger APIs.
- [ ] Confirm time synchronization, maximum skew, and clock-failure handling.
- [ ] Confirm canonical request normalization for each real MCP/API schema.

Use `config/security_bindings.template.yaml` to record these answers without
changing the common interface schema.
