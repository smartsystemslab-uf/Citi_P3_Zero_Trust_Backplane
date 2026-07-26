# Zero Trust Backplane — Task 4 PDP Prototype

This package implements the Task 4 deliverables even though Tasks 1-3 are not yet available:

- FastAPI PDP service (`POST /v1/authorize`)
- YAML policy engine using Subject + Resource + Action + Context
- Agent-, role-, resource-, workflow-, risk-, time-, and approval-aware matching
- Decisions: `ALLOW`, `DENY`, `MANUAL_REVIEW`, `ALLOW_WITH_OBLIGATIONS`, `REAUTHENTICATE`
- Data-masking and enhanced-logging obligations
- Default deny for unknown subjects, resources, actions, and unmatched requests
- JSONL decision audit log
- Front-, mid-, back-office, tool, and ledger policy bundles
- Unit tests for the M4 acceptance criteria

## 1. Run locally

```bash
cd zero_trust_pdp_task4
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\activate
pip install -e ".[test]"
uvicorn zt_backplane.pdp_service:app --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080/docs` for the generated API page.

## 2. Example authorization request

```bash
curl -X POST http://127.0.0.1:8080/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "fraud_agent",
    "resource": "transaction_history",
    "action": "read",
    "context": {
      "workflow": "fraud_review",
      "risk": "medium"
    }
  }'
```

Expected decision: `ALLOW_WITH_OBLIGATIONS`, including masking and logging obligations.

## 3. Run tests

```bash
pytest
```

The tests cover all stated M4 completion rules:

- fraud agent reads transaction history
- fraud agent cannot execute transfers
- report agent reads reconciliation results
- report agent cannot update ledger
- unknown agents denied
- undefined actions denied
- critical operations require manual review

## 4. Policy format

Policies are under `policy_store/`.

```yaml
- id: FO-FRAUD-READ-TRANSACTION-HISTORY
  priority: 200
  effect: ALLOW_WITH_OBLIGATIONS
  match:
    subjects: [fraud_agent]
    resources: [transaction_history]
    actions: [read]
    workflows: [fraud_review]
    risk_levels: [low, medium, high]
  obligations:
    - type: enhanced_logging
      parameters: {}
```

No Python expressions are evaluated. Unsupported match keys fail during policy loading.

## 5. Decision resolution

1. Unknown or disabled subject → `DENY`.
2. Unknown resource → `DENY`.
3. Action not defined for the resource → `DENY`.
4. Find matching policies.
5. Select the highest priority.
6. For policies tied at that priority: `DENY` > `REAUTHENTICATE` > `MANUAL_REVIEW` > `ALLOW_WITH_OBLIGATIONS` > `ALLOW`.
7. No matching policy → default `DENY`.

## 6. What is intentionally not included

Task 5 features are not faked here: no Permit Lease, authorization cache, expiration, replay defense, policy-version invalidation, or revocation service. Every response says `cache_control: NO_STORE`. The example PEP client fails closed when the PDP is unavailable.

## 7. Fill-in points

Read `INTEGRATION_GAPS.md` and `config/citi_interfaces.yaml`. Search the source for `TODO(CITI` to see every explicit integration placeholder.

## 8. Validate configuration references

```bash
python scripts/validate_configuration.py
```

This catches policies that refer to unknown local identities, resources, or actions before the PDP starts.
