# Task 6 — Full Real-Testbed Integration

Implemented the Work Plan M6 representative workflow integration without modifying the Citi P3 business source files.

## Representative workflows

1. Customer transaction: customer-service route -> transaction processing -> original `execute_transfer`.
2. Fraud/compliance: monitoring -> fraud -> compliance -> decision route, using original transaction/customer/policy tools.
3. Back-office EOD: validation -> processing -> ledger update -> reconciliation -> original report/exception branch.

## Runtime features

- Unique workload-identity validation for participating workflow agents.
- Generated Task 3 agent-route/tool PEP selection by runtime identity, not hard-coded edge count.
- Signed Task 4 PDP decisions and a staged, signed M6 policy bundle.
- Task 5 Permit Lease enforcement and existing obligations preserved.
- Critical writes require signed human approval + independent authorization; ledger change-ticket and idempotency obligations are preserved.
- Enforcement-mode unauthorized transfer and ledger-update tests.
- Safe shadow-mode `would_block` test.
- Runtime direct protected-tool bypass guard.
- End-to-end Task 6 `trace_id` propagated into the signed Task 4 request and correlated with PDP audit.
- Task 6 JSONL audit with the M6 fields plus authorization/step latency for later Task 7 evaluation.

## Validation performed

- `integrated_demo/tests/test_task6_workflows.py` + existing bridge contract: 5 passed.
- Full integration against the uploaded Citi P3 source checkout:
  - customer_transaction: PASS
  - fraud_compliance: PASS
  - back_office_eod: PASS
  - unauthorized_transfer_blocked: PASS
  - unauthorized_ledger_update_blocked: PASS
  - shadow_mode_would_block_but_safe_read_continues: PASS
  - direct_protected_tool_bypass_blocked: PASS
  - audit completeness: PASS
  - end-to-end trace correlation: PASS
  - `ALL TASKS 1-6 INTEGRATED: PASS`

The uploaded Citi P3 checkout available in the test environment produced 82 scanner edges. The Task 6 implementation does not depend on 82 or fixed placement IDs; it resolves placements by runtime subject/tool/route identities, so it is intended to work with the user's current 95-edge checkout as well.
