# Integrated Zero Trust Backplane Demo — Tasks 1–6 + Real Multi-Agent Testbed

This runner connects Tasks 1–6 into one executable pipeline. Task 6 runs three representative workflows against the original multi-agent testbed tools/repository/backend while generated PEPs, the signed PDP, Permit Leases, obligations, direct-bypass guards, and audit tracing remain active.

## Pipeline

```text
Task 1 system model / Unified Interface
    -> Task 2 source scanner
    -> runtime reconciliation
    -> real scanner-graph merge
    -> Task 3 logical/physical PEP generation
    -> Task 4 signed PDP + staged runtime policy bundle
    -> Task 5 Permit Lease / cache safety / revocation
    -> Task 6 real representative workflows
```

## Requirements

Use Python 3.11+ and install the Backplane packages from the repository root:

```powershell
python -m pip install -e interface_standard -e Zero_Trust_Task3_PEP_Integrated/zero_trust_pep_task3_integrated -e zero_trust_pdp_task4_secure -e zero_trust_task5
```

## Task 6 — Full real-testbed integration

Run the three M6 workflows using the original testbed repository/tool implementations:

```powershell
python integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --task6-real-workflows
```

The three representative workflows are:

```text
1. Customer transaction
   customer-service workflow -> transaction_processing_agent -> execute_transfer

2. Fraud and compliance
   transaction monitoring -> fraud detection -> compliance -> decision path

3. Back-office EOD
   validation -> EOD processing -> ledger update -> reconciliation -> report/exception
```

Inputs are in:

```text
integrated_demo/task6_workflows.yaml
```

### Use the live FastAPI backend for the customer-transfer path

Start the backend first:

```powershell
cd D:\Lab\Citi_P3\citi_banking_backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Then run:

```powershell
cd D:\Lab\Citi_P3_Zero_Trust_Backplane
.\.venv\Scripts\Activate.ps1

python integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --task6-real-workflows `
  --task6-external-backend
```

Without `--task6-external-backend`, Task 6 still executes the original Citi P3 tool/repository implementation locally. This keeps M6 deterministic and repeatable for later Task 7 benchmarking.

## M6 features exercised

Task 6 verifies:

- unique workload identities for workflow agents;
- generated agent-route and tool PEPs;
- signed PDP decisions;
- Permit Lease validation;
- human approval / secondary authorization for critical writes;
- idempotency and change-ticket obligations;
- authorized workflow completion;
- unauthorized transfer blocking;
- unauthorized ledger-update blocking;
- shadow-mode `would_block` behavior on a safe read;
- direct protected-tool bypass blocking;
- one end-to-end `trace_id` correlated into Task 4 PDP audit;
- M6 audit-record completeness.

The Task 6 runtime policy bundle is generated from the discovered Task 3 placements and staged only under `integrated_demo/output/task4_policy_store/`. It uses lower priority than the hand-authored Task 4 policies, so existing DENY, masking, MANUAL_REVIEW, and other obligations continue to take precedence.

## Expected result

A successful M6 run ends with output similar to:

```text
Task 6 workload identities: PASS
customer_transaction: PASS
fraud_compliance: PASS
back_office_eod: PASS
Task 6 security check unauthorized_transfer_blocked: PASS
Task 6 security check unauthorized_ledger_update_blocked: PASS
Task 6 security check shadow_mode_would_block_but_safe_read_continues: PASS
Task 6 security check direct_protected_tool_bypass_blocked: PASS
Task 6 audit completeness: PASS
Task 6 end-to-end trace correlation: PASS

ALL TASKS 1-6 INTEGRATED: PASS
```

## Task 6 output artifacts

```text
integrated_demo/output/
├── task2/
├── task3_generated/
├── task4_decision_log.jsonl
├── task4_policy_store/
│   └── task6_real_workflows.yaml (+ signed sidecar)
├── task5_audit.json
├── task6/
│   ├── task6_report.json
│   └── task6_workflow_audit.jsonl
└── demo_summary.json
```

Each protected Task 6 operation records the M6 fields:

```text
trace_id
workflow_id
workflow_instance_id
caller_identity
target_resource
requested_action
PEP id
PDP decision
policy version
permit id
execution result
authorization latency
step latency
```

The latency fields are included now so the same harness can be reused by Task 7 for p50/p95/p99 overhead and throughput evaluation.

## Existing modes

Basic Task 1–5 self-test:

```powershell
python integrated_demo/run_demo.py --clean
```

Real scanner graph:

```powershell
python integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --scanner-graph
```

Legacy individual real-tool checks:

```powershell
python integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --scanner-graph `
  --execute-real-tools
```

Legacy standalone real writes require the backend and use `--execute-real-writes`.
