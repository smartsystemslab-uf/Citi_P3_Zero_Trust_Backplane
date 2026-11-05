# Integrated Zero Trust Backplane Demo — the components + Real Multi-Agent Testbed

This runner connects the components into one executable pipeline. The real-workflow run executes three representative workflows against the original multi-agent testbed tools/repository/backend while generated PEPs, the signed PDP, Permit Leases, obligations, direct-bypass guards, and audit tracing remain active.

## Pipeline

```text
Unified Interface system model / Unified Interface
    -> static scanner source scanner
    -> runtime reconciliation
    -> real scanner-graph merge
    -> PEP generator logical/physical PEP generation
    -> PDP signed PDP + staged runtime policy bundle
    -> Permit Lease / cache safety / revocation
    -> real-workflow real representative workflows
```

## Requirements

Use Python 3.11+ and install the Backplane packages from the repository root:

```powershell
python -m pip install -e packages/zt-interface -e packages/zt-pep -e packages/zt-pdp -e packages/zt-lease
```

## real-workflow — Full real-testbed integration

Run the three M6 workflows using the original testbed repository/tool implementations:

```powershell
python legacy/citi_p3/integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --workflow-real-workflows
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
legacy/citi_p3/integrated_demo/workflows.yaml
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

python legacy/citi_p3/integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --workflow-real-workflows `
  --workflow-external-backend
```

Without `--workflow-external-backend`, the real-workflow run still executes the original Citi P3 tool/repository implementation locally. This keeps M6 deterministic and repeatable for later benchmarking.

## M6 features exercised

The real-workflow run verifies:

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
- one end-to-end `trace_id` correlated into PDP audit;
- M6 audit-record completeness.

The real-workflow runtime policy bundle is generated from the discovered PEP generator placements and staged only under `legacy/citi_p3/integrated_demo/output/pdp_policy_store/`. It uses lower priority than the hand-authored PDP policies, so existing DENY, masking, MANUAL_REVIEW, and other obligations continue to take precedence.

## Expected result

A successful M6 run ends with output similar to:

```text
Real workflows: workload identities: PASS
customer_transaction: PASS
fraud_compliance: PASS
back_office_eod: PASS
Real workflows: security check unauthorized_transfer_blocked: PASS
Real workflows: security check unauthorized_ledger_update_blocked: PASS
Real workflows: security check shadow_mode_would_block_but_safe_read_continues: PASS
Real workflows: security check direct_protected_tool_bypass_blocked: PASS
Real workflows: audit completeness: PASS
Real workflows: end-to-end trace correlation: PASS

ALL COMPONENTS AND REAL WORKFLOWS INTEGRATED: PASS
```

## Real-workflow output artifacts

```text
legacy/citi_p3/integrated_demo/output/
├── scanner/
├── pep_generated/
├── pdp_decision_log.jsonl
├── pdp_policy_store/
│   └── real_workflows.yaml (+ signed sidecar)
├── lease_audit.json
├── workflow/
│   ├── workflow_report.json
│   └── workflow_audit.jsonl
└── demo_summary.json
```

Each protected real-workflow operation records the M6 fields:

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

The latency fields are included now so the same harness can be reused by the evaluation for p50/p95/p99 overhead and throughput evaluation.

## Existing modes

Basic Unified Interface–5 self-test:

```powershell
python legacy/citi_p3/integrated_demo/run_demo.py --clean
```

Real scanner graph:

```powershell
python legacy/citi_p3/integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --scanner-graph
```

Legacy individual real-tool checks:

```powershell
python legacy/citi_p3/integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --scanner-graph `
  --execute-real-tools
```

Legacy standalone real writes require the backend and use `--execute-real-writes`.
