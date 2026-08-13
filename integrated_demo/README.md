# Integrated Zero Trust Backplane Demo — Tasks 1–5 + Real Citi Testbed

This runner connects the currently implemented Zero Trust Backplane modules into one executable pipeline and can optionally protect the original Citi Front Office, Mid Office, and Back Office tools.

For the complete architecture, design rationale, sensitivity rules, troubleshooting guide, and repository-wide instructions, see the repository root `README.md`.

---

## Pipeline

```text
Task 1 system model / Unified Interface
    -> Task 2 source scanner
    -> runtime reconciliation
    -> optional real scanner-graph merge
    -> Task 3 PEP generation
    -> Task 4 signed PDP
    -> Task 5 Permit Lease
    -> optional real Citi tools / writes
```

---

## Requirements

Use Python 3.11+.

Install from the Backplane root:

```powershell
python -m pip install -e interface_standard -e Zero_Trust_Task3_PEP_Integrated/zero_trust_pep_task3_integrated -e zero_trust_pdp_task4_secure -e zero_trust_task5
```

---

## Mode 1 — Basic self-test

```powershell
python integrated_demo/run_demo.py --clean
```

---

## Mode 2 — Real Citi scanner graph

```powershell
python integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --scanner-graph
```

This replaces the small baseline interaction fixture with the graph actually discovered by Task 2 before Task 3 PEP placement.

---

## Mode 3 — Real three-office read tools

```powershell
python integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --scanner-graph `
  --execute-real-tools
```

Default read fixtures are defined in:

```text
integrated_demo/testbed_inputs.yaml
```

Current protected real read tools:

```text
Front Office: get_transaction_context
Mid Office:   get_customer_financial_profile
Back Office:  get_eod_batch
```

---

## Mode 4 — Real protected writes

Start the Citi FastAPI backend first:

```powershell
cd D:\Lab\Citi_P3\citi_banking_backend
python -m pip install -r requirements.txt
python scripts\init_db.py
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Then, in another PowerShell:

```powershell
cd D:\Lab\Citi_P3_Zero_Trust_Backplane
.\.venv\Scripts\Activate.ps1

python integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --scanner-graph `
  --execute-real-tools `
  --execute-real-writes
```

Current protected real writes:

```text
transaction_processing_agent -> execute_transfer
ledger_update_agent           -> apply_ledger_updates
```

Write fixtures are defined in:

```text
integrated_demo/real_write_inputs.yaml
```

---

## What `--clean` does

`--clean` removes generated Backplane demo artifacts under `integrated_demo/output/` before the run.

It does not reset the Citi banking database.

---

## Important Output

A successful real-testbed run should show stages such as:

```text
Task 2 discovered real agents/tools/APIs/databases/edges
Reconciled runtime bindings
scanner_edges_merged
Task 3 sensitive/protected edge counts
Task 3 / Task 4 registry compatibility: True
Task 4 PDP healthy
Task 5 security scenarios
REAL TOOL ... -> ALLOW
REAL WRITE ... -> ALLOW + EXECUTED
Task 5 hash-chained audit valid: True
ALL TASKS 1-5 INTEGRATED: PASS
```

---

## Output Artifacts

```text
integrated_demo/output/
├── task2/
├── task1_task2_reconciliation.json
├── reconciled_manifest.yaml
├── task3_generated/
├── task4_decision_log.jsonl
├── task4_policy_versions.json
├── task5_audit.json
└── demo_summary.json
```

---

## Current Coverage Interpretation

Task 3 reports coverage over the sensitive interaction edges currently represented in the merged manifest.

For example:

```text
42 sensitive edges
42 protected edges
100% coverage
```

means 100% of the **currently discovered and merged sensitive graph** is protected. It does not make a claim about a path the scanner did not discover.

Sensitivity is currently determined by rule-based attributes such as risk, trust-boundary crossing, side effects, data classification, and action criticality.
