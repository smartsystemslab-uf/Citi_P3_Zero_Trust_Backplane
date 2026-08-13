# Citi P3 Zero Trust Backplane

A prototype Zero Trust security backplane for Citi's multi-agent system testbed. The Backplane analyzes the existing multi-agent system, discovers interaction paths, maps runtime names into a unified interface, generates Policy Enforcement Points (PEPs), makes contextual authorization decisions through a Policy Decision Point (PDP), and protects real multi-agent operations with short-lived signed Permit Leases.

The current integrated demo connects **Tasks 1–5** to the real Citi Front Office, Mid Office, and Back Office testbed and has successfully protected both real read operations and real state-changing operations.

---

## 1. Project Goal

The project is designed to protect an existing multi-agent system without requiring major changes to its core application logic.

The Backplane is intended to provide three main capabilities:

1. **Understand the existing multi-agent architecture automatically.**
2. **Identify and generate the required Zero Trust enforcement points automatically.**
3. **Enforce runtime authorization safely**, including PDP delay, request binding, cached authorization, expiration, replay protection, approval requirements, and audit integrity.

The current implementation covers the functional scope of Tasks 1–5 and provides a real-testbed integration layer that prepares the system for full Task 6 workflow integration.

---

## 2. High-Level Architecture

### Build / generation path

```text
Existing Citi Three-Office Testbed
        |
        v
Task 1: System Model + Unified Interface
        |
        v
Task 2: Source Scanner + Interaction Graph
        |
        v
Runtime-Binding Reconciliation
        |
        v
Merged Unified Manifest / ZT-IR
        |
        v
Task 3: PEP Placement + PEP Generation
```

### Runtime authorization path

```text
Real Agent / Tool Request
        |
        v
Generated PEP
        |
        |  authorization request
        v
Task 4 PDP + Policy Engine
        |
        |  ALLOW / DENY / MANUAL_REVIEW /
        |  ALLOW_WITH_OBLIGATIONS / REAUTHENTICATE
        v
Task 5 Permit Lease
        |
        |  verify request binding, expiration,
        |  policy/identity versions, use count,
        |  obligations and signature
        v
Original Citi Tool / API
        |
        v
Real Testbed Data / State Change
```

The main design principle is:

> **Adapt the security layer to the existing multi-agent system instead of rewriting the multi-agent system for the security layer.**

---

## 3. Current Task Integration

| Task | Role | Current Demo Behavior |
|---|---|---|
| **Task 1** | Requirements, system model, ZT-IR, unified interface | Loads the canonical identities, resources, interfaces, workflows, and interaction model. |
| **Task 2** | System scanner and interaction-graph generation | Scans the real Citi source tree and discovers agents, tools, APIs, databases, and interaction edges. |
| **Integration / Reconciliation** | Connect scanner names to canonical IDs | Maps real runtime names such as `fraud_detection_agent` or `apply_ledger_updates` to stable Unified Interface IDs. |
| **Task 3** | PEP placement and generation | Analyzes the discovered graph and generates logical PEPs plus deduplicated physical enforcement components. |
| **Task 4** | PDP and policy engine | Evaluates `Subject + Resource + Action + Context` and returns signed runtime authorization decisions. |
| **Task 5** | Permit Lease, cache safety, revocation, replay protection | Converts valid authorization into bounded signed leases and rejects stale, modified, replayed, or unsafe operations. |

---

## 4. Unified Interface and Runtime Reconciliation

The Backplane distinguishes between:

- **Canonical IDs** used by Tasks 1–5 and policies.
- **Runtime IDs** discovered in the actual Citi implementation.

Example:

```text
Canonical identity:
agent.front_office.fraud

Runtime identity:
fraud_detection_agent
```

Another example:

```text
Canonical interface:
interface.mcp.ledger_update

Runtime tool:
apply_ledger_updates
```

The integration layer preserves the canonical identity as the policy-facing source of truth while storing the real Citi implementation name as the runtime binding.

Important integration files:

```text
integrated_demo/
├── reconcile.py
├── scanner_merge.py
├── task1_unified_bindings.yaml
└── native_task4_bridge.py
```

`reconcile.py` verifies important Task 1 / Task 2 runtime mappings.

`scanner_merge.py` merges the real Task 2 interaction graph into a demo copy of the unified manifest. It does **not** rewrite the original Task 1–5 source manifests.

`native_task4_bridge.py` verifies Task 4's native signed request/decision representation before normalizing the authorized operation for Task 5 Permit Lease issuance.

---

## 5. Automatic Sensitivity and Risk Classification

Sensitivity is currently determined automatically using **rule-based security heuristics**, not an ML or LLM classifier.

### Task 2 inference

Task 2 derives security attributes from source-code structure and operation semantics. Examples include:

- `get_*`, `list_*`, `search_*` -> read-style operation
- `execute_*`, `apply_*`, `update_*`, `persist_*`, `store_*` -> state-changing operation
- transfer or ledger mutation -> high-impact state-changing operation
- HTTP `GET` -> read
- HTTP `POST` / `PUT` / `PATCH` / `DELETE` -> write/state change
- database reads and writes -> data access / side effects
- customer data -> possible PII
- account / transaction data -> sensitive operational data

Task 2 records properties such as:

```text
action / operation class
risk level
side effects
data type
trust boundary
```

### Task 3 sensitivity rule

Task 3 treats an interaction as sensitive when at least one relevant security condition is present, including:

```text
trust boundary exists
OR risk is medium / high / critical
OR the operation has side effects
OR the resource is confidential / restricted / regulated
OR the action criticality is high / critical
```

The current scanner-to-manifest merge uses conservative risk mapping. In the current real Citi testbed run, all 42 merged interaction edges satisfy the protection criteria.

Therefore the reported result:

```text
42 sensitive interaction edges
42 protected sensitive edges
100% sensitive-path coverage
```

means:

> **100% coverage of the sensitive interaction edges currently discovered and represented in the merged manifest.**

It should not be interpreted as proof that an interaction not discovered by the scanner is automatically protected.

---

## 6. Task 3 PEP Generation

Task 3 analyzes each interaction and decides which enforcement type should protect it.

Supported logical PEP categories include:

```text
Input PEP
Agent Route PEP
Tool PEP
MCP PEP
API PEP
Data PEP
Event PEP
Output PEP
Shared Middleware
```

A logical PEP represents a required protection point in the interaction graph.

Multiple compatible logical PEPs can share one physical enforcement component. This avoids deploying unnecessary duplicate middleware or wrappers.

A reference run against the current Citi testbed produced:

```text
interaction_edges_total:       42
sensitive_interaction_edges:   42
protected_sensitive_edges:     42
logical_pep_count:             42
physical_pep_count:             4
deduplicated_component_savings: 38
```

---

## 7. Task 4 PDP and Policy Engine

Task 4 evaluates authorization using:

```text
Subject + Resource + Action + Context
```

Context can include:

```text
workflow
risk
human approval
secondary authorization
idempotency information
change-management context
time / policy state
```

Supported decision types include:

```text
ALLOW
DENY
MANUAL_REVIEW
ALLOW_WITH_OBLIGATIONS
REAUTHENTICATE
```

Examples:

- Fraud agent may read transaction history.
- Sensitive returned data may require masking.
- A critical state-changing operation may require human approval.
- An undefined or unauthorized operation is denied by default.

The integrated demo starts the real signed Task 4 PDP in-process and verifies Task 3 / Task 4 registry compatibility before runtime testing.

---

## 8. Task 5 Permit Lease and Cache Safety

A simple cached value such as:

```text
allow = true
```

is unsafe because it may remain usable after the request, identity, policy, or risk state changes.

Task 5 instead uses a short-lived signed **Permit Lease**.

A Permit Lease binds authorization to security context such as:

```text
subject identity
resource identity
action
request hash
workflow ID
issue time
expiration time
policy version
identity version
risk version
maximum uses
required obligations
digital signature
```

### Request binding

Authorization for one exact operation cannot be reused for a modified operation.

Example:

```text
Authorized:
Transfer $100 from A -> B

Modified request:
Transfer $1000 from A -> C

Result:
DENY
```

The request hash changes, so the old lease is no longer valid for the new operation.

### PDP timeout behavior

```text
NO_DECISION
    |
    v
WAITING_FOR_PDP
    |
    +-- ALLOW --> ACTIVE_LEASE
    |
    +-- DENY --> DENIED
    |
    +-- TIMEOUT
           |
           +-- valid exact matching lease --> ACTIVE_LEASE
           |
           +-- no valid lease --> DENIED
```

High-risk operations fail closed when no valid decision or matching lease is available.

### Critical write protection

Critical state-changing operations can use single-use or bounded-use Permit Leases. Replaying a consumed lease is rejected.

---

## 9. Real Citi Three-Office Testbed Integration

The current demo scans and protects the actual Citi Front Office, Mid Office, and Back Office source tree.

A reference scan discovered:

```text
33 agents
23 raw scanner tools
19 APIs
6 databases
42 interaction edges
```

The raw Task 2 inventory may include private helper names such as `_load`. The integration merge filters private `_`-prefixed helpers from the tool graph used by later stages.

### Real read operations used by the demo

#### Front Office

```text
fraud_detection_agent
    -> generated PEP
    -> PDP / Permit Lease
    -> get_transaction_context("TXN-1001")
```

#### Mid Office

```text
financial_data_agent
    -> generated PEP
    -> PDP / Permit Lease
    -> get_customer_financial_profile("CUST-001")
```

#### Back Office

```text
eod_processing_agent
    -> generated PEP
    -> PDP / Permit Lease
    -> get_eod_batch("EOD-2026-04-21-CLEAN")
```

### Real write operations used by the demo

#### Front Office transfer

```text
transaction_processing_agent
    -> generated PEP
    -> signed PDP decision
    -> Permit Lease
    -> execute_transfer(...)
    -> Citi FastAPI backend
    -> real persisted transaction
```

#### Back Office ledger update

```text
ledger_update_agent
    -> generated PEP
    -> signed PDP decision
    -> Permit Lease
    -> apply_ledger_updates(...)
    -> real EOD state update
```

The demo uses the real Citi tool implementation after Zero Trust authorization succeeds.

---

# 10. Usage Guide

## 10.1 Requirements

### Backplane

Use **Python 3.11 or newer**.

The Unified Interface package requires:

```text
Python >= 3.11
```

### Real Citi testbed

The real testbed is expected to contain the Citi multi-agent system components, including paths such as:

```text
citi_banking_adk/
citi_banking_backend/
citi_banking_mcp_server/
```

The integrated scanner specifically expects the existing Citi project structure that contains the agent definitions, tools, MCP server, FastAPI backend, and data models.

---

## 10.2 Create a Backplane Virtual Environment

### Windows PowerShell

From the Zero Trust Backplane repository root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Confirm the version:

```powershell
python --version
```

Expected:

```text
Python 3.11.x
```

Upgrade the packaging tools:

```powershell
python -m pip install --upgrade pip setuptools wheel
```

---

## 10.3 Install Backplane Packages

From the Backplane repository root:

```powershell
python -m pip install `
  -e interface_standard `
  -e Zero_Trust_Task3_PEP_Integrated/zero_trust_pep_task3_integrated `
  -e zero_trust_pdp_task4_secure `
  -e zero_trust_task5
```

Equivalent one-line command:

```powershell
python -m pip install -e interface_standard -e Zero_Trust_Task3_PEP_Integrated/zero_trust_pep_task3_integrated -e zero_trust_pdp_task4_secure -e zero_trust_task5
```

---

## 10.4 Demo Mode 1 — Basic Task 1–5 Self-Test

This mode uses the bundled static-analysis fixture and does not require the real Citi testbed.

```powershell
python integrated_demo/run_demo.py --clean
```

Use this to verify that the Backplane packages and Task 1–5 integration work locally.

---

## 10.5 Demo Mode 2 — Scan the Real Citi Testbed Graph

Example repository locations:

```text
Backplane:
D:\Lab\Citi_P3_Zero_Trust_Backplane

Citi testbed:
D:\Lab\Citi_P3
```

Run:

```powershell
python integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --scanner-graph
```

This mode:

1. Scans the real Citi source code.
2. Generates Task 2 draft inventories and interaction edges.
3. Reconciles runtime names with the Unified Interface.
4. Replaces the small baseline graph with the real scanner-discovered graph.
5. Runs Task 3 PEP placement on that real graph.
6. Starts Task 4 and Task 5 security tests.

No original Citi read/write tool needs to execute in this mode.

---

## 10.6 Demo Mode 3 — Execute Real Front/Mid/Back Office Read Tools

Run:

```powershell
python integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --scanner-graph `
  --execute-real-tools
```

This executes the original Citi testbed read tools behind the generated PEP/PDP/Permit-Lease chain.

Default inputs are stored in:

```text
integrated_demo/testbed_inputs.yaml
```

Current default examples:

```text
Front Office: TXN-1001
Mid Office:   CUST-001
Back Office:  EOD-2026-04-21-CLEAN
```

`testbed_runtime.py` initializes the original ADK repository used by these tools so the expected local testbed tables and seed records are available.

---

## 10.7 Demo Mode 4 — Execute Real Protected Write Operations

This is the most complete current demo mode.

It protects and executes:

```text
Front Office: execute_transfer(...)
Back Office:  apply_ledger_updates(...)
```

### Step A — Install Citi backend dependencies

Open a separate PowerShell window:

```powershell
cd D:\Lab\Citi_P3\citi_banking_backend
python -m pip install -r requirements.txt
```

The backend requirements include FastAPI, Uvicorn, SQLAlchemy, Pydantic, python-dotenv, and httpx.

### Step B — Initialize the backend database

For first-time setup, or whenever the backend database needs to be initialized:

```powershell
python scripts\init_db.py
```

### Step C — Start the Citi FastAPI backend

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Keep this terminal running.

The Backplane checks:

```text
http://127.0.0.1:8000/health
```

before executing the real transfer.

### Step D — Run the Backplane in real-write mode

Open another PowerShell window:

```powershell
cd D:\Lab\Citi_P3_Zero_Trust_Backplane
.\.venv\Scripts\Activate.ps1
```

Then run:

```powershell
python integrated_demo/run_demo.py --clean `
  --banking-repo "D:\Lab\Citi_P3" `
  --scanner-graph `
  --execute-real-tools `
  --execute-real-writes
```

The Backplane will first verify the Citi backend health endpoint and then execute the protected real operations.

---

## 10.8 Real-Write Input Configuration

Real-write parameters are stored in:

```text
integrated_demo/real_write_inputs.yaml
```

The current synthetic transfer fixture uses a small test transfer and includes approval context.

The current protected Back Office fixture uses the EOD batch and supplies the required approval / change-management context.

You can change the test parameters in this YAML file without changing Task 1–5 source code.

Custom file:

```powershell
python integrated_demo/run_demo.py ... `
  --execute-real-writes `
  --real-write-inputs "path\to\my_write_inputs.yaml"
```

---

## 10.9 Custom Backend URL

The default backend is:

```text
http://127.0.0.1:8000
```

Override it with:

```powershell
python integrated_demo/run_demo.py ... `
  --execute-real-writes `
  --banking-backend-url "http://127.0.0.1:9000"
```

or set:

```text
BANKING_BACKEND_BASE_URL
```

in the environment.

---

## 10.10 `--clean` Behavior

`--clean` removes the generated Backplane demo artifact directory before the run.

It cleans output such as:

```text
integrated_demo/output/
```

It does **not** mean "reset the Citi testbed database."

Real state-changing operations remain persisted testbed operations unless the testbed itself is reinitialized.

---

# 11. Command-Line Options

```text
--banking-repo PATH
    Multi-agent system source tree scanned by Task 2.

--output PATH
    Output directory for generated demo artifacts.

--scanner-graph
    Replace the small baseline interaction fixture with the real Task 2 discovered graph.

--execute-real-tools
    Execute original Front/Mid/Back Office Python tools after Zero Trust authorization.

--testbed-inputs PATH
    YAML parameters for real read-tool tests.

--execute-real-writes
    Execute protected real Front Office transfer and Back Office ledger update.

--real-write-inputs PATH
    YAML parameters for real write operations.

--banking-backend-url URL
    Citi FastAPI backend URL. Default: http://127.0.0.1:8000

--clean
    Clear generated Backplane demo output before running.
```

Check the locally installed options with:

```powershell
python integrated_demo/run_demo.py -h
```

---

# 12. How to Read the Demo Output

## Task 1

Example:

```text
Task 1 inventory: 29 agents, 28 tools, 78 interaction edges
Unified interface baseline: VALID
```

Meaning:

- The initial system model is loaded.
- The Unified Interface schema and baseline manifest are valid.
- Later tasks have a common naming and data contract.

---

## Task 2

Example reference output:

```text
discovered_agents: 33
discovered_tools: 23
discovered_apis: 19
discovered_databases: 6
discovered_edges: 42
```

Meaning:

- The scanner found the real multi-agent testbed components.
- The scanner generated a machine-readable interaction graph.

---

## Runtime Reconciliation

Example:

```text
agent.front_office.fraud:
fraud_agent -> fraud_detection_agent

interface.mcp.ledger_update:
ledger_update -> apply_ledger_updates
```

Meaning:

- Canonical Zero Trust identities remain stable.
- The Backplane knows which real Citi runtime object implements each selected identity or interface.

---

## Real Scanner Graph Merge

Example:

```text
scanner_edges_input: 42
scanner_edges_merged: 42
```

Meaning:

- Task 3 is consuming the graph discovered from the real Citi code instead of only the original small baseline fixture.

---

## Task 3 Coverage

Example:

```text
interaction_edges_total: 42
sensitive_interaction_edges: 42
protected_sensitive_edges: 42
sensitive_path_coverage_percent: 100.0
logical_pep_count: 42
physical_pep_count: 4
```

Meaning:

- All sensitive edges currently represented in the merged graph have generated protection.
- Logical protection requirements are deduplicated into fewer physical enforcement components.

---

## Task 4

Example:

```text
Task 3 / Task 4 registry compatibility: True
Task 4 PDP healthy
```

Meaning:

- Generated PEP identities/resources are compatible with the PDP registry.
- The signed policy engine is available for runtime decisions.

---

## Task 5 Security Scenarios

Typical scenarios include:

### Authorized read + masking

```text
Fraud read: ALLOW
full_account_number: ***MASKED***
ssn: ***MASKED***
```

Meaning: authorization may include obligations, not only a binary allow/deny result.

### Exact retry during PDP timeout

```text
ACTIVE_LEASE via CACHE
```

Meaning: an exact authorized noncritical request may continue using a still-valid bounded Permit Lease.

### Modified request

```text
DENIED
PDP_TIMEOUT_NO_VALID_LEASE
```

Meaning: request binding prevents an old authorization from being reused after parameters change.

### PEP restart

```text
DENIED
```

Meaning: local authorization cache is cleared and the system fails closed when no valid decision exists.

### Critical operation without approval

```text
DENIED
Task 4 decision=MANUAL_REVIEW
```

Meaning: high-risk state-changing operations can require additional approval.

### Critical operation with approval

```text
ALLOW
```

Meaning: the authorization decision is contextual rather than permanently attached to the identity.

### Replay

```text
DENIED
Single-use or bounded-use Permit Lease was replayed
```

Meaning: a critical authorization cannot be consumed repeatedly.

---

## Real Three-Office Read Tools

Expected successful output includes:

```text
front_office: REAL TOOL get_transaction_context -> ALLOW
mid_office: REAL TOOL get_customer_financial_profile -> ALLOW
back_office: REAL TOOL get_eod_batch -> ALLOW
```

Meaning:

The original Citi tool executes only after the generated Zero Trust enforcement path authorizes the request.

---

## Real Writes

Expected successful output includes:

```text
front_office_transfer:
REAL WRITE execute_transfer -> ALLOW + EXECUTED
```

and:

```text
back_office_ledger_update:
REAL WRITE apply_ledger_updates -> ALLOW + EXECUTED
```

Meaning:

The authorization layer is protecting actual state-changing multi-agent operations, not only mock callbacks or read-only functions.

---

## Audit Chain

Example:

```text
Task 5 hash-chained audit valid: True
```

Meaning:

Task 5's audit events form a valid hash chain, providing tamper-evident evidence of authorization and execution activity.

---

## Final Result

```text
ALL TASKS 1-5 INTEGRATED: PASS
```

Meaning:

All scenarios enabled for that run completed successfully.

For the full current real-testbed demo this includes the Task 1–5 pipeline, real graph generation, security behavior, real three-office read tools, real writes, and audit verification.

---

# 13. Generated Artifacts

The integrated runner writes outputs under:

```text
integrated_demo/output/
```

Important artifacts include:

```text
task2/
    Task 2 scanner drafts and coverage output

task1_task2_reconciliation.json
    Canonical/runtime binding verification

reconciled_manifest.yaml
    Unified manifest used by later demo stages

task3_generated/
    Generated PEP plan, adapters, coverage reports and registry artifacts

task4_decision_log.jsonl
    Task 4 decision log

task4_policy_versions.json
    Policy-version information used by the demo

task5_audit.json
    Task 5 hash-chained audit events

demo_summary.json
    Machine-readable pass/fail summary for the integrated demo
```

---

# 14. Troubleshooting

## Error: Python version is too old

Example:

```text
Package 'zero-trust-backplane-interface' requires a different Python:
3.10.x not in '>=3.11'
```

Fix:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Then reinstall the Backplane packages.

---

## Error: `No module named 'cryptography'`

This usually means the Backplane editable-package installation did not finish successfully.

Activate the Python 3.11 environment and reinstall the Backplane packages:

```powershell
python -m pip install -e interface_standard -e Zero_Trust_Task3_PEP_Integrated/zero_trust_pep_task3_integrated -e zero_trust_pdp_task4_secure -e zero_trust_task5
```

---

## Error: backend health check / connection refused

Example:

```text
Health check failed at http://127.0.0.1:8000/health
ConnectionRefusedError
```

Meaning:

`--execute-real-writes` requires the Citi FastAPI backend for the real transfer operation.

Fix:

```powershell
cd D:\Lab\Citi_P3\citi_banking_backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

---

## Error: backend dependency missing

Instead of installing packages one by one, install the backend requirements:

```powershell
cd D:\Lab\Citi_P3\citi_banking_backend
python -m pip install -r requirements.txt
```

---

## Error: `no such table: transactions/customers/eod_batches`

For the ADK local repository, the current integration runtime calls the original repository initialization path before executing real read tools.

For the separate FastAPI backend database, initialize it before first use:

```powershell
python scripts\init_db.py
```

---

## Deprecation warnings

A warning such as an AST or Starlette/httpx deprecation warning is not necessarily a demo failure.

Use the final `PASS` / `FAIL` scenario summary to determine whether the integrated execution succeeded.

---

# 15. Current Scope and Limitations

The current demo demonstrates:

- real Citi source scanning;
- real interaction-graph merging;
- automatic rule-based sensitivity analysis;
- generated PEP placement;
- real signed Task 4 PDP decisions;
- Task 5 Permit Lease protection;
- timeout and cache-safety behavior;
- request-modification rejection;
- critical-operation approval requirements;
- replay rejection;
- real Front/Mid/Back Office reads;
- real Front Office transfer execution;
- real Back Office ledger update execution;
- hash-chained audit validation.

Important scope limits:

1. **Coverage is scanner/discovered-graph coverage.** A path that is not discovered and not represented in the merged manifest is outside the reported coverage denominator.
2. **Sensitivity classification is currently heuristic/rule-based.** It is deliberately conservative and is not an ML risk classifier.
3. **The current real-tool integration is Backplane-driven tool execution.** The next integration stage is to place the Backplane directly inside the complete ADK workflow so that the normal `user_proxy_agent -> office workflow -> agent -> tool` execution is intercepted automatically.
4. **Real write mode changes real testbed state.** Use synthetic demo values and understand the testbed-side effects before enabling `--execute-real-writes`.

---

# 16. Next Steps

The next project stages are aligned with the original work plan:

### Task 6 — Full Citi Workflow Integration

Move from Backplane-driven protected tool calls to full agent-driven workflows:

```text
User / Trigger
    -> user_proxy_agent or office workflow
    -> actual agent routing
    -> generated PEP intercept
    -> PDP / Permit Lease
    -> original tool / API
```

Representative workflows:

```text
Front Office customer transaction
Fraud / compliance review
Back Office EOD -> ledger -> reconciliation -> report / exception
```

### Task 7 — Security and Performance Evaluation

Measure and validate:

```text
PEP latency
PDP latency
local lease-validation latency
end-to-end overhead
throughput
revocation propagation
bypass attempts
identity spoofing
expired permits
replay
PDP failure
network failure
PEP restart
```

### Task 8 — Final Demonstration and Documentation

Package the generator, protected workflows, evaluation results, audit evidence, presentation, and integration documentation.

---

# 17. Repository Layout

A typical Backplane checkout contains:

```text
Citi_P3_Zero_Trust_Backplane/
├── README.md
├── zero_trust_task1/
├── zero_trust_task2/
│   └── zt_scan.py
├── interface_standard/
├── Zero_Trust_Task3_PEP_Integrated/
│   └── zero_trust_pep_task3_integrated/
├── zero_trust_pdp_task4_secure/
├── zero_trust_task5/
└── integrated_demo/
    ├── run_demo.py
    ├── reconcile.py
    ├── scanner_merge.py
    ├── native_task4_bridge.py
    ├── testbed_runtime.py
    ├── task1_unified_bindings.yaml
    ├── testbed_inputs.yaml
    ├── real_write_inputs.yaml
    └── output/
```

---

# 18. Short Demo Summary

The integrated prototype can currently be summarized as:

```text
Existing Citi Multi-Agent System
                +
Automatically Generated Zero Trust Backplane
                =
Protected Real Multi-Agent Operations
```

The current demo demonstrates that the Backplane can discover the real Citi multi-agent testbed, generate enforcement based on the discovered interaction graph, make contextual authorization decisions, safely handle temporary authorization, and protect real read and state-changing operations while keeping the original application tools largely unchanged.
