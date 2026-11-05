# Citi P3 Zero Trust Backplane — legacy Citi guide

> **Legacy guide.** This is the Citi P3-specific guide (integrated demo, Tasks 1–6 on CITI-MAS,
> native runtime started from the MAS, the hand-written Citi policy store). The Backplane now
> protects **any** Google ADK application; start with the main [README](../README.md). Links to
> sections (§) below refer to this document.


A Zero Trust security layer for the Citi P3 multi-agent banking testbed (**CITI-MAS**: Front, Mid
and Back Office agents built on Google ADK). The Backplane scans the existing multi-agent system,
discovers how its agents, tools, APIs and databases interact, generates a Policy Enforcement Point
(PEP) for every sensitive interaction, decides every request with a signed Policy Decision Point
(PDP), and turns each permitted request into a short-lived, request-bound, signed **Permit Lease**.
It does this without rewriting the multi-agent system.

What this repository contains today:

* **Tasks 1–6 of the work plan:**
  * Task 1: system model and Unified Interface.
  * Task 2: source scanner.
  * Task 3: PEP generation.
  * Task 4: PDP.
  * Task 5: Permit Leases.
  * Task 6: protection of the real CITI-MAS workflows.
* **PSL policies.** Every authorization policy is a signed **PSL** (IEEE 1850) policy, decided
  **deny-overrides**. This covers the Task 4 policies, the generated least-privilege policies and
  the Task 1 natural-language rules.
* **SPIFFE identities (scheme B).** In the distributed runtime every agent runs in its own
  container. It authenticates with an X.509-SVID workload identity, a separate agent certificate
  and signed requests.
* **Three ways to run the Backplane against the real MAS:**
  * an integrated demo harness;
  * a native plugin inside the running MAS;
  * a distributed Docker deployment.

> **Conventions used in this README:**
> * Paths: the Backplane is at `D:\Lab\Citi_P3_Zero_Trust_Backplane` and the MAS at
>   `D:\Lab\Citi_P3`. Both locations can be changed (§3.2).
> * Commands are Windows PowerShell and run from the Backplane root with the virtual environment
>   active (§3.4), unless a section says otherwise. Notes for Linux/macOS are in §3.4.

## Contents

1. [What the Backplane does](#1-what-the-backplane-does)
2. [Choose how to run it](#2-choose-how-to-run-it)
3. [Setup](#3-setup)
4. [Quick start](#4-quick-start)
5. [Integrated demo (Tasks 1–6)](#5-integrated-demo-tasks-16)
6. [Native runtime: protect the MAS while it runs](#6-native-runtime-protect-the-mas-while-it-runs)
7. [Distributed runtime: one container per agent, SPIFFE identities](#7-distributed-runtime-one-container-per-agent-spiffe-identities)
8. [Policies (PSL): read, change, add, sign](#8-policies-psl-read-change-add-sign)
9. [Identity: SPIFFE scheme B](#9-identity-spiffe-scheme-b)
10. [How the protection works](#10-how-the-protection-works)
11. [Tests](#11-tests)
12. [Troubleshooting](#12-troubleshooting)
13. [Project status and limitations](#13-project-status-and-limitations)
14. [Repository layout](#14-repository-layout)
15. [Further documentation](#15-further-documentation)

---

## 1. What the Backplane does

Design principle:

> **Adapt the security layer to the existing multi-agent system instead of rewriting the
> multi-agent system for the security layer.**

### 1.1 Build path (once, before any request is served)

```text
CITI-MAS source tree
    -> Task 1  system model + Unified Interface (canonical IDs, schemas)
    -> Task 2  source scanner: agents, tools, APIs, databases, events, interaction edges
    -> reconciliation: real runtime names -> canonical IDs
    -> merged unified manifest
    -> Task 3  PEP placement: one logical PEP per sensitive edge, deduplicated into physical PEPs
    -> Task 4  PDP configuration: identities, resources, signed PSL policy store
```

### 1.2 Request path (every agent route, tool call, input and output)

```text
agent / tool request
    -> generated PEP                          intercepts the call
    -> SPIFFE scheme B (distributed runtime)  workload SVID + agent certificate + RFC 9421 signature
    -> Task 4 PDP                             signed request, verified evidence, PSL deny-overrides
         ALLOW | ALLOW_WITH_OBLIGATIONS | MANUAL_REVIEW | REAUTHENTICATE | DENY
    -> Task 5 Permit Lease                    bound to request hash, policy/identity version, TTL, uses
    -> PSL workflow monitors                  e.g. "validation ran before the ledger update"
    -> original Citi tool / API / agent
    -> hash-chained audit
```

### 1.3 Components

| directory | what it is | used by |
|---|---|---|
| `zero_trust_task1/` | system model, ZT-IR manifests, natural-language policy rules (`manifest/policy_intent.yaml`) | all |
| `interface_standard/` | Unified Interface: schemas, canonical IDs, validator (CLI `zt-interface`) | Tasks 2–5 |
| `zero_trust_task2/` | source scanner `zt_scan.py` | all runtimes |
| `Zero_Trust_Task3_PEP_Integrated/` | PEP placement and generation (CLI `zt-pep`) | all runtimes |
| `zero_trust_pdp_task4_secure/` | PDP, signed PSL policy store, development keys, report scripts | all runtimes |
| `zero_trust_task5/` | Permit Leases, cache safety, revocation, hash-chained audit | all runtimes |
| `zero_trust_psl/` | PSL language: parser, compiler, deny-overrides engine, temporal monitors, natural-language translator, signing (CLI `zt-psl`) | PDP, runtimes, policy authors |
| `zero_trust_identity/` | SPIFFE scheme B: SVID mTLS, agent certificates, RFC 9421 signatures, agent registry | distributed runtime |
| `integrated_demo/` | harness that runs Tasks 1–6 end to end | §5 |
| `native_mas_runtime/` | in-process engine called by the MAS's ADK plugin | §6 |
| `distributed_runtime/` | Docker deployment: gateway PEP, one container per agent, SPIRE | §7 |
| `docs/` | design document and PSL reports | §15 |

---

## 2. Choose how to run it

| you want to | go to | needs | writes into the MAS checkout? |
|---|---|---|---|
| check that everything works on your machine | §4 Quick start | Python 3.11 | no |
| watch the Backplane analyse the real MAS and protect real tool calls | §5 Integrated demo | + MAS checkout; mode 4 also the MAS backend | modes 1–2: no. Modes 3–4 and Task 6 write MAS databases, so run them on a copy (§5.1) |
| protect the real MAS while it runs, with real LLM-driven routing | §6 Native runtime | + MAS virtual environment + LLM API key | yes: allowed critical writes change the MAS database |
| run every agent in its own container with SPIFFE identities | §7 Distributed runtime | + Docker Desktop | no: it builds from a read-only copy |
| read, change or add a policy | §8 Policies | Python 3.11 | no |

---

## 3. Setup

### 3.1 Requirements

| requirement | needed for |
|---|---|
| Windows 10/11 with PowerShell (Linux/macOS also work, see §3.4) | all |
| Python 3.11 (on Windows the `py` launcher) | all |
| Git | all |
| The CITI-MAS repository, checked out next to this one | demo modes 2–4, Task 6, native and distributed runtimes |
| Docker Desktop with Linux containers | distributed runtime |
| An LLM endpoint and key in the MAS's `.env` | native runtime only |

### 3.2 Where the repositories are

```text
D:\Lab\
├── Citi_P3\                          the MAS (CITI-MAS)
└── Citi_P3_Zero_Trust_Backplane\     this repository
```

| component | where it looks for the other repository | how to change it |
|---|---|---|
| integrated demo | uses the bundled sample system unless told otherwise | `--banking-repo PATH` |
| native runtime (started from the MAS) | a sibling folder named `Citi_P3_Zero_Trust_Backplane` | `--zt-backplane-root PATH` or environment variable `CITI_ZT_BACKPLANE_ROOT` |
| native runtime tests (`native_mas_runtime/tests`) | a sibling folder named `Citi_P3` | environment variable `CITI_MAS_REPO` |
| generic path (`profiles/citi_p3`) | a copy of `citi_banking_adk` | environment variable `CITI_MAS_COPY` |

### 3.3 Get the code

```powershell
git clone https://github.com/smartsystemslab-uf/Citi_P3_Zero_Trust_Backplane.git D:\Lab\Citi_P3_Zero_Trust_Backplane
cd D:\Lab\Citi_P3_Zero_Trust_Backplane
```

The policy files and the hash-pinned interface schemas are signed or hashed byte for byte.
`.gitattributes` checks them out without line-ending conversion (`-text`), so their signatures
verify on every clone. If you edit a policy, re-sign it (§8.5).

### 3.4 Create the Python environment

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install `
    -e interface_standard `
    -e Zero_Trust_Task3_PEP_Integrated\zero_trust_pep_task3_integrated `
    -e zero_trust_pdp_task4_secure `
    -e zero_trust_task5 `
    -e zero_trust_psl `
    pytest
```

* **`zero_trust_psl` is required.** The PDP, the policy scripts and the `zt-psl` command all
  import it.
* **`pytest`** is needed only for the tests (§11).
* **Optional:** `python -m pip install -e zero_trust_identity` adds the SPIFFE scheme B library.
  You need it on the host only to run its 25 tests there. The distributed runtime installs it
  inside its own image.
* **The distributed runtime scripts use `.venv`.** `ctl.ps1` runs `.venv\Scripts\python.exe`, so
  keep the environment in that folder.
* **A committed `.venv`.** Older commits track a Windows `.venv` folder and some `*.egg-info`
  folders from the original development machine. Its `pyvenv.cfg` points at that machine's
  Python, so don't rely on it; the commands above rebuild it for your machine. After that,
  `git status` can show changes under `.venv/` and `*.egg-info/`. These are build artifacts:
  don't commit them.
* **Linux/macOS:** use `python3.11 -m venv .venv` and `source .venv/bin/activate`, write paths
  with `/`, and replace the PowerShell line continuation `` ` `` with `\`.
* **Script blocked:** if PowerShell refuses to run `Activate.ps1`, run
  `Set-ExecutionPolicy -Scope Process Bypass` once in that window.

### 3.5 Check the installation

```powershell
python zero_trust_pdp_task4_secure\scripts\sign_psl_policies.py --check
```
```text
verified and compiled 10 files, 33 rules, policy version 6ddcf1b28ad5e95e
```

```powershell
python zero_trust_pdp_task4_secure\scripts\validate_configuration.py
```
```text
Interface schemas: unchanged and verified
...
Configuration validation: PASSED
```

The first command verifies the signature of every policy file and compiles the policy set. The
second checks the interface schemas against their recorded hashes and starts the PDP once.

---

## 4. Quick start

These steps need only Python. Step 3 also reads the MAS source; it doesn't change it.

```powershell
# 1. The policy store is intact and signed
python zero_trust_pdp_task4_secure\scripts\sign_psl_policies.py --check

# 2. Tasks 1-5 end to end on the bundled sample system (no MAS needed)
python integrated_demo\run_demo.py --clean --output "$env:TEMP\ztbp-demo"

# 3. The same pipeline on the real MAS source code (read-only scan)
python integrated_demo\run_demo.py --clean --output "$env:TEMP\ztbp-demo" `
    --banking-repo D:\Lab\Citi_P3 --scanner-graph

# 4. All host test suites
$env:TASK4_ROOT = "$PWD\zero_trust_pdp_task4_secure"
foreach ($s in "zero_trust_psl", "zero_trust_pdp_task4_secure", "zero_trust_task2",
               "Zero_Trust_Task3_PEP_Integrated\zero_trust_pep_task3_integrated", "zero_trust_task5",
               "interface_standard", "integrated_demo", "native_mas_runtime",
               "distributed_runtime\tests\unit") {
    python -m pytest $s
    if ($LASTEXITCODE -ne 0) { Write-Host "FAILED: $s" -ForegroundColor Red }
}
```

Steps 2 and 3 end with:

```text
ALL TASKS 1-5 INTEGRATED: PASS
```

> **Always pass `--output`.** Without it the demo writes to `integrated_demo/output/`, which is
> a committed snapshot of an earlier Task 6 run. `--clean` would delete and regenerate it.

---

## 5. Integrated demo (Tasks 1–6)

`integrated_demo/run_demo.py` runs the whole pipeline in one process:

1. Task 1 model.
2. Task 2 scan.
3. Reconciliation.
4. Graph merge.
5. Task 3 PEPs.
6. Task 4 PDP (in-process, signed decisions).
7. Task 5 lease scenarios.
8. Optionally: real tools, real writes, the three Task 6 workflows.

It is a **harness**: the script itself calls the PEP/PDP/lease chain and the original Citi tools,
in an order it decides. Enforcement *inside* the running MAS is covered by §6 and §7.

### 5.1 Modes at a glance

| mode | flags | MAS needed | what runs | what it writes |
|---|---|---|---|---|
| 1 | (none) | no | bundled sample system, 10-edge baseline graph, lease scenarios A–G | output folder only |
| 2 | `--banking-repo PATH --scanner-graph` | yes | real scan (100 edges), PEPs for the real graph, scenarios A–G | output folder only |
| 3 | mode 2 + `--execute-real-tools` | yes | + one real read tool per office | MAS tool database (created and seeded if missing) |
| 4 | mode 3 + `--execute-real-writes` | yes + backend | + real transfer (backend) and real ledger update | MAS backend database + MAS tool database |
| Task 6 | `--banking-repo PATH --task6-real-workflows` | yes | three representative workflows + security checks | MAS tool database (+ backend database with `--task6-external-backend`) |

**Run modes 3, 4 and Task 6 on a copy of the MAS.** The MAS repository tracks its databases in
git. In the current MAS the tools write `citi_banking_adk_mlflow_observability\bank_adk\.runtime\banking.db`
and the backend writes `citi_banking_backend\data\citi_banking.db`. To make a disposable copy:

```powershell
# clean copy of the MAS source: no .env, no .venv, no databases, no caches
python distributed_runtime\scripts\stage_mas.py --src D:\Lab\Citi_P3
Copy-Item -Recurse distributed_runtime\runtime\build\Citi_P3 "$env:TEMP\Citi_P3_demo"
```

* `stage_mas.py` only reads the MAS. It writes the copy to `distributed_runtime\runtime\build\Citi_P3`,
  the git-ignored build input of the Docker images.
* Copy it elsewhere before running the demo, so demo databases don't end up in the images.
* In the copy, the tools create and seed their databases on first use.

### 5.2 Mode 1: self-test without the MAS

```powershell
python integrated_demo\run_demo.py --clean --output "$env:TEMP\ztbp-demo"
```

Uses the bundled sample system `integrated_demo/sample_banking_system/` and the 10-edge baseline
graph. It shows that the packages and the Task 1–5 chain work on your machine.

### 5.3 Mode 2: scan the real MAS

```powershell
python integrated_demo\run_demo.py --clean --output "$env:TEMP\ztbp-demo" `
    --banking-repo D:\Lab\Citi_P3 --scanner-graph
```

Steps:

1. Scan the MAS source.
2. Reconcile runtime names with canonical IDs.
3. Replace the baseline graph with the discovered one.
4. Generate PEPs for it.
5. Run the Task 4/5 scenarios.

No MAS tool is executed and nothing in the MAS is written.

Current result on the MAS (excerpt):

```text
Discovery summary: agents=40, tools=31, apis=24, databases=6, events=2, edges=100, unresolved=0
Reconciled runtime bindings: 6 verified; unified manifest VALID
  agent.front_office.fraud: fraud_agent -> fraud_detection_agent
  interface.mcp.ledger_update: ledger_update -> apply_ledger_updates
  ...
"interaction_edges_total": 100, "sensitive_interaction_edges": 100, "protected_sensitive_edges": 100,
"logical_pep_count": 100, "physical_pep_count": 9, "deduplicated_component_savings": 91
Task 3 / Task 4 registry compatibility: True
Task 4 PDP healthy: policy_version=67fc6558b6488566, identities=63, resources=84
A. Fraud read: ALLOW; data masking applied -> {... 'full_account_number': '***MASKED***', 'ssn': '***MASKED***' ...}
B. Exact retry during PDP timeout: ACTIVE_LEASE via CACHE
C. Modified request during PDP timeout: DENIED (PDP_TIMEOUT_NO_VALID_LEASE)
D. After PEP restart with PDP down: DENIED (PDP_TIMEOUT_NO_VALID_LEASE)
E. Critical ledger write without approvals: DENIED; Task 4 decision=MANUAL_REVIEW
F. Critical ledger write with approvals: ALLOW -> {'status': 'executed', 'operation': 'ledger'}
G. Critical retry with PDP down: DENIED (PDP_TIMEOUT_INVALID_LEASE:Single-use or bounded-use Permit Lease was replayed)
Task 5 hash-chained audit valid: True; events=7
ALL TASKS 1-5 INTEGRATED: PASS
```

Scenarios E–G use a Task 5 fixture callback, not the real ledger tool. The real tools run in
modes 3–4.

### 5.4 Mode 3: real read tools of the three offices

```powershell
python integrated_demo\run_demo.py --clean --output "$env:TEMP\ztbp-demo" `
    --banking-repo "$env:TEMP\Citi_P3_demo" --scanner-graph --execute-real-tools
```

Runs one original read tool per office behind the generated PEP, the PDP and a Permit Lease:

```text
front_office: REAL TOOL get_transaction_context -> ALLOW -> {...}
mid_office: REAL TOOL get_customer_financial_profile -> ALLOW -> {...}
back_office: REAL TOOL get_eod_batch -> ALLOW -> {...}
```

The inputs (`TXN-1001`, `CUST-001`, `EOD-2026-04-21-CLEAN`) are in
`integrated_demo/testbed_inputs.yaml`. To use your own file, pass `--testbed-inputs FILE`.

### 5.5 Mode 4: real protected writes

Mode 4 adds a real `execute_transfer` through the Citi FastAPI backend and a real
`apply_ledger_updates`. The backend has its own pinned dependencies, so give it its own
environment. In a **second** PowerShell window:

```powershell
cd "$env:TEMP\Citi_P3_demo\citi_banking_backend"
py -3.11 -m venv .venv-backend
.\.venv-backend\Scripts\python.exe -m pip install -r requirements.txt
.\.venv-backend\Scripts\python.exe scripts\init_db.py          # creates and seeds data\citi_banking.db
.\.venv-backend\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Keep it running. In the first window:

```powershell
python integrated_demo\run_demo.py --clean --output "$env:TEMP\ztbp-demo" `
    --banking-repo "$env:TEMP\Citi_P3_demo" --scanner-graph --execute-real-tools --execute-real-writes
```

The demo checks `http://127.0.0.1:8000/health` first. Expected:

```text
front_office_transfer: REAL WRITE execute_transfer -> ALLOW + EXECUTED -> {'transaction_id': 'TXN-...', 'status': 'posted', ...}
back_office_ledger_update: REAL WRITE apply_ledger_updates -> ALLOW + EXECUTED -> {'batch_id': 'EOD-2026-04-21-CLEAN', 'status': 'ledger_updated', ...}
ALL TASKS 1-5 INTEGRATED: PASS
```

* **Another port:** if port 8000 is taken, start uvicorn on another port and pass
  `--banking-backend-url http://127.0.0.1:PORT`, or set `BANKING_BACKEND_BASE_URL`.
* **Write parameters:** they are in `integrated_demo/real_write_inputs.yaml`: a small synthetic
  transfer and the EOD batch, with approval and change-management context. To use your own file,
  pass `--real-write-inputs FILE`.
* **The writes are real.** `--clean` only clears the Backplane output folder, never the testbed
  databases.

### 5.6 Task 6: three real workflows

```powershell
python integrated_demo\run_demo.py --clean --output "$env:TEMP\ztbp-demo" `
    --banking-repo "$env:TEMP\Citi_P3_demo" --task6-real-workflows
```

| workflow | path |
|---|---|
| customer transaction | customer-service workflow -> `transaction_processing_agent` -> `execute_transfer` |
| fraud and compliance | transaction monitoring -> fraud detection -> compliance -> decision |
| back-office EOD | validation -> EOD processing -> ledger update -> reconciliation -> report / exception |

Security checks that run in the same pass:

* unauthorized transfer blocked;
* unauthorized ledger update blocked;
* shadow mode reports `would_block` while a safe read continues;
* a direct call to a protected tool (bypassing the PEP) is blocked;
* audit completeness;
* one `trace_id` from end to end.

Expected:

```text
Task 6 workload identities: PASS (12 workflow agents checked)
customer_transaction: PASS mode=enforce ...
fraud_compliance: PASS mode=enforce ...
back_office_eod: PASS mode=enforce ...
Task 6 security check unauthorized_transfer_blocked: PASS
Task 6 security check unauthorized_ledger_update_blocked: PASS
Task 6 security check shadow_mode_would_block_but_safe_read_continues: PASS
Task 6 security check direct_protected_tool_bypass_blocked: PASS
Task 6 audit completeness: PASS (23 sensitive records)
Task 6 end-to-end trace correlation: PASS
ALL TASKS 1-6 INTEGRATED: PASS
```

* **Live backend:** add `--task6-external-backend` to run the transfer through the live backend
  (start it as in §5.5). Without the flag, the original tool implementation runs locally against
  the MAS tool database.
* **Inputs:** they are in `integrated_demo/task6_workflows.yaml`; pass `--task6-inputs FILE` to use
  your own.
* **Shadow mode:** `--task6-mode shadow` records what would be blocked without blocking it.
* **More detail:** `integrated_demo/README.md` and `integrated_demo/TASK6_IMPLEMENTATION_REPORT.md`.

### 5.7 All options

| option | meaning |
|---|---|
| `--banking-repo PATH` | MAS source tree scanned by Task 2. Default: the bundled sample system |
| `--output PATH` | output folder. Default: `integrated_demo/output` (a committed snapshot; see §4) |
| `--clean` | delete the output folder first |
| `--scanner-graph` | replace the 10-edge baseline graph with the graph Task 2 discovered |
| `--execute-real-tools` | run the original read tools after authorization (implies `--scanner-graph`) |
| `--testbed-inputs FILE` | parameters for the real read tools |
| `--execute-real-writes` | run the protected real transfer and ledger update (backend must be running) |
| `--real-write-inputs FILE` | parameters for the real writes |
| `--banking-backend-url URL` | backend URL. Default: `BANKING_BACKEND_BASE_URL`, else `http://127.0.0.1:8000` |
| `--task6-real-workflows` | run the three Task 6 workflows (implies `--scanner-graph`) |
| `--task6-external-backend` | Task 6 transfer through the live backend |
| `--task6-inputs FILE` | Task 6 inputs |
| `--task6-mode enforce\|shadow` | Task 6 enforcement mode (default `enforce`) |

`python integrated_demo\run_demo.py -h` prints the same list.

### 5.8 Reading the output

| line | meaning |
|---|---|
| `Task 1 inventory: 29 agents, 28 tools, 78 interaction edges` / `Unified interface baseline: VALID` | the Task 1 model loaded and the baseline manifest is valid |
| `Discovery summary: agents=40, ... edges=100, unresolved=0` | Task 2 found these components in the source. `unresolved` counts interfaces it could not resolve |
| `Reconciled runtime bindings: 6 verified` | canonical IDs (used by policies) are bound to the real names in the MAS |
| `scanner_edges_merged: 100` | Task 3 now works on the discovered graph, not the baseline fixture |
| `sensitive_path_coverage_percent: 100.0` | every sensitive edge **in the merged graph** has a PEP (see §10.2 for what this does and doesn't claim) |
| `logical_pep_count: 100`, `physical_pep_count: 9` | 100 required enforcement points, served by 9 shared components |
| `Task 3 / Task 4 registry compatibility: True` | every generated PEP identity/resource is known to the PDP |
| scenario A | an allow can carry obligations, here data masking |
| scenario B | an exact retry may reuse a still-valid lease while the PDP is unreachable |
| scenarios C, D | a modified request, or a restarted PEP, gets no decision and fails closed |
| scenarios E, F | a critical write needs signed human approval and a secondary authorization |
| scenario G | a single-use lease cannot be replayed |
| `REAL TOOL ... -> ALLOW` / `REAL WRITE ... -> ALLOW + EXECUTED` | the original Citi code ran only after authorization |
| `Task 5 hash-chained audit valid: True` | the audit events form an intact hash chain |
| `ALL TASKS 1-5 INTEGRATED: PASS` (or `1-6` with Task 6) | every scenario enabled in this run passed |

### 5.9 Output files

| file | content |
|---|---|
| `task2/` | scanner drafts, coverage and unresolved-interface reports |
| `task1_task2_reconciliation.json` | canonical ↔ runtime binding check |
| `task2_scanner_graph_merge.json`, `reconciled_manifest.yaml` | merged unified manifest used by Task 3 |
| `task3_generated/` | PEP plan, adapters, coverage report, registry artifacts |
| `task4_config/`, `task4_policy_store/` | PDP registries and the signed policy store used in this run |
| `task4_decision_log.jsonl`, `task4_policy_versions.json` | PDP decisions, policy-version record |
| `task5_audit.json` | Task 5 hash-chained audit |
| `task6/task6_report.json`, `task6/task6_workflow_audit.jsonl` | Task 6 results and per-step audit |
| `demo_summary.json` | machine-readable pass/fail summary |

---

## 6. Native runtime: protect the MAS while it runs

Here the Backplane runs **inside** the real MAS process. An ADK plugin in the MAS calls the
`NativeMasBackplane` engine (`native_mas_runtime/engine.py`) at every lifecycle hook:

* CLI input;
* every agent hand-off (`transfer_to_agent`);
* every tool call;
* the final output.

A real LLM decides the routing, the original agents and tools run, and each hop is authorized by
the PDP and a Permit Lease.

### 6.1 Prerequisites

* Both repositories as siblings (§3.2), or `--zt-backplane-root` / `CITI_ZT_BACKPLANE_ROOT`.
* The MAS's own virtual environment in `D:\Lab\Citi_P3\citi_banking_adk`, with its requirements.
  - The Backplane packages don't need to be installed there: the plugin puts the Backplane source
    folders (Tasks 3–5, interface, PSL) on `sys.path` itself.
  - If an import of `cryptography`, `PyYAML` or similar fails, install that library into the MAS
    environment.
* A working LLM endpoint in the MAS's `.env`. Every run makes real LLM calls.

### 6.2 Run

From the MAS folder, with the MAS environment active:

```powershell
cd D:\Lab\Citi_P3\citi_banking_adk
python run_cli.py --message "What is the bank's policy on a lost debit card?" --zt-status
```

Zero Trust is on by default. `--zt-status` adds the following to the result:

* `trace_id`;
* `workflow_instance_id`;
* the audit file path;
* the policy version.

A critical write with the approvals the policies require:

```powershell
python run_cli.py `
    --message "Please run the scheduled end-of-day batch processing for batch EOD-2026-04-21-CLEAN, including posting the ledger update." `
    --zt-human-approval --zt-secondary-authorization --zt-change-ticket "CHG-1234" --zt-status
```

Without the approval flags, the ledger update is held at the PDP (`MANUAL_REVIEW`) and not
executed.

**When an allowed critical write runs, it really writes** to the MAS database
`citi_banking_adk\bank_adk\.runtime\banking.db`, which the MAS repository tracks in git.

Automated live check (5 scenarios, real LLM, about 2–4 minutes):

```powershell
python verify_native_zero_trust_e2e.py                      # all scenarios
python verify_native_zero_trust_e2e.py --skip-critical-writes # skip the two that write the database
```

### 6.3 Flags of `run_cli.py`

| flag | default | meaning |
|---|---|---|
| `--message TEXT` | required | the user message |
| `--no-zero-trust` | Zero Trust on | switch enforcement off (local comparison only) |
| `--zt-backplane-root PATH` | sibling folder | Backplane location |
| `--zt-output PATH` | `<backplane>\native_mas_runtime\output` | where generated artifacts and audit logs go |
| `--zt-mode enforce\|shadow` | `enforce` | `shadow` records what would be blocked without blocking |
| `--zt-refresh` | off | rescan the MAS source before this run (use after changing agent/tool code) |
| `--zt-human-approval` | off | supply a signed human approval for critical operations |
| `--zt-secondary-authorization` | off | supply the independent second authorization |
| `--zt-change-ticket ID` | none | satisfies the change-ticket obligation of critical writes |
| `--zt-shadow-allow-critical` | off | in shadow mode, also simulate allowing critical writes |
| `--zt-status` | off | print trace and policy metadata |
| `--raw` | off | print the raw ADK event stream |

The authoritative description of this mode is in the MAS repository:
`citi_banking_adk/NATIVE_ZERO_TRUST_README.md`. It covers the nine ADK hooks, shadow mode, the
latency benchmark (`latency_benchmark.py`) and the mocked-plugin tests (`tests_native_zt/`).

### 6.4 What a native run produces

The bootstrap at the start of every run regenerates the output folder (default
`native_mas_runtime/output/`). The Task 2 scan is the exception: it is reused from the cache
(§6.5).

| file / folder | content |
|---|---|
| `native_mas_audit.jsonl` | every authorization of the run: input, agent route, tool, output. **Truncated at the start of every run.** Filter by `trace_id` |
| `task4_decision_log.jsonl` | PDP decisions (hash chain) |
| `native_runtime_summary.json` | bootstrap summary: logical PEPs (105), physical PEPs (12), mode, policy version |
| `task2/` | cached scan of the MAS, with `scan_fingerprint.json` |
| `task3_generated/`, `task4_config/` | PEP plan and PDP registries for the 105 placements of the real MAS |
| `task4_policy_store/` | copy of the signed policy store + generated `native_mas_runtime.psl` (least-privilege permissions for every placement) |

`native_mas_runtime/output/` is committed as a reference snapshot. Pass `--zt-output` to a
different folder if you don't want a run to change it.

### 6.5 Scan cache, domains, policy changes

* **Scan cache.** The Task 2 scan is cached in `<output>/task2`. It is rescanned automatically
  when the scanner (`zt_scan.py`) or the MAS root changes; this is what `scan_fingerprint.json`
  records. After editing MAS agent or tool code, pass `--zt-refresh`.
* **Agent domains** (front/mid/back office) come from the scanner:
  * the source path, or
  * for factory-built workflow agents, the office of the router that attaches them.

  The cross-domain intent rule depends on them; see `zero_trust_task2/README.md`.
* **Policy changes.** Every run copies `zero_trust_pdp_task4_secure/policy_store` again, so a
  re-signed policy change applies on the next run.

### 6.6 Without an LLM

`python -m pytest native_mas_runtime` bootstraps the engine on the real MAS (scan, PEPs, PDP, PSL
store) and checks the decisions on the real agent tree. No LLM is called and nothing is written
to the MAS.

### 6.7 Limit

All agents share one process, hence one workload identity. The agent layer of SPIFFE scheme B
cannot tell agents apart there. Native requests carry no authentication block, so
`identity.psl` (§9) doesn't apply to them. Per-agent identities need the distributed runtime.

---

## 7. Distributed runtime

The Citi-specific distributed runtime described here before was replaced by the generic one
(any ADK application, one container per agent, SPIFFE scheme B). See the main
[README](../README.md#5-distributed-runtime) and [distributed_runtime/README.md](../distributed_runtime/README.md);
Citi P3 runs through it with [profiles/citi_p3](../profiles/citi_p3/zt_adk.yaml).

---

## 8. Policies (PSL): read, change, add, sign

### 8.1 Where the policies are

All policies are in the signed store `zero_trust_pdp_task4_secure/policy_store/`. Each file has a
detached Ed25519 signature `NAME.sig.json`, and the store is verified before it is loaded.

| file | policy set | content |
|---|---|---|
| `core.psl` | `core` | critical writes need human approval + secondary authorization (formerly hard-coded in the engine) |
| `front_office.psl`, `mid_office.psl`, `back_office.psl`, `ledger_access.psl`, `tool_access.psl` | `bundle.*` | the Task 4 policies, translated from the YAML bundles kept in `legacy_policy_store/` |
| `identity.psl` | `identity` | the PDP's re-check of SPIFFE scheme B authentication (§9) |
| `intent.psl` | `intent.*` | **generated** from the Task 1 natural-language rules (§8.6). Don't edit by hand |
| `gateway_runtime.psl` | `gateway.runtime*` | tool-path monitors P1–P6 of the distributed gateway |
| `policy_fields.yaml` | — | field catalogue: every field a rule may use, its type and its trusted source |

The native runtime adds a generated `native_mas_runtime.psl` to its own copy of the store (§6.4).
`docs/PSL_POLICY_RULES.md` lists every rule.

### 8.2 How a decision is made (deny-overrides)

1. **Structural checks first.** An unknown subject or resource, or an undefined action, is denied.
2. **Default deny.** The request needs at least one `@permit` rule that holds.
3. **Constraints.** Every other rule must hold. Each violated rule contributes its
   `@on_violation` outcome; the strictest one decides:
   **DENY > REAUTHENTICATE > MANUAL_REVIEW**.
4. **Outcome.** If nothing is violated, the result is **ALLOW**, or **ALLOW_WITH_OBLIGATIONS**
   with the union of the obligations of the permissions that hold.

There are no priorities, so **adding a rule can only make decisions stricter**. A rule with
`@on_violation FLAG` never blocks; when it is violated, it adds the obligation
`anomaly_flag(rule=ID)`.

### 8.3 Anatomy of a rule

Excerpt from `tool_access.psl` (other rules of the file omitted):

```psl
// @policy_set bundle.tool_access
// @version 2.0.0
// @source legacy_policy_store/tool_access.yaml
vunit tool_access (pdp_request) {

  // @rule policy.tool.transfer_approved
  // @nl A transfer may proceed only when approval and secondary authorization are signed and request-bound.
  // @permit
  // @obligation enhanced_logging(reason=financial_write)
  // @obligation require_idempotency_key
  // @obligation independent_resource_audit
  property transfer_approved =
      subject.id == "agent.front_office.transaction_processing"
      && resource.id == "resource.front_office.banking_transfer"
      && action == "execute"
      && workflow.id == "workflow.front_office.customer_transaction";

  // @rule policy.tool.transfer_pending_review
  // @nl Transfer execution is blocked until signed approval and independent authorization are present.
  // @on_violation MANUAL_REVIEW
  transfer_pending_review: assert always (authz_request
      && subject.id == "agent.front_office.transaction_processing"
      && resource.id == "resource.front_office.banking_transfer"
      && action == "execute"
      && workflow.id == "workflow.front_office.customer_transaction"
      -> approval.valid && approval.secondary_valid);
}
```

How to read it:

* `vunit NAME (SCOPE)` groups the rules and names the scope that evaluates them (§8.4).
* `@rule` is the stable rule ID. It appears in decisions, the audit log and the reports.
* `transfer_approved` is a **permission** (`@permit`). When it holds, its obligations are
  attached.
* `transfer_pending_review` is a **constraint**. Read it as: for every request that matches the
  part before `->`, the part after `->` must hold, otherwise the outcome is `MANUAL_REVIEW`.
* Together they say: the transfer is permitted in this workflow, but it is held for review until
  both approvals are valid.

Syntax summary:

* **Permissions** are `property NAME = <Boolean>;` with `@permit`.
* **Constraints** are `LABEL: assert always (authz_request && <when> -> <must hold>);` or
  `LABEL: assert never (authz_request && <forbidden>);`.
* **Operators:** `&&`, `||`, `!`, `->`, and comparisons `== != < <= > >=` against strings,
  integers, `true` / `false`.
* **Annotations:** `@rule`, `@nl`, `@source`, `@on_violation`, `@permit`,
  `@obligation TYPE(k=v)`, `@runtime`, `@note`, `@disabled`. On the vunit: `@policy_set` and
  `@version`, both required.
* **`@on_violation` values:** `DENY` (the default), `REAUTHENTICATE`, `MANUAL_REVIEW` or `FLAG`.
* **Errors are explicit.** Unknown fields, type errors, unknown annotations and unsupported PSL
  are compile errors with file:line:col.
* **Language reference:** `zero_trust_psl/docs/PSL_SUPPORTED_SUBSET.md` (§8 there covers the
  policy layer).

### 8.4 Scopes and fields

| scope | kind | evaluated by |
|---|---|---|
| `pdp_request` | request | the PDP, for every authorization (default deny) |
| `gateway_input`, `gateway_output`, `gateway_tool` | request, check only | the distributed gateway, on every ingress message / response / tool call |
| `workflow_run` | temporal | workflow monitors of the native runtime and the gateway (authorize / begin_tool / finish_tool) |
| `request_attempt`, `operation`, `workflow_batch`, `workflow_participation` | temporal | gateway tool-path monitors (`gateway_runtime.psl`) |
| `harness_output` | request, check only | evaluation harness expectations |

A rule may only use fields that `policy_fields.yaml` declares for its scope.

* **`pdp_request` examples:**
  * `subject.id`, `subject.runtime_id`, `subject.domain`, `subject.role.*`;
  * `resource.id`, `resource.runtime_id`, `resource.critical`, `resource.target_type`;
  * `action`, `workflow.id`, `risk.level`, `risk.score`, `auth.strength`;
  * `approval.valid`, `approval.secondary_valid`;
  * `auth.scheme`, `auth.factor.*`, `auth.agent_bound`;
  * `time.in.business_hours_new_york`;
  * argument checks `args.*`;
  * `request.cross_domain`.
* **Trusted sources only.** Every field names its source: the PEP-signed request, signed evidence
  assertions, the registries, trusted checkers, or events the runtime observed itself. Agent
  session state is LLM output and is never a source.
* **Adding a field** therefore means adding code that computes it from a trusted source, plus the
  catalogue entry.

### 8.5 Change or add a rule: step by step

Example: ledger updates outside New York business hours go to manual review.

1. **Write the rule.** Edit an existing file, or create a new file in the store, for example
   `zero_trust_pdp_task4_secure\policy_store\ledger_hours.psl`:

   ```psl
   // Ledger updates outside business hours go to manual review.

   // @policy_set example.ledger_hours
   // @version 1.0.0
   vunit example_ledger_hours (pdp_request) {

     // @rule policy.example.ledger_update_business_hours
     // @nl Ledger updates outside New York business hours need manual review.
     // @on_violation MANUAL_REVIEW
     ledger_update_business_hours: assert always (authz_request
         && resource.id == "resource.back_office.ledger" && action == "update"
         -> time.in.business_hours_new_york);
   }
   ```

   If you change an existing file, raise its `@version`. The PDP records the versions it loaded
   and rejects a lower one (rollback protection).

2. **Compile and list the rules:**

   ```powershell
   $store = "zero_trust_pdp_task4_secure\policy_store"
   zt-psl check --catalog "$store\policy_fields.yaml" (Get-ChildItem "$store\*.psl").FullName
   ```
   ```text
   constraint   MANUAL_REVIEW   policy.example.ledger_update_business_hours  [ledger_hours.psl:10]
   ...
   69 rules, source sha256 ...
   ```

   PowerShell does not expand `*.psl` for external programs, hence `(Get-ChildItem ...).FullName`.
   A mistake fails here with its location, for example
   `error: tool_access.psl:12:3 property knowledge_search: unknown field 'subject.name' in scope pdp_request`.

3. **Sign.** Either sign just the file you changed:

   ```powershell
   zt-psl sign --key zero_trust_pdp_task4_secure\security\dev_keys\policy_private.pem "$store\ledger_hours.psl"
   ```

   or re-sign the whole store with `python zero_trust_pdp_task4_secure\scripts\sign_psl_policies.py`.
   This rewrites every `.sig.json` with a new timestamp; commit only those of the files you
   changed.

4. **Verify the store as the PDP will load it:**

   ```powershell
   python zero_trust_pdp_task4_secure\scripts\sign_psl_policies.py --check
   ```
   ```text
   verified and compiled 11 files, 34 rules, policy version ...
   ```

   An unsigned or modified file fails here:

   * `missing signature sidecar for ledger_hours.psl`
   * `policy file changed after signing: ledger_hours.psl`

5. **Test and measure the effect:**
   * run the PDP tests: `python -m pytest zero_trust_pdp_task4_secure`;
   * run the differential report (§8.8). It lists every decision that changed and the rule that
     changed it.

6. **Use it:**

   | runtime | when the change applies |
   |---|---|
   | integrated demo | the next run |
   | native runtime | the next run |
   | distributed runtime | after `build`, `prepare`, `start` |

### 8.6 Natural-language rules → PSL

The Task 1 rules in `zero_trust_task1/manifest/policy_intent.yaml` are written in a controlled
natural language. `zt-psl intent` translates them deterministically into `policy_store/intent.psl`,
keeping each rule's text (`@nl`) and origin (`@source`).

Rule in `policy_intent.yaml` (excerpt):

```yaml
  - rule_id: no-cross-domain-transfers
    description: >
      No agent may transfer control across domain boundaries (front→back,
      mid→front, etc.) without going through user_proxy_agent.
    subject: "*"
    resource: transfer_target
    action: transfer
    conditions:
      - NOT (transfer.from_domain != transfer.to_domain AND transfer.from_agent != user_proxy_agent)
    decision: allow
    obligations:
      - audit_log
    on_condition_fail: deny
```

Generated PSL in `intent.psl` (`@nl` shortened):

```psl
  // @rule intent.no-cross-domain-transfers
  // @nl No agent may transfer control across domain boundaries (front→back, mid→front, etc.) without going through user_proxy_agent. ...
  // @source zero_trust_task1/manifest/policy_intent.yaml#no-cross-domain-transfers
  // @obligation audit_log
  intent_no_cross_domain_transfers: assert always (authz_request && resource.target_type == "subject"
      -> !(request.cross_domain && subject.runtime_id != "user_proxy_agent"));
```

**Grammar.** Conditions use a controlled grammar:

* `X is present`;
* `==` / `!=`;
* `in [...]`;
* `NOT ( ... AND ... )`;
* `len(X) >= n`;
* `X does not match pattern P`;
* ...

**Bindings.** Every subject, resource, field and phrase a rule uses must be bound in
`zero_trust_task1/manifest/policy_intent_bindings.yaml`; anything unbound is an error, and nothing
is guessed.

**Session state.** Conditions on agent session state (`session_state.*`) are LLM output, so they
are not trusted. They are bound to trusted facts instead:

* events the runtime observed itself, as temporal `workflow_run` rules (for example, "the
  customer-service step ran before `execute_transfer`");
* or the request's own hash-bound arguments.

After changing `policy_intent.yaml` or the bindings:

```powershell
zt-psl intent `
    --intent zero_trust_task1\manifest\policy_intent.yaml `
    --bindings zero_trust_task1\manifest\policy_intent_bindings.yaml `
    --catalog zero_trust_pdp_task4_secure\policy_store\policy_fields.yaml `
    --source-label zero_trust_task1/manifest/policy_intent.yaml `
    --out zero_trust_pdp_task4_secure\policy_store\intent.psl `
    --report docs\PSL_INTENT_TRANSLATION.md
```
```text
24 intent rules -> 28 PSL rules (0 disabled, 1 realized by other rules); wrote ...intent.psl
```

Then sign `intent.psl` (§8.5, step 3) and run the consistency check (§8.8). The check evaluates
every request intent rule against every legitimate route and tool edge of the real MAS (105
placements). It must report **0 conflicts**; otherwise the rule would refuse something the
deployed MAS does.

**To switch an intent rule off** without deleting it, list it with its reason in the bindings:

```yaml
disabled:
  no-cross-domain-transfers: >
    Why it is disabled, and what has to change before it can be enabled again.
```

The rule is still translated and compiled, but it is marked `@disabled` and no runtime evaluates
it. The reason appears in the translation report and in `docs/PSL_POLICY_RULES.md`. The
consistency check still evaluates disabled rules, so it shows when one can be enabled again. All
24 rules are enabled at present.

### 8.7 `zt-psl` command reference

| command | purpose |
|---|---|
| `zt-psl check --catalog CATALOG FILE...` | compile; print every rule (kind, outcome, id, file:line). Exit 1 on any error |
| `zt-psl describe --catalog CATALOG --out RULES.md [--title T] FILE...` | write a Markdown description of every rule (this is how `docs/PSL_POLICY_RULES.md` is made) |
| `zt-psl sign --key PRIVATE.pem [--issuer I --key-id K] FILE...` | write `NAME.sig.json` next to each file. Defaults: issuer `policy.prototype`, key id `policy-1` |
| `zt-psl verify --pub PUBLIC.pem [--issuer I --key-id K] FILE...` | verify signatures (`ok` / `INVALID`) |
| `zt-psl intent --intent YAML --bindings YAML --catalog CATALOG --out FILE.psl [--report MD] [--source-label L]` | translate natural-language rules (§8.6); the output must compile or nothing is written |

**Try a decision in Python** without starting the PDP. This evaluates only the policy layer; the
PDP's signature, evidence and registry checks are not involved:

```python
from pathlib import Path
from zt_psl import load_policy_set, RequestPolicyEngine

store = Path("zero_trust_pdp_task4_secure/policy_store")
policy_set = load_policy_set(sorted(store.glob("*.psl")), store / "policy_fields.yaml")
engine = RequestPolicyEngine(policy_set)                  # scope pdp_request, runtime pdp
scope = policy_set.catalog.scopes["pdp_request"]

# every field in engine.fields_needed must be supplied (a missing one raises UnboundField)
EMPTY = {"string": "", "int": 0, "bool": False}
fields = {f: EMPTY.get(scope.spec(f).type, "low") for f in engine.fields_needed}
fields.update({"subject.id": "agent.front_office.transaction_processing",
               "subject.runtime_id": "transaction_processing_agent",
               "resource.id": "resource.front_office.banking_transfer",
               "resource.runtime_id": "banking_transfer", "resource.critical": True,
               "action": "execute", "workflow.id": "workflow.front_office.customer_transaction",
               "args.well_formed": True, "args.source_account.nonempty": True,
               "args.destination_account.nonempty": True, "args.amount.finite_nonzero": True})

d = engine.decide(fields)
print(d.outcome, [r.rule_id for r in d.violated])
# MANUAL_REVIEW ['core.critical_write_requires_dual_approval', 'policy.tool.transfer_pending_review']

fields.update({"approval.valid": True, "approval.secondary_valid": True})
d = engine.decide(fields)
print(d.outcome, [o.type for o in d.obligations])
# ALLOW_WITH_OBLIGATIONS ['enhanced_logging', 'require_idempotency_key', 'independent_resource_audit',
#                         'audit_log', 'emit_financial_event']
```

`load_policy_set` compiles the files but does not check their signatures. The PDP loads the store
through `zt_backplane.psl_policy.PslPolicyStore`, which verifies every signature first.

### 8.8 Reports and evidence

Run these from the Backplane root:

```powershell
$scripts = "zero_trust_pdp_task4_secure\scripts"
python "$scripts\psl_differential_report.py"                                        # ~1.5 min
python "$scripts\psl_native_differential.py" --native-out native_mas_runtime\output  # ~2.5 min
python "$scripts\psl_intent_consistency.py"  --native-out native_mas_runtime\output  # < 1 s
python "$scripts\psl_performance_report.py"  --native-out native_mas_runtime\output
```

| script | what it shows | writes |
|---|---|---|
| `psl_differential_report.py` | legacy YAML engine vs PSL engine on 552,960 requests (cross product of identities, resources, actions, workflows, risk, auth strength, approvals, business hours); every differing decision with its rule | `docs/PSL_DIFFERENTIAL_REPORT.md`, `docs/psl_differential_task4.json` |
| `psl_native_differential.py` | the same for the native runtime's store (582,400 requests), including added and removed obligations | `docs/PSL_NATIVE_DIFFERENTIAL_REPORT.md`, `docs/psl_differential_native.json` |
| `psl_intent_consistency.py` | intent rules vs the 105 legitimate placements of the real MAS | `docs/PSL_INTENT_CONSISTENCY.md` |
| `psl_performance_report.py` (`--rounds N`, default 3) | decision latency, legacy vs PSL | `docs/PSL_PERFORMANCE_REPORT.md`, `docs/psl_performance.json` |

* **Output files.** Each script overwrites the files listed under `docs/`. Pass `--out-md` (and,
  where the script writes JSON, `--out-json`) to write somewhere else.
* **`--native-out`.** It accepts any native bootstrap output folder; the committed
  `native_mas_runtime/output` works.
* `PSL_PERFORMANCE_REPORT.md` ends with a hand-written section on the distributed runtime. The
  script doesn't produce it, so keep it when regenerating the report.

Current results:

* **Translated store vs legacy:** 0 differences.
* **With the intent rules:** 128 decisions stricter, none more permissive.
* **Native store:** 128 decisions differ, none more permissive; obligations are only added.
* **Intent consistency:** 0 conflicts.

### 8.9 Keys

* **Development key only.** The key in `zero_trust_pdp_task4_secure/security/dev_keys/` is
  committed and for development only. Production policies must be signed by a release pipeline
  with a Citi key.
* **Distributed runtime.** It never uses the committed key. `prepare` re-signs the store with a
  freshly generated deployment key that only the gateway can read.

---

## 9. Identity: SPIFFE scheme B

Two independent layers authenticate every hop in the distributed runtime.

* **Workload identity.**
  * An X.509-SVID issued by SPIRE and verified on every connection (mTLS).
  * Selectors: compose label, compose project and a distinct UID per container.
  * SPIFFE IDs: `spiffe://citi-p3.test/ztbp/wl/<agent_id>` for agents,
    `spiffe://citi-p3.test/ztbp/svc/<name>` for services.
* **Agent identity.**
  * An agent certificate from the agent-issuer's own CA (never the SPIRE CA), bound to the
    workload SPIFFE ID.
  * Every request is signed with RFC 9421, with a content digest, a nonce and a replay window.
  * The gateway checks the registry: agent enabled, certificate serial not revoked, workload
    allowed.

The gateway passes the verification result to the PDP inside the IdP-signed authentication
assertion. The PDP **re-checks** it in `policy_store/identity.psl`:

* an agent request is decided only if both factors were verified and the assertion names the
  request's subject;
* a service may use only the MAS input and output channels;
* any other caller is denied.

So a PEP defect cannot turn a partly verified caller into an allowed decision.

Library: `zero_trust_identity/` (package `zt_identity`). Design: `docs/SPIFFE_PSL_DESIGN.md`.
The native runtime has a single process identity and is not covered by this layer (§6.7).

---

## 10. How the protection works

### 10.1 Unified Interface and runtime reconciliation

Policies use stable **canonical IDs**, while the MAS uses its own **runtime names**:

```text
agent.front_office.fraud      <->  fraud_detection_agent
interface.mcp.ledger_update   <->  apply_ledger_updates
```

The reconciliation step (`integrated_demo/reconcile.py`, `scanner_merge.py`,
`task1_unified_bindings.yaml`) keeps the canonical ID as the policy-facing source of truth and
records the real name as its runtime binding. It merges the discovered graph into a copy of the
unified manifest and never rewrites the original Task 1–5 manifests. The PDP checks that a
request's runtime name matches the registry binding of its canonical ID.

### 10.2 Sensitivity and coverage

Task 2 classifies operations with **rule-based heuristics**, not with ML or an LLM:

| pattern | classified as |
|---|---|
| `get_*`, `list_*`, `search_*`, HTTP `GET` | read |
| `execute_*`, `apply_*`, `update_*`, `persist_*`, `store_*`, HTTP `POST` / `PUT` / `PATCH` / `DELETE` | state change |
| transfers, ledger mutations | high-impact state change |
| customer, account and transaction data | PII or sensitive data |

Task 3 treats an edge as sensitive if any of the following holds:

* it crosses a trust boundary;
* its risk is medium/high/critical;
* it has side effects;
* its resource is confidential/restricted/regulated;
* its action is high/critical.

On the current MAS all 100 discovered edges are sensitive and all 100 are protected.

"100% coverage" means **every sensitive edge that the scanner discovered and that is in the merged
manifest**. An interaction the scanner does not discover is outside that denominator. The Task 3
output lists sensitive inventory resources that have no discovered edge
(`sensitive_inventory_resources_without_discovered_edges`).

### 10.3 PEP generation (Task 3)

Logical PEP types:

* input PEP;
* agent-route PEP;
* tool PEP;
* MCP PEP;
* API PEP;
* data PEP;
* event PEP;
* output PEP;
* shared middleware.

Compatible logical PEPs share one physical component. On the current MAS, 100 logical PEPs are
served by 9 physical components.

The native and distributed runtimes add the agent routes that only the instantiated ADK agent
tree shows (for example `user_proxy_agent` -> office routers). That gives 105 placements.

### 10.4 PDP (Task 4)

The PDP evaluates **subject + resource + action + context** and returns:

* ALLOW;
* ALLOW_WITH_OBLIGATIONS (for example masking, enhanced logging, idempotency key);
* MANUAL_REVIEW;
* REAUTHENTICATE;
* DENY.

Hardening:

* **Requests:**
  * every request is signed by a trusted PEP and bound to a `request_hash`;
  * a nonce and a JTI give replay protection.
* **Signed evidence:**
  * risk score (the PDP recomputes the level);
  * authentication factors (the PDP computes the strength);
  * workflow;
  * human approval;
  * secondary authorization.
* **Time:** time rules use the PDP's clock.
* **Policies:** signed, with rollback protection.
* **Decisions:** signed (the signature is in HTTP headers).
* **Audit:** a hash-chained audit log.

The runtimes run the PDP in-process. It can also run as an HTTP service:

```powershell
cd zero_trust_pdp_task4_secure
python -m uvicorn zt_backplane.pdp_service:app --host 127.0.0.1 --port 8080
```

In a second window (environment active), send a signed request and verify the signed decision:

```powershell
cd D:\Lab\Citi_P3_Zero_Trust_Backplane\zero_trust_pdp_task4_secure
$env:PYTHONPATH = "src"; python examples\authorize_demo.py --pdp http://127.0.0.1:8080
```
```text
{... 'decision': 'ALLOW_WITH_OBLIGATIONS', 'reason': 'psl_permit:policy.front_office.fraud_read_transaction_history', ...
 'obligations': [{'type': 'enhanced_logging', ...}, {'type': 'data_masking', 'parameters': {'fields': ['full_account_number', 'ssn']}}], ...}
decision_signature_valid=True
```

* Endpoints: `GET /health`, `POST /v1/challenge`, `POST /v1/authorize`, `POST /v1/admin/reload`
  (disabled by default), Swagger UI at `/docs`.
* Configuration comes from environment variables `ZT_POLICY_DIR`, `ZT_IDENTITY_FILE`,
  `ZT_RESOURCE_FILE`, `ZT_TRUSTED_ISSUERS`, ...; see `zt_backplane/pdp_service.py`.
* More detail: `zero_trust_pdp_task4_secure/README.md`.

### 10.5 Permit Leases (Task 5)

A cached `allow = true` is unsafe: it outlives changes to the request, identity, policy or risk.
Task 5 issues a **Permit Lease** instead. It is signed, short-lived and bound to:

* subject, resource and action;
* the request hash and the workflow ID;
* issue and expiry time;
* the policy, identity and risk versions;
* a maximum number of uses;
* the required obligations.

Consequences:

* **Request binding.** Authorization for "transfer $100 A → B" is useless for "transfer $1000
  A → C", because the request hash differs.
* **PDP timeout.** An exact retry may use a still-valid lease. Anything else fails closed:

  ```text
  NO_DECISION -> WAITING_FOR_PDP -> ALLOW -> ACTIVE_LEASE
                                  -> DENY  -> DENIED
                                  -> TIMEOUT -> valid exact lease ? ACTIVE_LEASE : DENIED
  ```
* **Critical writes** use single-use leases. A replay is rejected.
* **Revocation.** A registry or policy change bumps the corresponding version, which invalidates
  outstanding leases.

---

## 11. Tests

Run from the Backplane root with the environment active (§3.4). The loop in §4 runs all host
suites.

| suite | command | tests | notes |
|---|---|---|---|
| PSL language | `python -m pytest zero_trust_psl` | 143 | parser/subset, compiler vs reference interpreter, field catalogue, decisions, guard index, signing, monitors, intent translator |
| PDP | `python -m pytest zero_trust_pdp_task4_secure` | 36 | policies, security controls, interface compatibility, differential equivalence, SPIFFE identity rule |
| scanner | `python -m pytest zero_trust_task2` | 13 | incl. domain inheritance of factory-built agents |
| PEP generation | `python -m pytest Zero_Trust_Task3_PEP_Integrated\zero_trust_pep_task3_integrated` | 12 | set `$env:TASK4_ROOT = "$PWD\zero_trust_pdp_task4_secure"`, otherwise 2 are skipped |
| Permit Leases | `python -m pytest zero_trust_task5` | 16 | |
| Unified Interface | `python -m pytest interface_standard` | 4 | |
| integrated demo | `python -m pytest integrated_demo` | 5 | |
| native runtime | `python -m pytest native_mas_runtime` | 14 | needs the MAS checkout; bootstraps on the real MAS, no LLM |
| distributed runtime (host) | `python -m pytest distributed_runtime\tests\unit` | 60 | gateway monitors from the signed store, PSL guard, content checks |
| identity | `python -m pytest zero_trust_identity` | 25 | needs `pip install -e zero_trust_identity`; or `ctl.ps1 unit-test` inside the image |
| distributed end to end | `.\distributed_runtime\scripts\ctl.ps1 functional-test` | 15 | needs Docker and `build` + `prepare`; about 6–7 minutes |
| native live (MAS repo) | `python verify_native_zero_trust_e2e.py` in `D:\Lab\Citi_P3\citi_banking_adk` | 5 scenarios | real LLM calls (§6.2) |

What the 15 end-to-end tests cover:

* workload identities and a separate agent CA;
* read;
* transfer through the customer-service path;
* direct transfer refused;
* approval required;
* EOD clean run and EOD with mismatch;
* EOD not ready;
* direct ledger post refused;
* knowledge question;
* three input-rule refusals;
* disable/enable with lease revocation;
* SVID and agent-certificate rotation.

---

## 12. Troubleshooting

| symptom | cause and fix |
|---|---|
| `No module named 'zt_psl'` | `zero_trust_psl` is not installed in the active environment: `python -m pip install -e zero_trust_psl` |
| `No module named 'cryptography'` / `'zt_backplane'` | the Backplane packages are not installed, or another Python is active. Activate `.venv` and repeat §3.4 |
| `requires a different Python: 3.10.x not in '>=3.11'` | create the environment with `py -3.11` |
| `No module named pytest` | `python -m pip install pytest` |
| `No module named 'aiohttp'` / `'http_message_signatures'` (identity tests) | `python -m pip install -e zero_trust_identity` |
| `policy file changed after signing: X.psl` | the file differs from what was signed. If you edited it, re-sign (§8.5). If you didn't, it was probably re-saved with different line endings: restore it with `git checkout -- <file>` |
| `missing signature sidecar for X.psl` | a new or renamed `.psl` file has no `.sig.json`: sign it |
| `policy rollback rejected for SET: A < B` | a policy set's `@version` went down. Raise it. In development you can delete the version record of that run (`zero_trust_pdp_task4_secure/runtime/policy_versions.json`, or `task4_policy_versions.json` in an output folder) |
| `error: FILE:line:col ... unknown field 'x' in scope s` | the field is not in `policy_fields.yaml` for that scope (§8.4) |
| `OSError: [Errno 22] Invalid argument: '...\*.psl'` | PowerShell passed the wildcard literally; use `(Get-ChildItem ...\*.psl).FullName` |
| `Health check failed at http://127.0.0.1:8000/health` | mode 4 needs the MAS backend (§5.5), or pass `--banking-backend-url` |
| `no such table: transactions / customers / eod_batches` | the backend database was not initialised: `scripts\init_db.py` in `citi_banking_backend` |
| the native runtime still uses old agent domains or tools | the scan cache is reused; run once with `--zt-refresh` |
| `git status` shows changes in the MAS (`*.db`) | a mode that writes was run against the MAS itself. Use a copy (§5.1). Restore with `git -C D:\Lab\Citi_P3 checkout -- <db>` only if those changes are not yours |
| `git status` shows changes under `.venv/` or `*.egg-info/` | build artifacts from `pip install -e`; don't commit them (§3.4) |
| `ctl.ps1 build` fails on the SPIRE tarball | download it to `distributed_runtime\deploy\vendor\` (§7.1) |
| `ctl.ps1` cannot reach Docker | start Docker Desktop (Linux containers). For a different engine, set `DOCKER_HOST` |
| containers start but agents are not healthy | run `prepare` again (after `stop --purge` the volumes with keys and SPIRE data are gone), then `start` |
| deprecation warnings (AST, Starlette/httpx) | harmless. The final `PASS` / `FAIL` lines decide |

---

## 13. Project status and limitations

**Status (2026-11-03):**

* Tasks 1–6 are implemented. Task 6 runs in three forms:
  * the integrated demo's representative workflows;
  * the native ADK plugin with a real LLM;
  * the distributed runtime with SPIFFE identities.
* All policies are signed PSL policies, decided deny-overrides. The behaviour changes against the
  legacy engine are listed in the differential reports, and none is more permissive.
* All suites in §11 pass, with one exception: the native live check
  (`verify_native_zero_trust_e2e.py`) needs an LLM key and has not been rerun since the switch to
  PSL. The native engine itself is covered by `native_mas_runtime` tests.

**Evidence collected so far for Task 7 (security and performance evaluation):**

* PDP decision latency, legacy vs PSL: `docs/PSL_PERFORMANCE_REPORT.md`. Same policy content
  ×0.99. Deployed store with the intent and identity rules ×1.59. Native store ×0.33.
* Per-step overhead of a gateway tool call (scheme B authentication ≈ 0.5 ms, PDP round trip
  ≈ 8 ms): same report.
* The MAS-side latency benchmark in the MAS repository.
* The 15 distributed security tests.

**Still open:**

* **Task 7:** the remaining measurements:
  * throughput;
  * revocation propagation;
  * network failure;
  * bypass and spoofing campaigns.
* **Task 8:** final packaging and demonstration.

**Limitations:**

1. **Coverage is discovered-graph coverage.** An interaction the scanner does not find is not
   protected by a generated PEP (§10.2).
2. **Sensitivity is heuristic.** It is rule-based and conservative, not a risk classifier.
3. **The integrated demo is a harness.** Enforcement inside the running MAS is the native runtime
   (§6) and the distributed runtime (§7).
4. **Native runtime: one process identity.** SPIFFE scheme B does not apply there (§6.7).
5. **Distributed runtime: scripted model.** The LLM is replaced by a deterministic model fixture.
   The PDP runs inside the gateway, so there is no separately deployed PDP edge to protect with
   mTLS.
6. **Prototype trust material:**
   * development keys are committed;
   * replay state is held in memory, per PDP process;
   * the audit log is a local file;
   * the independent secondary authorization is represented by signed evidence.

   Production needs Citi-controlled keys, a shared replay store, an append-only audit sink and a
   separate authorization service.
7. **Real-write modes change real state.** Run them on a copy of the MAS (§5.1).

---

## 14. Repository layout

```text
Citi_P3_Zero_Trust_Backplane/
├── README.md
├── .gitattributes                  signed / hash-pinned files are checked out byte-exact
├── zero_trust_task1/               system model, ZT-IR, manifest/policy_intent.yaml (+ _bindings.yaml)
├── interface_standard/             Unified Interface schemas and validator (zt-interface)
├── zero_trust_task2/               source scanner zt_scan.py, tests, reference output
├── Zero_Trust_Task3_PEP_Integrated/
│   └── zero_trust_pep_task3_integrated/   PEP placement and generation (zt-pep)
├── zero_trust_pdp_task4_secure/
│   ├── src/zt_backplane/           PDP: engine, evidence verification, PSL store loader, service
│   ├── policy_store/               signed PSL policies + policy_fields.yaml (+ *.sig.json)
│   ├── legacy_policy_store/        former YAML bundles (differential report only)
│   ├── config/                     identities, resources, trusted issuers, security context
│   ├── security/dev_keys/          development keys (never for real data)
│   ├── interface_contract/         unchanged PDP schemas + SHA-256 record
│   └── scripts/                    sign_psl_policies, validate_configuration, PSL reports
├── zero_trust_task5/               Permit Leases, cache safety, revocation, audit
├── zero_trust_psl/                 PSL language, compiler, decisions, monitors, intent translator (zt-psl)
├── zero_trust_identity/            SPIFFE scheme B library (zt_identity)
├── integrated_demo/                Tasks 1-6 harness: run_demo.py, reconcile.py, scanner_merge.py,
│                                   testbed_runtime.py, task6_real_workflows.py, input YAMLs,
│                                   sample_banking_system/, output/ (committed snapshot)
├── native_mas_runtime/             engine.py (NativeMasBackplane), tests, output/ (committed snapshot)
├── distributed_runtime/
│   ├── zt_distributed/             gateway, agent service, PSL guard, MCP server/client, ingress client, prepare
│   ├── deploy/                     Dockerfiles, SPIRE config, compose generator, dependency locks, vendor/
│   ├── scripts/                    ctl.ps1 / ctl.py, stack.py, stage_mas.py
│   └── tests/                      unit/ (host), functional/ (Docker)
└── docs/                           design document, PSL reports
```

---

## 15. Further documentation

| document | content |
|---|---|
| `docs/SPIFFE_PSL_DESIGN.md` | design and decisions for SPIFFE scheme B + PSL; status and resolved issues |
| `zero_trust_psl/docs/PSL_SUPPORTED_SUBSET.md` | PSL syntax, semantics, what is rejected, how translation is validated |
| `docs/PSL_POLICY_RULES.md` | every rule of the policy store |
| `docs/PSL_INTENT_TRANSLATION.md` | each natural-language rule and its PSL translation |
| `docs/PSL_INTENT_CONSISTENCY.md` | intent rules vs the real MAS placements |
| `docs/PSL_DIFFERENTIAL_REPORT.md`, `docs/PSL_NATIVE_DIFFERENTIAL_REPORT.md` | every decision that changed with PSL |
| `docs/PSL_PERFORMANCE_REPORT.md` | decision latency and distributed per-step overhead |
| `distributed_runtime/README.md` | distributed runtime: identities, policy scopes, layout |
| `native_mas_runtime/README.md`, `native_mas_runtime/NATIVE_TASK6_INTEGRATION_PROOF.md` | native engine, the `transfer_to_agent` fix, live evidence |
| `citi_banking_adk/NATIVE_ZERO_TRUST_README.md` (MAS repository) | running the native mode, the nine ADK hooks, shadow mode, latency |
| `integrated_demo/README.md`, `integrated_demo/TASK6_IMPLEMENTATION_REPORT.md` | Task 6 harness and report |
| `zero_trust_task2/README.md` | scanner, including how agent domains are assigned |
| `zero_trust_pdp_task4_secure/README.md` | PDP hardening, interface compatibility, HTTP service |
| `zero_trust_task5/README.md`, `interface_standard/README.md`, `zero_trust_task1/README.md`, `Zero_Trust_Task3_PEP_Integrated/zero_trust_pep_task3_integrated/README.md` | per-task documentation |
