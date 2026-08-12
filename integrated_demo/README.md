# Integrated Zero Trust Backplane Demo — Tasks 1–5

This demo makes the currently implemented Zero Trust Backplane tasks run as one pipeline instead of as isolated packages.

## What runs together

1. **Task 1** — loads the legacy Citi ZT-IR inventory and validates the unified interface baseline.
2. **Task 2** — scans a banking repository with the AST scanner and generates draft agent/tool/API/database/edge manifests.
3. **Task 1 + Task 2 reconciliation** — verifies selected runtime names against both sources and updates only the unified runtime bindings. Canonical IDs stay stable.
4. **Task 3** — consumes the reconciled manifest, generates logical/physical PEP placements and adapter code, and checks the post-sync Task 4 registry contract.
5. **Task 4** — runs the real security-hardened PDP in-process, including signed requests, signed policy bundles, verified context, replay protection, and signed decisions.
6. **Task 5** — verifies the native Task 4 decision, issues a signed Permit Lease, binds it to the Task 3 PEP sender, enforces obligations, handles PDP timeout, rejects modified requests, clears cache on PEP restart, and fails closed for critical single-use permits.

## Run

Use Python 3.11+ and install the four Python packages first:

```bash
python -m pip install -e interface_standard \
  -e Zero_Trust_Task3_PEP_Integrated/zero_trust_pep_task3_integrated \
  -e zero_trust_pdp_task4_secure \
  -e zero_trust_task5
```

From the repository root:

```bash
python integrated_demo/run_demo.py --clean
```

The ZIP does not contain the full Citi banking-agent implementation, so the default command scans `integrated_demo/sample_banking_system`, a small static-analysis fixture whose names mirror the Task 1 inventory. To scan a real checkout instead:

```bash
python integrated_demo/run_demo.py --clean --banking-repo /path/to/citi-banking-system
```

The real repository must expose the paths currently expected by Task 2:

- `citi_banking_adk/bank_adk/agents/*.py`
- `citi_banking_adk/bank_adk/tools/*.py`
- `citi_banking_mcp_server/mcp_server.py`
- `citi_banking_backend/app/main.py`
- `citi_banking_backend/app/models.py`

## Demo scenarios

The runner demonstrates:

- fraud-agent read is allowed and Task 4's masking obligation is still applied after Task 5 is inserted;
- an exact noncritical request may use a bounded valid Permit Lease during a simulated PDP timeout;
- a modified request cannot reuse that cached authorization;
- a PEP restart clears local authorization cache and disables timeout fallback;
- a critical ledger write without signed approvals returns `MANUAL_REVIEW` and is blocked;
- the same ledger write with signed human approval, independent authorization, idempotency key, and change ticket is allowed;
- that critical Permit Lease is single-use and therefore cannot be reused when the PDP later times out;
- the Task 5 hash-chained audit log verifies successfully.

## Important integration detail: Task 4 hash vs Task 5 hash

Task 4 and Task 5 intentionally bind slightly different canonical request representations. `native_task4_bridge.py` handles this without weakening verification:

1. Task 4's original request and response are verified using Task 4's own request hash and decision signature.
2. The bridge checks that subject, resource, action, workflow, and parameters are semantically identical to the Task 5 request.
3. Only after that succeeds is the decision normalized to Task 5's operation hash for Permit Lease issuance.

So the demo never trusts a Task 5 hash as a substitute for verifying Task 4's native signed request.

## Output

`integrated_demo/output/` contains:

- Task 2 draft manifests and coverage report;
- Task 1/2 reconciliation report;
- reconciled unified manifest;
- Task 3 generated PEP plan/adapters/coverage reports;
- compiled Task 4 identity/resource/interface configuration;
- Task 4 decision audit log;
- Task 5 hash-chained audit log;
- `demo_summary.json` with pass/fail results for every scenario.
