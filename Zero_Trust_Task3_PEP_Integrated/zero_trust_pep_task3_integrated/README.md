# Zero Trust Backplane Task 3 — Integrated PEP Placement and Generation

This package implements Task 3 and is designed to work with the provided unified interface standard and the security-hardened Task 4 PDP.

## Implemented deliverables

- `pep_placement_engine.py`
- `generated/generated_pep_plan.json`
- Generated Python middleware and wrappers
- Generated MCP wrappers
- Generated FastAPI dependencies
- Generated data-access wrappers
- Generated event adapters
- PEP coverage report
- Unprotected-path and scanner-gap report
- Logical-to-physical PEP map
- Task 4 compatibility report
- Task 4 registry synchronization command
- End-to-end tests against the real Task 4 FastAPI application

## 1. Install Task 3

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -e ".[test,fastapi]"
```

## 2. Make Task 4 importable

Task 3 intentionally uses Task 4's own signed evidence and decision-verification implementation.

```bash
pip install -e "C:\path\to\zero_trust_pdp_task4_secure"
```

Linux/macOS:

```bash
pip install -e /path/to/zero_trust_pdp_task4_secure
```

## 3. Generate Task 3 artifacts

```bash
python pep_placement_engine.py generate \
  examples/citi_project_baseline.yaml \
  --output generated \
  --task4-root /path/to/zero_trust_pdp_task4_secure
```

The engine validates the manifest against the unchanged unified schema before generating anything.

## 4. Verify compatibility with Task 4

```bash
python scripts/verify_task4_integration.py \
  --task4-root /path/to/zero_trust_pdp_task4_secure
```

Expected summary:

```json
{
  "interface_schemas_match": true,
  "all_pep_requests_resolve_in_task4_registry": true,
  "compatible": true
}
```

### Current Task 4 policy gaps

The existing Task 4 registry accepts every generated Task 3 request, but five known business edges currently have no candidate explicit policy and therefore return `DENY` under Task 4 default-deny:

- `edge.customer_transaction.get_context`
- `edge.eod_processing.create_exception`
- `edge.eod_processing.reconcile`
- `edge.eod_processing.store_report`
- `edge.eod_processing.write_report`

This package reports these gaps but does not silently change the completed Task 4 policy bundles.

## 5. Run the actual Task 4 PDP

From the Task 4 folder:

```bash
uvicorn zt_backplane.pdp_service:app --app-dir src --host 127.0.0.1 --port 8080
```

Then, from this Task 3 folder:

```bash
python scripts/live_pep_demo.py \
  --task4-root /path/to/zero_trust_pdp_task4_secure
```

The demo shows:

1. Fraud-agent transaction-history access allowed with masking obligations.
2. Ledger update blocked when Task 4 returns `MANUAL_REVIEW`.
3. Ledger update allowed only after signed human approval, independent authorization, idempotency key, and change ticket are present.

## 6. Run tests

Task 3-only tests:

```bash
pytest
```

Include the real Task 4 integration test:

Windows PowerShell:

```powershell
$env:TASK4_ROOT="C:\path\to\zero_trust_pdp_task4_secure"
pytest
```

Linux/macOS:

```bash
TASK4_ROOT=/path/to/zero_trust_pdp_task4_secure pytest
```

## 7. Synchronize Task 4 registries from the same manifest

This backs up the current files and regenerates only Task 4's identity/resource/interface configuration. It does not overwrite policies.

```bash
zt-pep sync-task4 \
  examples/citi_project_baseline.yaml \
  /path/to/zero_trust_pdp_task4_secure
```

## Generated adapter usage

```python
from generated.adapters.data_wrappers import protect_pep_fraud_review_read_history
from zt_pep.runtime import PEPEnforcer, Task4PDPClient

client = Task4PDPClient(
    pdp_url="http://127.0.0.1:8080",
    pdp_public_key="../zero_trust_pdp_task4_secure/security/dev_keys/pdp_signing_public.pem",
)
enforcer = PEPEnforcer("generated/generated_pep_plan.json", pdp_client=client)


def read_history(transaction_id: str):
    return {
        "transaction_id": transaction_id,
        "full_account_number": "123456789",
        "ssn": "111-22-3333",
    }

protected_read = protect_pep_fraud_review_read_history(enforcer, read_history)
result = protected_read(
    "t-1",
    zt_context={"parameters": {"transaction_id": "t-1"}},
)
```

The returned account number and SSN are masked because Task 3 enforces Task 4's obligations.

## Security boundary

The included Task 4 keys and issuers are development-only. Task 3 does not copy private keys. For Citi integration, replace the Task 4 development evidence providers with Citi identity, risk, workflow, approval, and key-management services while retaining the unified interface and placement IDs.
