# zt-pep — PEP placement and generation

This package places a Policy Enforcement Point on every sensitive interaction of a Unified Interface
manifest and generates the PEP plan and adapters. It works with the Unified Interface standard (zt-interface)
and the PDP (zt-pdp); `zt-adk build` uses it for every protected application.

## What it generates (`zt-pep generate`, into `generated/` by default; not versioned)

- `generated_pep_plan.json`
- Generated Python middleware and wrappers
- Generated MCP wrappers
- Generated FastAPI dependencies
- Generated data-access wrappers
- Generated event adapters
- PEP coverage report
- Unprotected-path and scanner-gap report
- Logical-to-physical PEP map
- PDP compatibility report
- PDP registry synchronization command
- End-to-end tests against the real PDP FastAPI application

## 1. Install

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -e ".[test,fastapi]"
```

## 2. Make PDP importable

The PEP generator intentionally uses PDP's own signed evidence and decision-verification implementation.

```bash
pip install -e "C:\path\to\packages/zt-pdp"
```

Linux/macOS:

```bash
pip install -e /path/to/zt-pdp
```

## 3. Generate PEP generator artifacts

```bash
zt-pep generate \
  examples/citi_project_baseline.yaml \
  --output generated \
  --pdp-root /path/to/zt-pdp
```

The engine validates the manifest against the unchanged unified schema before generating anything.

## 4. Verify compatibility with PDP

```bash
python scripts/verify_pdp_integration.py \
  --pdp-root /path/to/zt-pdp
```

Expected summary:

```json
{
  "interface_schemas_match": true,
  "all_pep_requests_resolve_in_pdp_registry": true,
  "compatible": true
}
```

### Current PDP policy gaps

The existing PDP registry accepts every generated PEP generator request, but five known business edges currently have no candidate explicit policy and therefore return `DENY` under PDP default-deny:

- `edge.customer_transaction.get_context`
- `edge.eod_processing.create_exception`
- `edge.eod_processing.reconcile`
- `edge.eod_processing.store_report`
- `edge.eod_processing.write_report`

This package reports these gaps but does not silently change the completed PDP policy bundles.

## 5. Run the actual PDP

From the PDP folder:

```bash
uvicorn zt_pdp.pdp_service:app --app-dir src --host 127.0.0.1 --port 8080
```

Then, from this PEP generator folder:

```bash
python scripts/live_pep_demo.py \
  --pdp-root /path/to/zt-pdp
```

The demo shows:

1. Fraud-agent transaction-history access allowed with masking obligations.
2. Ledger update blocked when PDP returns `MANUAL_REVIEW`.
3. Ledger update allowed only after signed human approval, independent authorization, idempotency key, and change ticket are present.

## 6. Run tests

PEP generator-only tests:

```bash
pytest
```

Include the real PDP integration test:

Windows PowerShell:

```powershell
$env:PDP_ROOT="C:\path\to\packages/zt-pdp"
pytest
```

Linux/macOS:

```bash
PDP_ROOT=/path/to/zt-pdp pytest
```

## 7. Synchronize PDP registries from the same manifest

This backs up the current files and regenerates only PDP's identity/resource/interface configuration. It does not overwrite policies.

```bash
zt-pep sync-pdp \
  examples/citi_project_baseline.yaml \
  /path/to/zt-pdp
```

## Generated adapter usage

```python
from generated.adapters.data_wrappers import protect_pep_fraud_review_read_history
from zt_pep.runtime import PEPEnforcer, PdpClient

client = PdpClient(
    pdp_url="http://127.0.0.1:8080",
    pdp_public_key="../zt-pdp/security/dev_keys/pdp_signing_public.pem",
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

The returned account number and SSN are masked because PEP generator enforces PDP's obligations.

## Security boundary

The included PDP keys and issuers are development-only. The PEP generator does not copy private keys. For Citi integration, replace the PDP development evidence providers with Citi identity, risk, workflow, approval, and key-management services while retaining the unified interface and placement IDs.
