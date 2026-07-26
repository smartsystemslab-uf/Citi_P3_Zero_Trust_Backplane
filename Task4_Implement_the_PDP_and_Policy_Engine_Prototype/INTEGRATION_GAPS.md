# Citi Integration Gaps to Fill

The prototype runs without Tasks 1-3, but the following values are placeholders and must be replaced before real integration.

| Area | Placeholder now | What Citi / earlier tasks must provide | Where to update |
|---|---|---|---|
| Agent identity | Local YAML name such as `fraud_agent` | Cryptographically verified workload identity, issuer, audience, stable agent ID | `config/citi_interfaces.yaml`, then replace/wrap `IdentityRegistry` in `src/zt_backplane/identity.py` |
| Agent roles/domains | Starter role mapping | Exact agent inventory and roles | `config/identities.yaml` |
| Resources/actions | Starter names such as `ledger:update` | Task 1 ZT-IR or Task 2 scan output with exact tool/API/DB/ledger identifiers | `config/resources.yaml` |
| PEP call site | Example HTTP client only | Task 3 generated middleware/wrappers and exact invocation points | `src/zt_backplane/pep_client_example.py` |
| Workflow/risk context | PEP-supplied strings | Trusted workflow ID, risk source, and which component is allowed to assert them | `config/citi_interfaces.yaml` and PEP request construction |
| Human approval | Boolean in request context | Approval system/API and signed approval evidence | `config/citi_interfaces.yaml`; replace plain `human_approved` trust model |
| MCP tools | Not connected | Exact MCP tool names and schemas | `config/citi_interfaces.yaml`; add matching resources/policies |
| FastAPI/OpenAPI | Not connected | Backend OpenAPI document and route/action mapping | `config/citi_interfaces.yaml`; add Task 3 interceptors |
| Ledger function | Logical `ledger:update` only | Exact ledger update function/API and parameters | `config/citi_interfaces.yaml`; protect with a PEP |
| Audit sink | Local JSONL file | Citi SIEM/log pipeline, required fields, retention, redaction rules | `src/zt_backplane/audit.py` |
| Policy administration | Local YAML + optional token reload | Policy owner, review/approval process, signing and deployment mechanism | `policy_store/`, `/v1/admin/reload` |
| Permit cache | Intentionally absent | Task 5 Permit Lease, expiry, revocation, request binding | New Task 5 modules; do not cache Task 4 ALLOW responses |

## Important trust boundary

The PDP currently accepts `subject`, `workflow`, `risk`, and `human_approved` in the JSON request so the prototype is testable. In production, a caller must not be able to freely claim these fields. A PEP or trusted gateway must derive them from verified identity, signed workflow state, the risk system, and the approval system.
