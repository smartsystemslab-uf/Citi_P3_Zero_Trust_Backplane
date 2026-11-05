# PEP generator Design: PEP Placement and Generation

## Source of truth

The PEP generator consumes the unified `zt_manifest.yaml`. The interaction edge is the coverage and authorization unit:

`caller + target + resource + action + workflow + interface + trust boundary + risk + PEP`

The PEP generator never renames canonical IDs. Therefore the request sent by a generated PEP resolves directly in PDP's identity and resource registries.

## Placement rules

1. User-to-agent paths generate an Input PEP.
2. Agent-to-agent paths generate an Agent Route PEP.
3. MCP interfaces generate an MCP PEP.
4. HTTP/gRPC interfaces generate an API PEP.
5. Database, ledger, file, knowledge-base, and direct data paths generate a Data PEP.
6. Event-to-agent paths generate an Event PEP.
7. External output or egress paths generate an Output PEP.
8. Unknown mechanisms use shared middleware rather than silently remaining unprotected.
9. Sensitive paths cannot be disabled by `pep.required: false`; the engine records a blocking finding and forces protection.
10. Critical/high-risk paths fail closed.

## Logical versus physical PEPs

Each edge receives a logical placement ID. Compatible logical PEPs share a physical adapter, such as one MCP gateway or one data-access guard. The physical component routes by logical placement ID, so PDP still receives the exact edge-specific subject, resource, action, and workflow.

## Runtime sequence

1. Generated adapter selects a logical placement.
2. The PEP generator resolves canonical and runtime bindings from the generated plan.
3. The PEP generator requests a nonce from PDP `/v1/challenge`.
4. The PEP generator calls PDP's own signed-evidence builder.
5. The PEP generator sends the unchanged PDP request schema to `/v1/authorize`.
6. The PEP generator verifies PDP's signed decision headers and request binding.
7. DENY, MANUAL_REVIEW, and REAUTHENTICATE are blocked in enforcement mode.
8. ALLOW obligations are enforced before or after the business operation.
9. A PEP audit event records the decision and execution outcome.

## Coverage interpretation

The 100% target applies to sensitive interaction paths discovered in the manifest. A sensitive resource with no incoming interaction is reported as a static scanner gap. It is not falsely counted as protected.
