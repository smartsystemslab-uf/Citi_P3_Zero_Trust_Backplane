# Zero Trust Backplane Interface Specification

## 1. Scope

The unified manifest is the source of truth for:

- Task 1 requirements and ZT-IR.
- Task 2 scanner inventories and interaction graph.
- Task 3 PEP placement and generated adapters.
- Task 4 PDP identities, resources, actions, workflows, and policy references.
- Task 5 permit binding, versions, and revocation scope.
- Task 6 Citi environment bindings.
- Task 7 security tests and audit fields.
- Task 8 documentation and demonstration configuration.

## 2. Canonical IDs

Canonical IDs are stable and environment-independent.

| Record | Pattern | Example |
|---|---|---|
| Subject | `agent.<domain>.<name>` | `agent.front_office.fraud` |
| Service | `service.<domain>.<name>` | `service.shared.pdp` |
| Resource | `resource.<domain>.<name>` | `resource.back_office.ledger` |
| Interface | `interface.<type>.<name>` | `interface.mcp.execute_transfer` |
| Workflow | `workflow.<domain>.<name>` | `workflow.front_office.fraud_review` |
| Interaction | `edge.<workflow>.<step>` | `edge.fraud_review.read_history` |
| Boundary | `boundary.<from>.<to>` | `boundary.agent.mcp` |
| Gap | `gap.<name>` | `gap.citi_identity_issuer` |
| Policy | `policy.<domain>.<name>` | `policy.front_office.fraud_read_history` |

Use lowercase snake case inside each segment. Never encode a hostname, port, Git branch, employee name, or environment in a canonical ID.

## 3. Canonical ID versus runtime binding

A canonical ID represents what an entity means. A binding records how it appears in a specific environment.

```yaml
id: resource.back_office.ledger
bindings:
  prototype:
    runtime_id: ledger
    function_name: ledger_update
  citi_dev:
    runtime_id: null
    function_name: null
```

Policies use the canonical ID. Generated adapters resolve the environment binding at deployment time.

## 4. Required metadata and provenance

Every subject, resource, interface, workflow, interaction, and trust boundary has:

- `status`: `confirmed`, `provisional`, `placeholder`, or `deprecated`.
- `source.provided_by`: the organization or team that supplied the information.
- `source.reference`: a document, repository path, ticket, meeting note, or scanner output.
- `source.verified_at`: an ISO 8601 timestamp, or `null` when not verified.
- `owner`: responsible team or owner, or `null` while unresolved.

A record must not be marked `confirmed` unless its runtime binding and semantics have been verified.

## 5. Placeholder rules

Unknown Citi values are represented in two ways:

1. The field is `null` when the schema permits null.
2. The manifest contains a matching entry under `spec.unresolved`.

Use the token `__CITI_REQUIRED__` only in string fields that cannot be null. Never invent an endpoint, claim name, identity provider, authentication mechanism, timeout, ownership team, retention period, or action name.

Example:

```yaml
unresolved:
  - id: gap.citi_identity_issuer
    path: spec.interfaces[id=interface.http.identity_provider].authentication.issuer
    required_from: citi
    question: What issuer identifies trusted Citi agent workloads?
    blocking_tasks: [4, 6]
    status: open
    answer: null
```

## 6. Environment overlays

Base manifests contain stable definitions. Environment overlays replace only environment-dependent fields.

Allowed overlay targets:

- `metadata.environment`
- `metadata.source_revision`
- `spec.defaults.environment_binding`
- entity `bindings.<environment>`
- interface authentication configuration
- audit sink and retention settings
- unresolved answers and statuses

Do not use overlays to silently change canonical actions, risk classification, criticality, or policy meaning. Such changes require a manifest version update and review.

## 7. Versioning

- Interface schema version: `apiVersion: ztb/v1alpha1`.
- Manifest content version: semantic version in `metadata.manifest_version`.
- Policy version: policy bundle version or content hash.
- Runtime identity/risk versions: supplied by Task 5 services.

Increment:

- Patch: metadata corrections or non-semantic binding changes.
- Minor: additive subjects, resources, actions, interfaces, or workflows.
- Major: incompatible field meaning, action renaming, or authorization semantics.

## 8. Interface records

An interface records the mechanism used to access a function or resource.

Required information:

- Stable interface ID and type.
- Per-environment endpoint, service name, function name, and runtime ID.
- Authentication method and secret references.
- Request and response schema references.
- Timeout and retry policy.
- Provenance, owner, and status.

Supported interface types include HTTP, MCP, gRPC, Python functions, databases, event buses, files, and message queues.

## 9. Interaction edges

An interaction edge records exactly one intended operation:

`caller + target + resource + action + workflow + interface + trust boundary + risk + PEP`

This is the reusable unit for scanner output, PEP placement, PDP test generation, security coverage, and audit trace verification.

## 10. Security requirements

- Default decision is always `DENY`.
- Runtime identity and workflow context must come from trusted components, not arbitrary request body fields.
- Secrets are represented only by references.
- Critical writes must specify a fail-closed PEP mode.
- Every protected edge must point to a known subject, resource, interface, workflow, and trust boundary.
- Every action on an edge must be declared by the referenced resource.
- Audit records use canonical IDs plus optional runtime IDs.
- Task 5 permits bind to canonical subject, resource, action, workflow instance, and exact request hash.

## 11. Compatibility policy

Consumers must ignore unknown keys only inside explicit `extensions` objects. Unknown top-level or normal record fields are rejected by the schema. This prevents spelling mistakes from silently becoming configuration.
