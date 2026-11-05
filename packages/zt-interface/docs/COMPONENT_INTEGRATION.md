# Component Integration Using the Unified Manifest

## Unified Interface: requirements and ZT-IR

Create and maintain `zt_manifest.yaml`. Record confirmed information, provisional assumptions, and unresolved Citi questions. The manifest replaces separate informal lists of agents, tools, APIs, resources, and workflows.

## Static scanner: interaction graph

The scanner writes discovered entities into the same manifest format. Scanner-generated records use:

```yaml
status: provisional
source:
  provided_by: scanner
  reference: repo/path.py:line
```

A review process promotes them to `confirmed`.

## PEP generator: PEP placement

Read `spec.interactions[*].pep`. Generate or update PEP placement IDs, wrappers, middleware, and unprotected-path reports. The interaction edge is the coverage unit.

## PDP: decision point and policy engine

Compile:

- `spec.subjects` into the identity registry.
- `spec.resources` and actions into the resource catalog.
- workflows and risk classifications into policy inputs.
- interfaces into PEP-to-PDP integration configuration.

The included `compile-pdp` command creates compatible YAML files for the current prototype.

## Permit Lease: leases and revocation

Use canonical IDs and environment versions. Permit fields are defined in `schemas/permit_lease.schema.json`. Request hashing must include the canonical subject, resource, action, workflow instance, and normalized parameters.

## Integrated workflows: Citi integration

Create a Citi environment overlay. Add actual runtime identities, endpoints, function names, authentication method, schema references, and secret references without changing canonical IDs.

## Evaluation

Generate tests from interaction edges:

- Positive test for intended caller/action.
- Unknown-agent and undefined-action tests.
- Direct bypass test for every protected resource.
- Failure-mode test for every critical edge.
- Audit-completeness test using `audit_event.schema.json`.

## Demo and documentation

Use the same manifest version in the scanner output, PEP plan, PDP health endpoint, permit logs, audit traces, diagrams, and final demonstration. This provides end-to-end traceability.
