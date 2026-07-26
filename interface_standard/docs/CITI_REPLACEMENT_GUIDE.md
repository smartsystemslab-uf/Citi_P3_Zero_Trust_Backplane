# Citi Replacement Guide

Use `examples/citi_project_baseline.yaml` as the current project-wide baseline.

## Fields that remain stable

Do not replace:

- Canonical IDs such as `agent.front_office.fraud`.
- Canonical resource/action names once approved.
- Workflow and interaction IDs.
- Schema versions.
- Default-deny behavior.

## Fields to replace with Citi information

Replace through a Citi environment overlay:

1. `spec.subjects[*].bindings.citi_dev.runtime_id`
2. `spec.resources[*].bindings.citi_dev`
3. `spec.interfaces[*].bindings.citi_dev`
4. `spec.interfaces[*].authentication`
5. Interface request/response schema references
6. Resource and interface owners
7. Confirmed workflow steps and interaction edges
8. Risk, approval, and obligation requirements
9. Audit sink, redaction, and retention configuration
10. Deployment namespaces, service names, zones, and trust boundaries

## Update status and provenance

When Citi confirms a record:

```yaml
metadata:
  status: confirmed
  source:
    provided_by: citi
    reference: <document, ticket, meeting, or repository path>
    verified_at: <ISO 8601 time>
  owner: <Citi owner or team>
```

Then update the corresponding gap:

```yaml
- id: gap.citi_agent_runtime_ids
  status: answered
  answer:
    agent.front_office.fraud: <Citi runtime ID>
```

## Validate and generate Task 4 files

```bash
PYTHONPATH=src python -m zt_interface.cli validate examples/citi_project_baseline.yaml
PYTHONPATH=src python -m zt_interface.cli unresolved examples/citi_project_baseline.yaml
PYTHONPATH=src python -m zt_interface.cli compile-task4 \
  examples/citi_project_baseline.yaml generated/citi_project_task4_config
```

The generated `identities.yaml`, `resources.yaml`, and `citi_interfaces.yaml` can replace the current Task 4 prototype configuration.
