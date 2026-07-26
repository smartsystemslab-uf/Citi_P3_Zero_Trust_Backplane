# Zero Trust Backplane Unified Interface Standard

Version: `1.0.0-alpha.1`

This package defines one reusable representation for recording Citi-specific information and exchanging data between every Zero Trust Backplane task.

The central artifact is `zt_manifest.yaml`. It records stable logical identities, Citi runtime bindings, resources, interfaces, workflows, interaction edges, trust boundaries, policy references, audit requirements, and unresolved information.

## Core rule

Policies and generated components reference stable canonical IDs, not Citi's temporary code names, URLs, function names, or deployment addresses.

Example:

```yaml
id: agent.front_office.fraud
bindings:
  prototype:
    runtime_id: fraud_agent
  citi_dev:
    runtime_id: null
```

When Citi provides the real identity, only `bindings.citi_dev.runtime_id` changes. The canonical ID, policies, interaction graph, PEP plan, audit records, and tests remain stable.

## Package contents

- `schemas/zt_manifest.schema.json`: schema for the complete system manifest.
- `schemas/pdp_request.schema.json`: common PEP-to-PDP request contract.
- `schemas/pdp_response.schema.json`: common PDP response contract.
- `schemas/policy_bundle.schema.json`: reusable policy bundle format.
- `schemas/audit_event.schema.json`: cross-component audit record.
- `schemas/permit_lease.schema.json`: Task 5 permit-lease contract.
- `templates/citi_manifest.template.yaml`: blank Citi replacement template.
- `templates/citi_overlay.template.yaml`: environment-specific replacement layer.
- `examples/zt_manifest.example.yaml`: working banking-agent example.
- `src/zt_interface`: validator, overlay merger, unresolved-field reporter, and Task 4 compiler.
- `docs/INTERFACE_SPECIFICATION.md`: field definitions and rules.
- `docs/TASK_INTEGRATION.md`: how Tasks 1–8 use the same manifest.

## Install and validate

```bash
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -e ".[test]"

zt-interface validate examples/zt_manifest.example.yaml
zt-interface unresolved templates/citi_manifest.template.yaml
zt-interface compile-task4 examples/zt_manifest.example.yaml generated/task4_config
```

## Apply a Citi environment overlay

```bash
zt-interface merge \
  templates/citi_manifest.template.yaml \
  templates/citi_overlay.template.yaml \
  generated/citi_dev_manifest.yaml

zt-interface validate generated/citi_dev_manifest.yaml
```

## Replacement workflow

1. Keep canonical IDs unchanged.
2. Copy `templates/citi_overlay.template.yaml` for the target environment.
3. Replace only runtime bindings, endpoints, authentication settings, schema references, ownership metadata, and unresolved placeholders.
4. Validate the merged manifest.
5. Regenerate Task 2 inventories, Task 3 PEP plans, Task 4 configuration, and later Task 5–7 artifacts from the same manifest.

Do not place passwords, API keys, private keys, access tokens, customer records, account numbers, or other secrets in this manifest. Store only secret references.
