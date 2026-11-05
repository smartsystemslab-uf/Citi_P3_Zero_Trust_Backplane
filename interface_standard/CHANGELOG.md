# Changelog

## 1.1.0-alpha.1

- `domain` of subjects, resources and workflows is a free-form identifier
  (`^[a-z][a-z0-9_]*$`, at most 64 characters) instead of the fixed Citi office list, so a
  manifest can describe any multi-agent system. Every manifest valid under 1.0.0-alpha.1 stays
  valid.
- `metadata.environment` additionally accepts `dev`, `test`, `stage` and `prod`.
- `spec.defaults.placeholder_token` may be the generic `__REQUIRED__` (or `__CITI_REQUIRED__`).

## 1.0.0-alpha.1

- Added a single Zero Trust system manifest.
- Separated canonical IDs from environment-specific Citi runtime bindings.
- Added schemas for PDP, policy, audit, and future Permit Lease interfaces.
- Added placeholder and provenance requirements.
- Added validation, overlay merge, unresolved-field reporting, and Task 4 compilation tools.
