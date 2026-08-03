# Task 3 and Task 4 Integration

## Exact compatibility points

- Same interface schema version: `1.0`.
- Same canonical subject, resource, action, and workflow IDs.
- Same prototype runtime bindings compiled from the unified manifest.
- Same Task 4 challenge endpoint and nonce/JTI replay protection.
- Same Task 4 signed identity, risk, authentication, workflow, approval, and secondary-authorization evidence.
- Same signed decision verification.
- Default deny remains authoritative when no policy matches.

## Why Task 3 imports Task 4's evidence builder

The Task 4 prototype contains security extensions inside the existing interface schema. Re-implementing these signatures in Task 3 would create protocol drift. The runtime bridge imports `zt_backplane.dev_evidence.build_signed_request` and `zt_backplane.decision_signing.verify_decision_headers` directly from Task 4.

The development keys are not copied into Task 3. Citi-managed issuers and keys can replace Task 4's development evidence layer later without changing generated PEP placement IDs.

## Configuration synchronization

`zt-pep sync-task4` recompiles `identities.yaml`, `resources.yaml`, and `citi_interfaces.yaml` from the same manifest. Existing Task 4 files are backed up first. Policies are not overwritten.
