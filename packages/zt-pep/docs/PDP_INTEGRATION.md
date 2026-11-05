# PEP generator and PDP Integration

## Exact compatibility points

- Same interface schema version: `1.0`.
- Same canonical subject, resource, action, and workflow IDs.
- Same prototype runtime bindings compiled from the unified manifest.
- Same PDP challenge endpoint and nonce/JTI replay protection.
- Same PDP signed identity, risk, authentication, workflow, approval, and secondary-authorization evidence.
- Same signed decision verification.
- Default deny remains authoritative when no policy matches.

## Why PEP generator imports PDP's evidence builder

The PDP prototype contains security extensions inside the existing interface schema. Re-implementing these signatures in PEP generator would create protocol drift. The runtime bridge imports `zt_pdp.dev_evidence.build_signed_request` and `zt_pdp.decision_signing.verify_decision_headers` directly from PDP.

The development keys are not copied into PEP generator. Citi-managed issuers and keys can replace PDP's development evidence layer later without changing generated PEP placement IDs.

## Configuration synchronization

`zt-pep sync-pdp` recompiles `identities.yaml`, `resources.yaml`, and `citi_interfaces.yaml` from the same manifest. Existing PDP files are backed up first. Policies are not overwritten.
