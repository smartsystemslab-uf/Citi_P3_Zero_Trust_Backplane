# Interface compatibility

The JSON Schemas in this directory are byte-for-byte copies of the previously
approved `zero_trust_backplane_interface_standard` version 1.0. Task 4 does not
add fields to either the PDP request or response schema.

Security data uses fields already available in that contract:

- `subject.identity_evidence`: PEP/workload proof, nonce, JTI, and signature.
- `context` extension properties: signed risk, authentication, workflow, and
  secondary-authorization assertions.
- `context.human_approval`: signed approval evidence bound to `request_hash`.
- `request_hash`: canonical operation binding.
- HTTP response headers: PDP decision signature and digest. The JSON response
  body remains unchanged.

`SCHEMA_SHA256.json` records the exact copied-schema hashes and the test suite
checks them before testing Task 4.
