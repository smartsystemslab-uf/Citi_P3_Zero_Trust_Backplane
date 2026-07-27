# Changelog

## 1.0.0 — Security-hardened rewrite

- Preserved the reusable interface standard v1.0 byte-for-byte.
- Replaced caller-supplied trust with signed identity and context assertions.
- Added canonical request hashing, server-issued nonce, JTI replay blocking,
  signed policy bundles, rollback prevention, signed PDP decisions, and
  tamper-evident audit chaining.
- Added deterministic risk-level and authentication-strength validation.
- Required signed approval plus independent authorization for critical writes.
- Kept Permit Lease disabled (`NO_STORE`); Permit Lease remains Task 5.
