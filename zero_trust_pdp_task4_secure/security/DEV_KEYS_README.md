# Development keys — never use in Citi integration

These Ed25519 private keys exist only so the Task 4 prototype and tests run out
of the box. They are not protected by an HSM/KMS, are distributed with the code,
and therefore provide **no production secrecy**.

Replace them with Citi-managed trust sources:

- PEP/workload identity: mTLS, SPIFFE/SPIRE, Citi PKI, or signed workload token.
- Risk/auth/workflow/approval assertions: Citi service signing keys or JWKS.
- Policy authority: an approved release-signing key held in KMS/HSM.
- PDP decision key: a short-lived KMS/HSM-backed signing key.

Run `PYTHONPATH=src python scripts/bootstrap_dev_crypto.py --force` only for a
new local demonstration environment.
