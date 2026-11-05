# zt-psl — PSL policy language for the Zero Trust Backplane

All Backplane authorization policies are written in **PSL** (IEEE 1850-2010, Verilog flavour,
simple subset) instead of natural language or ad-hoc YAML. This package parses, checks,
compiles and evaluates them.

| module | role |
|---|---|
| `parser.py`, `ast.py` | PSL subset parser (unsupported PSL fails with file:line:col); Boolean layer with hierarchical fields and comparisons; `// @key value` annotations |
| `core.py`, `automaton.py` | desugaring to a core form, formula progression, monitor automata with LTL3 verdicts and neutral finite-path close verdicts |
| `reference.py` | independent reference interpreter (used only by tests to validate the compiler) |
| `fields.py` | field catalogue (typed, trusted inputs), static type checks, binder (field values -> AP values) |
| `compiler.py` | policy sets: permissions, request invariants, generated default deny, temporal monitors |
| `decision.py` | deny-overrides decisions for request rules |
| `runtime.py` | execution of temporal monitors (per-key slices, atomic admission) |
| `signing.py` | detached Ed25519 signatures for policy files |

Language, semantics and limits: [`docs/PSL_SUPPORTED_SUBSET.md`](docs/PSL_SUPPORTED_SUBSET.md).
Design of the Backplane integration: [`../docs/SPIFFE_PSL_DESIGN.md`](../docs/SPIFFE_PSL_DESIGN.md).

## Example

```psl
// @policy_set bundle.ledger_access
// @version 2.0.0
vunit ledger_access (pdp_request) {
  // @rule policy.ledger.eod_approved_update
  // @nl EOD ledger update may proceed only with signed human approval and independent authorization.
  // @permit
  // @obligation require_idempotency_key
  property eod_approved_update = subject.id == "agent.back_office.eod"
      && resource.id == "resource.back_office.ledger" && action == "update";

  // @rule policy.ledger.eod_pending_review
  // @on_violation MANUAL_REVIEW
  eod_pending_review: assert always (authz_request && subject.id == "agent.back_office.eod"
      && resource.id == "resource.back_office.ledger" && action == "update"
      -> approval.valid && approval.secondary_valid);
}
```

## Use

```python
from zt_psl import load_policy_set, RequestPolicyEngine
ps = load_policy_set(files, catalog_path)          # compile (+ verify signatures in the PDP loader)
decision = RequestPolicyEngine(ps).decide(fields)  # deny-overrides
```

Tests: `python -m pytest packages/zt-psl/tests` (112 tests: parser/subset, compiler vs reference
interpreter on random formulas incl. comparisons, field catalogue, annotations, decisions,
signing, temporal monitors).
