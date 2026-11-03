# Supported PSL subset, semantics and translation

## 1. Language baseline

* **Standard:** IEEE Std 1850-2010 *Property Specification Language (PSL)* (identical content:
  IEC 62531:2012). Temporal layer (FL properties, SEREs), verification layer (`vunit`,
  `assert`, `property`, `sequence` declarations) and Boolean layer.
* **Flavor:** Verilog flavor for the Boolean layer (`!`, `&&`, `||`, `->`, `<->`, `true`,
  `false`, `0`/`1`). Booleans are atomic propositions (APs): events, Boolean fields with
  hierarchical names (`resource.critical`), and comparisons `FIELD op LITERAL` with
  `==, !=, <, <=, >, >=` against a string, integer, `true` or `false` literal
  (`subject.id == "agent.x"`, `auth.strength >= 2`). There are no bit vectors, no arithmetic,
  no field-to-field comparisons; a comparison is one AP whose value the runtime computes from a
  declared, typed field (see §8).
* **Subset:** the PSL *simple subset* (IEEE 1850 §4.4.4, the monitorable fragment used for
  simulation-based checking), further restricted as listed in §4. This is a small compiler for
  that subset, not a complete PSL implementation.

## 2. Sampling (the "clock")

There is no clock. A vunit is bound to a *monitor scope* (`vunit NAME (SCOPE)`); the scope's
trace is the sequence of **trusted events** emitted for one scope key. Scopes, their events
and fields are declared in a **field catalogue** (§8): a *request* scope has exactly one event
(one authorization request = one step); a *temporal* scope has a trace of runtime events per
key (e.g. one workflow run). **One event = one step.** `default clock` and `@` are rejected
because sampling is defined by the event model, not by the property text.

* **Event steps** order things *within one scope instance*; they are not time.
* **Real time** (permit `expires_at`, certificate `notAfter`, revocation epochs) never appears
  as steps: it enters only through *data APs* evaluated by the PEP against its clock at the step
  where they are used (`live_ok` at `execution_admitted`). `next[3]` therefore means "three
  events later in this scope", never "3 seconds".
* At each step exactly one event AP is true; data APs are true only if the event model defines
  them for that event and the PEP's check succeeded (false otherwise).

## 3. Finite-trace semantics and verdicts

Monitors observe finite prefixes of an unbounded execution. Each property has two verdicts:

**Step verdict (while the scope is open)** -- three-valued, in the runtime-verification sense of
LTL3 (Bauer, Leucker, Schallhart 2011) applied to the PSL semantics on infinite paths:

| verdict | meaning |
|---|---|
| `V` violated | the observed prefix is a *bad prefix*: no continuation (over the scope's alphabet) satisfies the property |
| `S` satisfied | *good prefix*: every continuation satisfies it |
| `P` pending | neither: more events are needed to decide |

A pending property is **never** reported as a violation. Example: after `execution_succeeded`,
`P6_post_audit` (`... -> eventually! audit_post_recorded`) is pending, not violated.

**Close verdict (when the scope is closed: request finished, workflow run ended, timeout)** --
the neutral finite-path semantics of IEEE 1850 on the *complete* finite trace (the scope will
receive no further events): weak operators hold at the end of the path (`next`, `until`,
`before`, `always`, suffix implication with an unfinished match), strong obligations that are
not met fail (`next!`, `until!`, `before!`, `eventually!`). Only at close can an unmet strong
obligation become a violation (`P6_post_audit`, `P6_outcome_recorded`).

Relationship to PSL's own truncated-path views: IEEE 1850 classifies a property on a finite
path as *holds strongly / holds / pending / fails* via weak/neutral/strong views. The step
verdicts here use the *bad/good prefix* definitions, which coincide with PSL's weak/strong views
for the informative prefixes of the properties in this project; for pathological formulas the
LTL3 reading may report a violation earlier than PSL's weak view (never later). This is stated
explicitly rather than claimed to be identical.

Enforcement: for **controllable** events (`execution_admitted`, `execution_started`) the
runtime computes the next state of every affected monitor *before* committing the event; if any
property would become `V`, the event is not committed and the PEP denies the request (the
business function never runs). All other events are observed; a transition to `V` is a
**detected** violation (logged, counted, reported), not a prevented one.

## 4. Supported syntax

| construct | form | notes |
|---|---|---|
| verification unit | `vunit NAME (SCOPE) { ... }` | the parenthesised name binds the vunit to a monitor scope |
| declarations | `property NAME = FL ;` `sequence NAME = { SERE } ;` | used by name later; sequences must be braced |
| directive | `LABEL : assert FL ;` / `LABEL : assert NAME ;` | the label is the stable `property_id`; every assertion needs one |
| Boolean | AP, `true`, `false`, `0`, `1`, `!b`, `b && b`, `b \|\| b`, `b -> b`, `b <-> b`, `( )` | Verilog flavor |
| invariance | `always P`, `never b`, `never { SERE }` | |
| next | `next P`, `next[n] P`, `next! b` | `next!` only with a Boolean operand |
| occurrence | `eventually! b` | Boolean operand only |
| bounding | `P until b`, `P until! b`, `b until_ b`, `b until!_ b` | right operand Boolean (simple subset); `until_` operands Boolean |
| before | `b before b`, `before!`, `before_`, `before!_` | both operands Boolean (simple subset) |
| suffix implication | `{ SERE } \|-> P`, `{ SERE } \|=> P` | antecedent must not match the empty word |
| property logic | `P && P`, `b \|\| P`, `b -> P` | at most one non-Boolean operand of `\|\|`; left of `->` Boolean |
| SERE | Boolean, `{ SERE }`, `R ; R`, `R : R`, `{R} \| {R}`, `R[*]`, `R[*n]`, `R[*n:m]`, `R[*n:inf]`, `R[+]`, `[*]`, `[*n]`, `[+]`, `b[->]`, `b[->n]` | |
| comments | `// ...`, `/* ... */` | |

Operator precedence used by the parser (lowest to highest): `always`/`never` (operand extends to
the right) < `->` `<->` < `||` < `&&` < `until*`/`before*` < `next*`/`eventually!` < `{SERE}`,
suffix implication, parentheses, Booleans. The project's properties are fully parenthesised.

## 5. Not supported (explicit error with file:line:col, never ignored)

`assume`, `assume_guarantee`, `restrict`, `restrict_guarantee`, `cover`, `fairness`, `strong`;
`default clock` and every clocked form `@`; `abort`, `async_abort`, `sync_abort`; `within`;
length-matching SERE `&` and SERE `&&`; non-consecutive repetition `[= ]`; goto ranges
`[->n:m]`; strong SEREs `{r}!`; stand-alone SERE properties `{r}`; `eventually!` with a SERE
operand; `next!` with a non-Boolean operand; `next_a`, `next_e`, `next_event*`; `whilenot*`;
built-ins `prev()`, `next()`, `rose()`, `fell()`, `stable()`, `ended()`, `isunknown()`,
`countones()`, `onehot()`, `onehot0()`, `nondet()`, `nondet_vector()`; LTL keywords
`X X! F G U W`; OBE (`AX AG AF AU EX EG EF EU A E`); `forall`, `%for`, `%if`, `inherit`, `vmode`,
`vprop`, `endpoint`, `const`, `function`, `report`, `severity`, `union`, parameter sets, HDL
comparisons and bit operators; negation of non-Boolean properties; every simple-subset violation
(e.g. `(always a) -> b`, `a until (next b)`, `(next a) before b`, `never (next a)`); SERE
antecedents / `never` operands that match the empty word. `tests/psl/test_parser_subset.py`
checks each of these.

## 6. Translation (properties -> monitors)

```
.psl text --parser--> surface AST --desugar (IEEE 1850 definitions)--> core NNF formula
  --formula progression + Brzozowski SERE derivatives, ACI normalisation--> progression graph
  over the property's letters (valuations of its APs allowed by the event model)
  --SCC analysis (generalised Buechi on strong obligations)--> step verdict per state
  --neutral end-of-path evaluation--> close verdict per state
  --Moore minimisation--> transition table  --code generation--> generated/psl_monitors_{A,B}.py
```

Desugaring: `never b = always !b`; `never {r} = always ({r} |-> false)`; `eventually! b = true
until! b`; `a before b = (!a && !b) until (a && !b)`; `a before_ b = (!a && !b) until a`;
`p until_ b = p until (p && b)`; `{r} |=> p = {r ; true} |-> p`; `b -> p` keeps the
implication (vacuous when no letter is left); `next[n]` = n nested `next`.

The generated module carries `SOURCE_SHA256` over the `.psl` files, the event model and the
compiler sources. The runtime refuses to load stale tables (`MonitorStale`), and the production
image build runs `python -m psl.compiler check`. Editing a property and rebuilding regenerates
the machine (`tests/psl/test_regeneration.py` edits P3 and observes the new behaviour); there is
no per-`property_id` hand-written check function.

## 7. How the translation is validated

* `tests/psl/test_translation_vs_reference.py` compares every generated machine with an
  **independent reference interpreter** (`psl/reference.py`) that evaluates the *surface* syntax
  directly by its semantic definitions -- it shares only the parser with the compiler (no
  desugaring, no derivatives, no progression):
  * close verdicts must be identical on every trace (exhaustive up to length 3-4, plus random
    traces up to length 14);
  * step verdicts are checked against bounded sets of infinite lasso extensions of the trace
    (`V` => none satisfies, `S` => all satisfy, `P` => both kinds exist; the bounded search may be
    inconclusive for some `P` states, which is counted and bounded);
  * besides the project's properties, 400 randomly generated simple-subset formulas are checked.
* `tests/psl/test_property_traces.py` executes hand-derived expected verdicts (normal, missing,
  swapped, duplicated events, deny-then-execute, mid-trace end, timeout, capacity) through the
  generated tables and the runtime. These expectations are an oracle written from the property
  text; no hand-written state machine is used as the monitor.
* `tests/psl/test_pep_start.py` (PEP, not translation): the pre-execution record,
  `audit_pre_recorded` and `execution_started` happen in the tool thread before the original
  function; a refused start keeps the function from running; tickets are single use and bound to
  the arguments; 16 concurrent critical starts each get their own durable record; an audit
  append does not wait for another writer's fsync.
* Bugs found by this cross-check during development (fixed before any experiment): weak `next`
  at the end of a complete path, vacuous implication on the empty path (both in the compiler);
  `next[0]` at the end of the path (in the reference).

## 8. Policy layer (Zero Trust Backplane)

`zt_psl.compiler.compile_policy_set` turns PSL files + a field catalogue into a policy set.

* **Field catalogue** (`policy_fields.yaml`, signed like the policies): scopes, their events,
  and every field with type (`string`, `int`, `bool`, `enum` with values) and *trusted source*.
  Field families (`subject.role.*`) may declare `missing: false` (absent role = false); any
  other field a rule needs but the runtime did not supply raises `UnboundField` and the caller
  must deny. Unknown fields, type mismatches, enum values outside the declaration and fields
  not defined at any event of a temporal scope are compile errors.
* **Annotations** -- structured comments above a declaration (`// @rule`, `@nl`, `@source`,
  `@on_violation DENY|REAUTHENTICATE|MANUAL_REVIEW`, `@permit`, `@obligation TYPE(k=v)`,
  `@runtime`, `@note`; on the vunit `@policy_set`, `@version`). Unknown or misplaced
  annotations are errors. Files stay plain PSL for any other tool.
* **Request rules** (request scope): `@permit` properties (Boolean) and invariants
  `always b` / `never b`. Anything else is rejected ("request rules must be invariants"). The
  compiler adds `R_default_deny: always (EVENT -> (permit_1 || ... || permit_n))`. The PDP
  evaluates the Boolean body of each invariant directly (the automaton of `always b` is "stay
  while b, violate on !b"); `tests/test_policy_sets.py::test_fast_path_matches_reference_interpreter`
  checks this against the reference interpreter (6,000 checks).
* **Decision (deny-overrides)**: every applicable rule must hold. Outcome = strictest
  `@on_violation` among violated rules (DENY > REAUTHENTICATE > MANUAL_REVIEW); otherwise ALLOW,
  or ALLOW_WITH_OBLIGATIONS with the union of the obligations of the permissions that hold.
  No priorities: adding a rule can only make a decision stricter (tested).
* **Rule selection (guard index)**: every field is still read and type-checked for every
  request, but a rule is only *evaluated* when its guard matches -- an equality
  `field == literal` in the top-level conjunction of a permission, of a constraint's antecedent
  (`always (A -> C)`) or of a `never` body. A false guard makes the permission false and the
  constraint vacuously true, so skipping is exact; rules without a guard are always evaluated.
  `tests/test_guard_index.py` compares the indexed engine with exhaustive evaluation on the real
  store and on generated policy sets; the 552,960-request differential report is unchanged.
* **Temporal rules** (temporal scope): compiled to automata as in §6; comparison atoms are data
  APs of the events whose fields they read.
* **Signing**: detached Ed25519 signature per file (`NAME.sig.json`) over the file name and the
  SHA-256 of its exact bytes; verified against the caller's trust store before compilation.

