# AREF-001 §2 — Architecture

## 2.1 The gap, stated precisely

At the frozen commit the scanner produces, per consequential call site, a
`Finding` and a `Capability` (`actenon_scan/engine.py`,
`actenon_scan/capability.py`). Between them they carry: location, `rule_id`,
`category`, `severity`, `confidence`, `call_text`, `guard_status`,
`reachability_reason`, `tier`, `language`.

Everything in that list is a property of **the rule that matched** or of **the
path that reached it**. Nothing in it is a property of **what the call acts
on**.

Three consequences are visible in the shipped code:

1. **Effect is rule-scoped, not call-scoped.** `effect_for_rule_id`
   (`actenon_scan/repository/effect_summary.py`) is a pure function of the
   rule ID. Every `DATA-DELETE-SQL` match yields `DATA_DELETION`, whether the
   statement is `DELETE FROM users WHERE id = ?` or `DROP DATABASE prod`.
2. **Authority binding has no resource term.**
   `actenon_scan/repository/authority_binding.py` compares an authority call's
   *action label* and *parameters* against a sink's. The repository's own
   statement of the binding problem (`research/reachability-ground-truth/README.md`)
   lists six terms — principal, action, resource, parameters, tenant,
   constraints. `action` exists (`extract_action_label`,
   `infer_sink_action_label` in `guard_semantics.py`); `parameters` exists;
   **`resource` does not exist anywhere in the codebase.**
3. **The gap is already documented as the next step.** `docs/ARCHITECTURE.md`:
   "No semantic API models. Sink rules are pattern-matched, not modelled as
   structured semantic objects (effect category, resource parameters, severity
   characteristics, etc.). The `EffectType` catalogue is a first step in this
   direction."

REI supplies the missing term.

## 2.2 Pipeline placement

REI is an **annotation layer**. It runs after detection is complete and writes
additively onto records that already exist. It has no authority to create,
remove, reorder, reclassify or re-score a finding.

```
                        existing pipeline (UNCHANGED)
  ┌───────────────────────────────────────────────────────────────────┐
  │ _collect_files → detect_sinks → detect_reachability → guards      │
  │                → Finding / Capability construction                │
  │                → [optional] repository layer (engine_augment)     │
  └───────────────────────────────────────────────────────────────────┘
                                    │
                    (findings, capabilities, ruleset, AST cache)
                                    │
                                    ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │                 REI — resource_effect.py  (NEW, opt-in)           │
  │                                                                   │
  │  for each Capability c:                                           │
  │     entry  := catalogue.lookup(normalise(c.rule_id))              │
  │     call   := locate_call(c.file, c.line, c.col)                  │
  │     sel    := extract_selector(call, entry.selector)              │
  │     scope  := classify_scope(call, entry.scope_rule)              │
  │     ctrl   := taint_state_of(sel)      # existing lattice          │
  │     cert   := combine(entry.max_certainty, sel.certainty,          │
  │                       reachability_certainty(c))                   │
  │     c.resource_effect := ResourceEffect(...)  # ADDITIVE ONLY      │
  └───────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
          report/json_out · sarif · pretty · markdown · html
              (additive fields only; absent when layer is off)
```

The placement is the single most important frozen decision, because it makes
the safety argument structural rather than empirical: a layer that only ever
*adds a field* to an already-decided record cannot change the finding count,
the severity distribution, the precision benchmark, or the recall benchmark.
The invariant is checkable by a test that runs the same scan twice and
compares the finding lists (invariant **I-01**).

## 2.3 Module layout (proposed — not created by this task)

```
actenon_scan/repository/
└── resource_effect.py        # ResourceKind, ResourceScope, ResourceSelector,
                              # ResourceEffect, infer_resource_effect,
                              # load_catalogue, normalise_rule_id
actenon_scan/rules/
└── resource_effects.json     # the shipped catalogue (data only)
tests/repository/
└── test_resource_effect.py   # invariants I-01 … I-12
```

`resource_effect.py` is placed under `repository/` rather than `detectors/`
deliberately: `detectors/` is where *detection* lives, and REI is not
detection. The placement encodes the non-gating property in the directory
structure, where a future contributor will trip over it.

Nothing in the layout requires a change to an existing module's behaviour.
`engine.py` gains one call site behind the opt-in flag; the report modules gain
one additive field each.

## 2.4 The fourteen frozen decisions

Each decision states the decision, the reason, and what evidence in the
repository or in the task constrains it. A decision marked **frozen** may not
be revisited without superseding AREF-001.

---

### D-01 — REI is a non-gating annotation layer

REI never creates, suppresses, reorders or re-scores a finding. Its sole output
is a `resource_effect` field attached to an existing `Capability` (and, where a
`Capability` has a corresponding `Finding`, mirrored onto the `Finding` for
report convenience).

*Reason.* `actenon_scan/report/blast_radius.py` states the project's own
constraint as "RULE 5: detection must not change. These helpers only GROUP and
RANK existing findings; they do not filter, add, or reclassify."
`docs/ARCHITECTURE.md` principle 3 states existing per-file findings are NEVER
suppressed. REI inherits both. The consequence is that the precision (16/16),
recall (9/10 synthetic, 3/10 corpus-demonstrated) and soundness (6/6) gates are
*invariant* under REI by construction, not by measurement.

**Status: frozen.**

---

### D-02 — The unit of inference is the sink call site

One `(file, line, col, rule_id)` tuple — the identity `Capability` already uses
— yields exactly one `ResourceEffect`. Never zero, never more than one. A site
whose resource cannot be determined yields a `ResourceEffect` whose kind is
`unknown_resource`; it does not yield a missing field.

*Reason.* Any other cardinality creates a join problem in every consumer.
"Exactly one, possibly unknown" is the only cardinality that lets a reader
count sites and count unknowns with the same denominator — which is what
invariant **I-11** requires.

**Status: frozen.**

---

### D-03 — The record has five inferred components, not one

`ResourceEffect` is the product of:

| Component | Question it answers | Type |
|---|---|---|
| `effect` | *What is done?* | `EffectType` (existing enum) |
| `kind` | *To what class of thing?* | `ResourceKind` (new closed enum) |
| `selector` | *To which instance(s)?* | `ResourceSelector` (text + origin + taint) |
| `scope` | *To how many?* | `ResourceScope` — `single` / `set` / `all` / `unknown` |
| `controllability` | *Who chose it?* | existing `TaintLattice` state |

*Reason.* `scope` is the component that does not exist anywhere in the current
model and is the one that changes a reader's decision. `DELETE FROM users WHERE
id = ?` and `DELETE FROM users` are the same rule, the same category, the same
severity and the same `EffectType`. They differ only in scope. A capability
report that cannot express that difference cannot rank anything usefully.

`controllability` reuses `TaintLattice` rather than inventing a parallel notion
of "model-controlled", because the argument-sensitive work already landed at
commit `f472a57` established that "what the model controls" is a per-argument
taint property. REI must consume that answer, not re-derive it.

**Status: frozen.**

---

### D-04 — The effect vocabulary is `EffectType`, not a new enum

`ResourceEffect.effect` takes its values from
`actenon_scan.repository.effect_summary.EffectType`. REI introduces **no**
parallel effect taxonomy. Adding an effect verb means adding an `EffectType`
member through the path `docs/ARCHITECTURE.md` already documents ("Where to add
new analysis", step 1).

*Reason.* Two catalogues describing the same thing diverge; the divergence is
then discovered by a user. `EffectType` is already the bridge between rules and
effects and already carries an `UNKNOWN_EFFECT` sentinel. Reusing it also means
REI inherits `propagate_effects` for free if interprocedural resource
propagation is ever authorised (it is not, in v0 — see X-06).

**Status: frozen.**

---

### D-05 — The resource vocabulary is a new *closed* enum

`ResourceKind` is a closed enum with a mandatory `unknown_resource` sentinel.
Free-text resource kinds are forbidden at the type level. The v0 membership is
fixed in [03-DATA-MODEL.md](03-DATA-MODEL.md) §3.3 and in
`schema/resource-effect.schema.json` as a JSON Schema `enum`.

*Reason.* Three properties depend on closure. (a) A closed set can be diffed
between releases, so "this change grants a new resource class" is a computable
statement — which is the capability model's stated purpose
(`actenon_scan/capability.py`: "be told when a change grants it a new power").
(b) A closed set can be mapped to authority action labels; an open set cannot.
(c) A closed set makes the schema self-validating, so a malformed catalogue
fails at load rather than at render.

**Status: frozen.** The *membership* of the enum is **not** frozen — see B-02.

---

### D-06 — Selector extraction is declared as data, not written as code

For each rule ID, *where the resource lives in the call* is declared in
`actenon_scan/rules/resource_effects.json` as an argument position, an argument
keyword, the call receiver, or `unresolved`. There is no per-rule Python, no
per-provider branch, and no module-name or function-name matching introduced by
REI.

*Reason (three independent ones).* First, the task prohibits provider-specific
rules. Second, the repository already puts matching knowledge in JSON
(`default_rules.json`) and treats `CONTRIBUTING.md` "How to add a new sink
rule" as the extension path; a code-based catalogue would fork that convention.
Third and most importantly, the repository's own recorded evidence is that
code-resident name heuristics are its dominant false-positive mechanism:
`_name_looks_db` matched receiver names by unanchored substring, so `"sandbox"`
contained `"db"` and a shell executor was reported as destructive SQL at HIGH
severity. Declarative argument positions have no equivalent failure mode — a
position either exists in the call or it does not.

**Status: frozen.**

---

### D-07 — `unknown` is the default, and there is no name-based resource inference in v0

If the catalogue has no entry for a rule ID, the record is
`kind = unknown_resource`, `scope = unknown`, `certainty = unknown`, with
`unresolved_reason` populated. If the catalogue has an entry but the declared
argument is absent, dynamic, or a non-literal the layer cannot characterise,
the same applies.

REI v0 must **never** infer a resource kind from an identifier name, a variable
name, a receiver name, a docstring, or a file path.

*Reason.* This is `docs/ARCHITECTURE.md` principle 1 ("Every analysis state has
a literal `UNKNOWN` value; nothing labelled `unknown` is ever silently promoted
to `safe`") applied to a new field, plus the `_name_looks_db` evidence cited in
D-06, plus the ground-truth study's explicit finding that name-based
justification was the one classification error its own hostile self-audit
caught and corrected. A heuristic that guesses `users_table` is a
`database_table` will also guess `sandbox` is a database.

**Status: frozen.** Whether a *measured, gated* name heuristic may be
introduced in v1 is B-06's neighbour and is not decided here.

---

### D-08 — Certainty reuses `AnalysisCertainty`, combines by weakest link, and is capped by reachability

`ResourceEffect.certainty` is an `AnalysisCertainty` value
(`actenon_scan/repository/certainty.py`: `PROVEN`, `STRONG`, `HEURISTIC`,
`UNKNOWN`, `UNSUPPORTED`, `ANALYSIS_ERROR`). It is computed with the existing
`combine_certainty` over: the catalogue entry's declared `max_certainty`, the
selector extraction's certainty, and the certainty of the reachability path
that put the capability in the report.

The cap is the substantive part: **resource-effect certainty can never exceed
the certainty of the reachability claim it annotates.** A `PROVEN` resource on
a `HEURISTIC` path is `HEURISTIC`.

*Reason.* `combine_certainty` already implements weakest-link with
`ANALYSIS_ERROR` dominating, and `CallPath.certainty()` already implements the
same idea for paths. Without the cap, REI would let a reader upgrade their
confidence in a path by reading a field that says nothing about the path — the
exact conflation that commit `f472a57` had to fix when "agent entry point" was
printed for HTTP route handlers.

**Status: frozen.**

---

### D-09 — REI changes no severity in v0

`Finding.severity` and `Finding.effective_severity` are untouched. `scope =
all` does **not** escalate. `controllability = model_controlled` does **not**
escalate. No new `escalate_when` clause is introduced.

*Reason.* Escalation is the one REI output that changes exit codes and
therefore breaks builds. The only defensible basis for it is a measured
false-positive rate, which is precisely what the missing REI-002 would supply.
Freezing "no escalation" makes v0 shippable without that evidence; the
escalation decision is B-01.

**Status: frozen for v0.**

---

### D-10 — Output is additive, versioned, and absent when the layer is off

The JSON report gains `rei_schema_version` (a string) at top level and an
optional `resource_effect` object on each capability and each finding. When
the layer is off, `rei_schema_version` is absent and no `resource_effect` key
appears — not `null`, not `{}`. SARIF carries it in the properties bag only.
Pretty/markdown/HTML render one extra line, and only when
`certainty >= HEURISTIC`.

*Reason.* `report/json_out.py` already carries legacy keys for backward
compatibility and already versions its output (`"version": scanner_version`).
Absent-when-off is stricter than null-when-off because it makes "did this scan
run REI?" answerable by key presence, which is what a consumer needs in order
to avoid treating an un-annotated scan as an all-unknown scan.

**Status: frozen.**

---

### D-11 — REI is opt-in for at least one minor release

CLI: `--resource-effects` (default off). Config:
`reachability.resource_effects_enabled` — no; **config key
`resource_effects.enabled`**, deliberately *not* nested under `reachability`,
because REI is not a reachability signal (see D-12).

*Reason.* The repository has an established precedent and an established
reason for it. `--resource-boundary` was made opt-in in "Task 4c" because a
route decorator "is not evidence that an agent is involved", and
`--repository-analysis` shipped opt-in for the same class of reason. A new
field on every capability in every report is a change to every consumer's
output; one release behind a flag is the cheapest way to learn what breaks.

**Status: frozen.**

---

### D-12 — "Resource boundary" and "resource effect" are different concepts and must never share a name

The repository already uses **resource boundary** to mean *an entrypoint class*
— an HTTP route handler driven by an external client rather than by a model
(`reachability_cfg["resource_boundary_decorators"]`,
`resource_boundary_enabled`, the `resource_boundary` signal). REI introduces
**resource** to mean *the object a sink acts upon*. These are unrelated.

The freeze therefore mandates:

- existing names keep the `resource_boundary` prefix and their meaning;
- every REI name uses `resource_effect*` / `ResourceKind` / `ResourceScope`;
- no REI identifier may be named `resource_*` alone;
- a `ResourceKind` member may never denote an entrypoint class. There is no
  `HTTP_ROUTE` resource kind.

*Reason.* This is not pedantry; the repository has already paid for this exact
class of conflation. Commit `f472a57` records the root cause as
"`resource_boundary` signals produce HIGH confidence reachability, but the
pretty output said 'agent entry point' for ALL signals — conflating
externally-callable HTTP endpoints with model-callable entrypoints." Shipping a
second, different meaning of "resource" into the same report is how that defect
recurs, and it would recur in the user-facing text where it is most expensive.

**Status: frozen.**

---

### D-13 — A disclosure counter is mandatory, not optional

The report must carry `resource_effect_known_count` and
`resource_effect_unknown_count` whenever the layer runs, in every output
format, unconditionally — including when the unknown count is the larger
number, and including on a clean scan.

*Reason.* The repository has direct, documented experience of the alternative.
Its transitive-reachability layer shipped enabled by default and resolved
**2 call edges against 3,297 unfollowed**, catching **0 of 22** confirmed
agent-reachable cases — and this was invisible until someone measured
resolution separately from findings. The response was to put
`transitive_unfollowed_count` on every `ScanResult` and in every output path.
REI's failure mode is identical in shape: a catalogue that resolves nothing
looks exactly like a repository with no resources. The counter is the
instrument that distinguishes them, and it must exist from the first release,
not be added after the same lesson is learned twice.

**Status: frozen.**

---

### D-14 — Rule-ID normalisation is explicit, language-aware, and total

The catalogue is keyed by *normalised* rule ID. Normalisation strips the
qualifier suffixes the pipeline appends (`-WEAK`, `-UNBOUND`) and records the
language suffix (`-GO`) as a separate field rather than discarding it. A rule ID
that normalises to nothing known must produce `unknown_resource` with
`unresolved_reason = "rule_id_not_in_catalogue"` — never a silent skip.

*Reason.* This is not a hypothetical. At the frozen commit,
`effect_for_rule_id` strips only `-WEAK` and `-UNBOUND`, so 8 of the 9 rule IDs
the Go detector emits return `None` — reproduced in
[10-CONTRADICTION-CHECK.md](10-CONTRADICTION-CHECK.md) §10.5. The existing
effect model already has this hole. Freezing normalisation explicitly is what
stops REI from inheriting it, and it is why the draft catalogue in this
directory covers the Go and TypeScript rule IDs as well as the Python ones.

The observation is **recorded, not fixed**: fixing `effect_for_rule_id` would be
a scanner change, which this task prohibits.

**Status: frozen.**

## 2.5 What REI explicitly does not do

| | |
|---|---|
| Does not resolve resources across function boundaries | The repository has no interprocedural taint (`docs/ARCHITECTURE.md`). A selector that is a parameter is reported as a parameter with its taint state, not chased to its caller |
| Does not parse SQL in v0 | Blocked — B-04 |
| Does not model tenancy | `tenant` is a PCCB term with no static signal; it stays absent rather than being faked |
| Does not claim authorisation | REI says what a call acts on. It says nothing about whether that action is permitted. The standing rule applies: where the relationship cannot be established the state is `UNKNOWN / RUNTIME VERIFICATION REQUIRED`, never `AUTHORISED` |
| Does not touch the cache | The per-file content-hash cache does not cover the repository layer today; REI inherits that and must not claim cached correctness |
