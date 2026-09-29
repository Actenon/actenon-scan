# AREF-001 — Final report

Thirty sections. Written to be read by someone who did not watch the work and
will not read the other ten documents unless this one tells them to.

**Verdict, up front: `ARCHITECTURE NOT READY`.** The architecture is complete,
internally consistent and validated. It is not ready because six load-bearing
decisions depend on evidence (REI-001, REI-001B, REI-002) that is not accessible
in this environment, and five of those six are unrecoverable if guessed wrong.
Section 28 is the argument; section 30 is the recommendation.

---

## 1. Task identity and interpretation

The task was an **architecture freeze**, explicitly not an implementation:
produce the AREF-001 research and specification artefacts for **Resource Effect
Inference (REI)**, in a new isolated directory, without touching production
code, tests, configuration or existing evidence.

Two things had to be interpreted, and both interpretations are declared rather
than assumed:

1. **What REI is.** The term is not defined anywhere in the repository. It is
   taken to mean the capability that closes the gap `docs/ARCHITECTURE.md`
   states in its own limitations list: *"No semantic API models. Sink rules are
   pattern-matched, not modelled as structured semantic objects (effect
   category, resource parameters, severity characteristics, etc.)."* That
   reading is corroborated by the absence of any `resource` term in
   `authority_binding.py`, while `action` and `parameters` both exist.
2. **The seven architecture questions.** These were not transmitted verbatim.
   They are derived from the repository's own stated constraints, frozen as
   Q1–Q7, and their derivation basis is tabulated in
   [06-ARCHITECTURE-QUESTIONS.md](06-ARCHITECTURE-QUESTIONS.md) §6.0 so that a
   reviewer holding the original list can diff against them. The frozen
   decisions do not depend on the question wording, so a mismatch costs one
   file.

## 2. Prohibition compliance ledger

Thirteen prohibitions, each with how it was honoured, are tabulated in
[00-SCOPE-AND-FREEZE.md](00-SCOPE-AND-FREEZE.md) §0.5. In summary: nothing
outside `specs/AREF-001/` was created or modified; no repository was searched
for, cloned, identified or browsed; no GitHub search of any kind was performed;
no experiment was re-run; no REI code exists; no PR was opened or modified;
nothing was pushed.

One adjacent hazard is worth restating because a reviewer grepping the
repository will hit it: `docs/COVERAGE.md`, `docs/RECALL.md` and
`tests/benchmark/recall_methodology.md` contain *architecture coverage row*
identifiers of the form `r01`…`r09`. Those are tool-exposure archetypes in the
coverage contract, not repositories. AREF-001 cites none of them and depends on
none of them.

## 3. Pre-work repository state

Recorded before any artefact was written.

```
$ git status --short
(no output — working tree clean)

$ git rev-parse HEAD
b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16

$ git branch --show-current
main
```

`b8a6a62` is `Feat/cross language reachability (#95)`. Package version `1.5.0`.
Every claim AREF-001 makes about the scanner is a claim about this commit;
§7.6 of [07-RISKS-AND-FALSIFICATION.md](07-RISKS-AND-FALSIFICATION.md) lists
what invalidates the freeze if it moves.

## 4. Evidence discovery procedure

Seven searches, all reproducible, tabulated in
[01-EVIDENCE-AVAILABILITY.md](01-EVIDENCE-AVAILABILITY.md) §1.1: a token search
across the working tree, an exact-token extraction from the single match, a
commit-message search across all 68 refs, a filename search across the whole
filesystem, the agent persistent store, the conventional hand-off directories,
and the remote ref list.

The one grep hit was a false positive: `research/reachability-ground-truth/evidence.json`
matched `AREF` only through the substring `areful`, inside the English word
"careful".

## 5. Evidence availability result

**REI-001: NOT AVAILABLE. REI-001B: NOT AVAILABLE. REI-002: NOT AVAILABLE.**

No artefact bearing any of those identifiers exists in the working tree, in any
reachable git ref, in the agent store, or anywhere on this filesystem.

Per the task's explicit instruction, the fact is recorded and nothing was
invented or re-derived: no experiment was re-run, no proxy measurement was
substituted, and no number is attributed to REI-001, REI-001B or REI-002
anywhere in this directory. The consequence is §28.

## 6. Accessible evidence, and why it is not a substitute

`research/reachability-ground-truth/` is accessible: 3.7 MB, a full inventory,
a seeded stratified sample, 160 human labels, adjudication rules, chains,
analysis and a full-scan verification pass.

It is **reachability** evidence — "can an agent-controlled boundary reach this
sink?" REI asks "given that a sink is reached, what does it act on?" A
perfectly resolved call path tells you nothing about whether
`cursor.execute(q)` removes one row or the table.

It was used for exactly three architectural purposes, none of them a
resource-effect measurement (itemised as U-1…U-3 in §1.4):

- the demonstrated fact that **name-based inference is this repository's
  dominant false-positive mechanism** — `_name_looks_db` matched receiver names
  by unanchored substring, `"sandbox"` contains `"db"`, and a shell executor was
  reported as destructive SQL at HIGH severity. This is the whole basis of D-07;
- the demonstrated fact that **an analysis layer can ship enabled and resolve
  almost nothing** — 2 followed call edges against 3,297 unfollowed, 0 of 22
  confirmed cases caught, invisible until resolution was measured separately
  from findings. This is the whole basis of D-13;
- the standing rule that where a relationship cannot be established the state
  is `UNKNOWN / RUNTIME VERIFICATION REQUIRED`, never `AUTHORISED`.

## 7. Problem statement

The scanner's per-call-site record carries location, `rule_id`, `category`,
`severity`, `confidence`, `call_text`, `guard_status`, `reachability_reason`,
`tier` and `language`. Every one of those is a property of **the rule that
matched** or of **the path that reached it**. None is a property of **what the
call acts on**.

Three consequences are visible in the shipped code:

1. **Effect is rule-scoped, not call-scoped.** `effect_for_rule_id` is a pure
   function of the rule ID, so every `DATA-DELETE-SQL` match yields
   `DATA_DELETION` whether the statement is `DELETE FROM users WHERE id = ?` or
   `DROP DATABASE prod`.
2. **Authority binding has no resource term.** The repository states the binding
   problem as six terms — principal, action, resource, parameters, tenant,
   constraints. `action` exists (`extract_action_label`,
   `infer_sink_action_label`), `parameters` exists (`authority_binding.py`),
   **`resource` exists nowhere in the codebase**.
3. **The gap is already documented as the next step**, in
   `docs/ARCHITECTURE.md`'s own limitations list.

## 8. Scope — in

Seven items, S-01…S-07 ([00-SCOPE-AND-FREEZE.md](00-SCOPE-AND-FREEZE.md) §0.3):
the per-site structured record; the data-only catalogue; the additive versioned
output; the composition rules; the opt-in gating; the invariants; the validation
plan.

## 9. Scope — out

Ten items, X-01…X-10 (§0.4). The ones that shape the design rather than merely
excluding work: no provider-specific rules (prohibited, and the repository's
recorded FP mechanism); no severity change (blocked on B-01); no interprocedural
resource propagation (the codebase has no interprocedural taint); no
cross-language resource unification; and no selection, identification or
inspection of any future validation repository — no such repository is named,
searched for or referenced anywhere in this directory.

## 10. Terminology, and one disambiguation that is load-bearing

The repository already uses **resource boundary** to mean an *entrypoint class*
— an HTTP route handler driven by an external client rather than by a model.
REI introduces **resource** to mean *the object a sink acts upon*. Unrelated
concepts, one word.

This is not a style question. Commit `f472a57` records a shipped defect whose
root cause was exactly this conflation: "`resource_boundary` signals produce
HIGH confidence reachability, but the pretty output said 'agent entry point' for
ALL signals — conflating externally-callable HTTP endpoints with model-callable
entrypoints."

**D-12** therefore mandates: existing names keep `resource_boundary`; every REI
name is `resource_effect*` / `ResourceKind` / `ResourceScope`; no
`ResourceKind` member may denote an entrypoint; and the config key is top-level
`resource_effects`, **not** nested under `reachability`. Invariant **I-08** is
the regression test.

## 11. The fourteen frozen decisions

Stated in full with reasons in [02-ARCHITECTURE.md](02-ARCHITECTURE.md) §2.4.

| | Decision |
|---|---|
| D-01 | REI is a non-gating annotation layer |
| D-02 | The unit of inference is the sink call site — exactly one record, possibly unknown |
| D-03 | Five inferred components: effect, kind, selector, scope, controllability |
| D-04 | The effect vocabulary is `EffectType`; no parallel taxonomy |
| D-05 | The resource vocabulary is a new **closed** enum with a mandatory sentinel |
| D-06 | Selector extraction is declared as data, never written as per-rule code |
| D-07 | `unknown` is the default; **no name-based resource inference in v0** |
| D-08 | Certainty reuses `AnalysisCertainty`, weakest link, capped by reachability |
| D-09 | No severity change in v0 |
| D-10 | Output is additive, versioned, and absent when off |
| D-11 | Opt-in for at least one minor release |
| D-12 | "Resource boundary" and "resource effect" never share a name |
| D-13 | A disclosure counter is mandatory, not optional |
| D-14 | Rule-ID normalisation is explicit, language-aware and total |

The three doing the most work are D-01 (it makes the safety argument structural
rather than empirical), D-07 (it forecloses the repository's known FP mechanism)
and D-13 (it forecloses the repository's known silent-failure mechanism).

## 12. Pipeline placement

After `_collect_files` → `detect_sinks` → `detect_reachability` → guards →
`Finding`/`Capability` construction → the optional repository layer. REI then
annotates. Diagram in §2.2; the engine delta is one flag-guarded call site
(§4.2).

The placement is why precision (16/16), recall (9/10 synthetic, 3/10
corpus-demonstrated) and soundness (6/6) are invariant under REI **by
construction**: all three are computed from the `findings` list, and REI has no
code path that reaches it. `annotate_capabilities` mutates in place and returns
only counters; `ResourceEffect` is immutable.

## 13. Data model

```
ResourceEffect = effect × kind × selector? × scope × controllability
                 × certainty × rule_id × normalised_rule_id × language
                 × catalogue_status × unresolved_reason?
ResourceSelector = text × origin × certainty
```

`kind` is non-nullable with an `unknown_resource` member; `selector` is
nullable. That asymmetry is deliberate: it puts the difference between "cannot
classify" and "nothing to classify" in the type, where a consumer can see it.
Full model in [03-DATA-MODEL.md](03-DATA-MODEL.md).

## 14. The resource vocabulary

Twenty `ResourceKind` members including the `unknown_resource` sentinel —
deliberately the same granularity as `EffectType`'s twenty. Full table with
illustrative rules in §3.3.

`database_table` is present but unreachable in v0. That is stated rather than
hidden: it is the member B-04 would activate, and omitting it would force a
schema bump the moment that decision is taken.

**The list is frozen as a schema, not as a finding.** Whether these are the
right twenty for real code is B-02.

## 15. Catalogue design

One JSON file, keyed by normalised rule ID and language. Each entry declares a
resource kind, a selector location (argument positions, argument keywords, or
the receiver), a scope rule, a certainty ceiling, and a status.

Three independent reasons for data over code (D-06): the task prohibits
provider-specific rules; the repository already puts matching knowledge in JSON
and documents that as the extension path; and the repository's own recorded
dominant FP mechanism is code-resident name heuristics. A declared argument
position has no equivalent failure mode — a position either exists in the call
or it does not.

Keyword policy: lowercase, vendor-neutral names only. No CamelCase SDK
parameter and no provider-branded field appears anywhere in the catalogue,
because a vendor keyword list in a data file is a provider-specific rule wearing
a different hat. The `NET-EGRESS` keyword set is copied verbatim from that
rule's own `escalate_when.arg_keywords`, so it introduces nothing new.

## 16. Selector and scope extraction

Selector: read the declared position or keyword; report the exact source
segment, its syntactic origin (one of eight, §3.6), and a certainty. `absent`
and `dynamic` are distinct origins on purpose — `absent` means the declaration
may be wrong, `dynamic` means no declaration could have helped. Collapsing them
would make the catalogue unimprovable.

Scope: four values, but only `single` and `set` are reachable in v0, and only
from an explicit catalogue declaration. Every rule whose scope depends on a
predicate reports `unknown`. This is stated as a limitation, not as modesty, and
it is most of falsifier F-2.

## 17. Certainty and UNKNOWN semantics

Certainty is `AnalysisCertainty`, combined weakest-link, with `analysis_error`
dominating and reachability as a hard ceiling. Per-status ceilings: `frozen` →
`strong`, `draft` → `heuristic`, `blocked`/`absent` → `unknown`. **`proven` is
unreachable in v0 for every rule** — a static argument-position read is not a
proof, and claiming otherwise is the overstatement the repository's
`UNKNOWN`-first stance exists to prevent.

Four UNKNOWN rules (§3.8): unknown is a value never an omission; unknown is
never promoted; unknown is counted; unknown carries a machine-readable reason
from a closed set of ten. The closed reason set is the load-bearing part — it is
what makes the catalogue improvable, because counting reasons distinguishes a
coverage gap from a wrong declaration from a genuine language limit.

## 18. Interface freeze

Signatures only, no bodies, in [04-INTERFACES.md](04-INTERFACES.md) §4.1. The
six frozen properties that matter: `infer_resource_effect` is keyword-only and
**total** (no exception, no `None` — a crash in an annotation layer must never
fail a scan that already has its findings); `annotate_capabilities` mutates in
place and returns only counters; `ResourceEffect` is immutable;
`is_determined()` is the only sanctioned consumer predicate; no function takes a
`Finding`.

## 19. Output surface

JSON gains `rei_schema_version`, a catalogue version, four counter/breakdown
keys, and an optional `resource_effect` object per record. SARIF gains a
properties-bag entry only — `level` does not move, because it drives
code-scanning severity in consumers that have never heard of REI. Pretty,
markdown and HTML gain one line, rendered only when `certainty >= heuristic`,
and never phrased as a narrowing claim when unknown.

Absent-when-off rather than null-when-off, so "did this scan run REI?" is
answerable by key presence.

## 20. Configuration and gating

`--resource-effects` (default off), config `resource_effects.enabled`
(default `false`), Action input `resource-effects` (default `false`). Opt-in for
at least one minor release, following the `--repository-analysis` and
`--resource-boundary` precedents — the latter was *made* opt-in in "Task 4c" on
the stated ground that a route decorator is not evidence an agent is involved.

One implementation obligation is recorded and deliberately **not** performed
here: `_KNOWN_KEYS` in `actenon_scan/rules/loader.py` must be extended, or the
loader's own unknown-key warning fires on a key the scanner documents.

## 21. Composition with existing layers

REI consumes from six layers (sink rules, reachability, `EffectType`, taint,
certainty, cross-language detectors), annotates one (`capability.py`), and
produces for one that is **not yet connected** (`authority_binding.py`, which
is B-06). It does not interact with guards or the cache. Full table in §6 of
[06-ARCHITECTURE-QUESTIONS.md](06-ARCHITECTURE-QUESTIONS.md) Q5.

That asymmetry is the architecture's main structural claim: REI is a leaf, so it
can be added or removed without disturbing anything upstream. It is also why the
usefulness question is entirely deferred — a leaf that nothing reads is useful
only to a human, and whether a human is helped is a measurement nobody here has
made.

## 22. Invariants and test obligations

Twelve invariants, twelve named obligations `AREF-001-T01`…`T12`, with
locations, in [05-INVARIANTS.md](05-INVARIANTS.md). **None was written** —
writing them would modify `tests/`.

The most important is T01: an *ordered-list* equality assertion on findings with
and without the flag. Ordered, not set, because a reordering changes the
most-exposed ranking in `report/blast_radius.py`.

§5.2 states plainly what no test in the list can establish: every invariant is a
*safety* property. None shows that a single inferred resource is correct, that
the twenty kinds are the right twenty, or that a reader's decision improves.
"Provably harmless" is not "proven useful", and the distinction is the substance
of the verdict.

## 23. JSON schemas and validation result

Four schemas, all JSON Schema 2020-12, all validated:

```
schema/resource-effect.schema.json            record; 20+20+4+6+6+8+10 enum members,
                                              6 conditional rules
schema/resource-effect-catalogue.schema.json  catalogue; 5 conditional rules encoding
                                              the status/ceiling table
schema/rei-report-fragment.schema.json        additive report delta; references the
                                              record schema rather than restating it
schema/aref-001-manifest.schema.json          this directory's manifest
```

`validate.py` result at completion:

```
55 checks passed, 0 failed
```

Covering: four schemas parse and are valid 2020-12; ten positive instances
validate; **nineteen negative instances are rejected** (twelve record cases,
seven catalogue cases), each for a stated reason; the draft catalogue conforms,
has unique keys, contains no `frozen` entry, and names a blocked decision on
every blocked entry; the vocabularies agree; the catalogue covers every shipped
rule ID exactly; the schema's effect enum equals `EffectType`; and the manifest
matches the files on disk.

The negative cases matter more than the positive ones. A schema that accepts
everything is not a constraint, and the conditional rules are where the frozen
decisions actually live — `certainty: proven` is rejected outright, a `blocked`
entry cannot yield `strong`, a `frozen` catalogue entry cannot declare no
selector, and a `receiver_patterns` field cannot be smuggled into a selector
declaration.

## 24. Catalogue coverage over the shipped rules

```
python      31 entries  vs  31 rule IDs in default_rules.json    exact match
typescript   9 entries  vs   9 rule IDs in detectors/typescript.py  exact match
go           9 entries  vs   9 rule IDs in detectors/go.py          exact match
            ──────────
            49 entries, 49 unique keys, 0 frozen, 38 draft, 11 blocked
            19 of 20 ResourceKind members used (database_table reserved for B-04)
```

Zero `frozen` entries is the catalogue's substantive statement, and
`validate.py` fails if one appears. Promoting an entry to `frozen` asserts its
declared selector location is correct **on real call sites**, and that assertion
requires the REI-001 measurement.

## 25. Cross-document contradiction check

Nine axes compared; full audit in
[10-CONTRADICTION-CHECK.md](10-CONTRADICTION-CHECK.md). **Three contradictions
were found and resolved**, and they are recorded rather than quietly fixed:

- **C-1** — two meanings of "resource" in one report. Resolved by D-12, the
  top-level config placement, and I-08. This is the repository's own shipped
  defect class (`f472a57`).
- **C-2** — a catalogue ceiling the catalogue could raise by itself: the first
  draft let `max_certainty` take any value, so an edit could mint `proven`.
  Resolved in three layers — catalogue schema restricts the field, record schema
  rejects `proven`, and I-06 is a test obligation over every entry.
- **C-3** — a "frozen" catalogue inside a freeze that is NOT READY. The first
  draft marked well-known positional rules as `frozen`/`strong`, contradicting
  B-03. Resolved: no entry is `frozen`, the schema's `frozen` branch keeps
  coverage through a clearly-labelled illustrative example, and `validate.py`
  enforces it.

Two pre-existing observations about the shipped scanner were recorded and
**not** fixed, because fixing them would be a scanner change: `_RULE_ID_TO_EFFECT`
carries one rule ID no Python rule emits (§10.4), and `effect_for_rule_id`
returns `None` for 8 of the 9 rule IDs the Go detector emits, because it strips
only `-WEAK` and `-UNBOUND` (§10.5). The second is the empirical basis for D-14.

One residual inconsistency is disclosed rather than resolved (§10.11): the
record schema restates three Python enum member lists, which is duplication of
the kind D-04 forbids inside the codebase. It is unavoidable — a JSON Schema
cannot import a Python enum — and it is mitigated by a `validate.py` check and
by invariant I-07.

## 26. Risk register

Twelve risks, R-01…R-12, in
[07-RISKS-AND-FALSIFICATION.md](07-RISKS-AND-FALSIFICATION.md) §7.1. Four carry
residual risk that this freeze cannot remove:

- **R-01** a wrong resource line discrediting a correct finding — unmitigable
  without B-05;
- **R-05** scope unknown everywhere, so the component that justified the record
  carries no information — honest but useless;
- **R-12** the missing evidence contradicting a *frozen* decision rather than
  just a blocked one — unquantifiable without the evidence, and the honest
  reason a freeze built on absent evidence cannot be called ready.

R-02 (all-unknown misread as clean) is the one high-likelihood risk with a
complete mitigation, precisely because the repository has already paid for that
lesson once.

## 27. Falsification criteria

Four falsifiers with thresholds fixed in advance (§7.2), so the measurement
cannot be argued after the fact:

| | Falsifier | Threshold | Source |
|---|---|---|---|
| F-1 | Declarative extraction insufficient | selector resolved on < 50% of real sites | REI-001 |
| F-2 | Scope carries no information | `scope == unknown` on > 90% of real sites | REI-001 |
| F-3 | Vocabulary wrong | one kind absorbs > 50% of determined sites, or > 20% need a member that does not exist | REI-001 |
| F-4 | Annotation harms the reader | readers shown the line adjudicate worse than readers shown none | REI-002 / human study |

And what validation must **not** be: "the fixtures pass". A catalogue that
matches its own fixtures and nothing else would satisfy all twelve invariants,
report `unknown` for every real site, and be indistinguishable from correct on
the evidence available here. The disclosure counter is the only instrument that
would catch it, which is why D-13 is mandatory rather than recommended.

## 28. Blocked decisions and the required evidence

Six decisions, B-01…B-06, are recorded unresolved in
[08-BLOCKED-DECISIONS.md](08-BLOCKED-DECISIONS.md), each with options, costs, the
measurement that would close it, and what breaks if it is taken anyway.

| ID | Decision | Wrong-guess cost | Recoverable? |
|---|---|---|---|
| B-01 | Does `scope: all` escalate severity? | Precision-gate failures; scope errors and sink-rule errors become permanently inseparable | No |
| B-02 | Is the twenty-member vocabulary right? | Post-release churn destroys the release-to-release diffability that justified closing the enum | No |
| B-03 | Which rules can have their selector extracted declaratively? | Some entries yield `absent`, visible in the counters | **Yes** |
| B-04 | Is SQL parsing in v0? | The middle option (a `WHERE`-presence regex) produces a false *narrowing* claim — the forbidden error direction | No |
| B-05 | What threshold makes REI default-on? | Credibility loss that survives turning the flag back off | No |
| B-06 | Does the resource feed authority binding in v1? | A presentation error becomes a soundness error | No |

**Five of six are unrecoverable. One is recoverable and self-reporting.**

An architecture is ready for implementation when its unresolved questions are
the recoverable kind. These are not, and the evidence that would close them is
not accessible. That — and nothing about the design being wrong — is the
verdict.

What would flip it (§8.2): make the three evidence artefacts accessible;
re-derive B-01…B-06 against them using the options and thresholds already
enumerated; confirm no *frozen* decision is contradicted (R-12), for which the
contradiction check is written to be re-runnable; and supersede AREF-001 with
AREF-002. Nothing in D-01…D-14 needs to change. If step three finds no
contradiction, step four is a mechanical transcription.

## 29. Non-modification proof

```
$ git diff -- actenon_scan tests
(no output)

$ git diff --stat HEAD -- actenon_scan tests
(no output)

$ git status --short
?? specs/
```

`git diff` against both the index and `HEAD` is empty for `actenon_scan` and
`tests`. `git status --short` shows a single untracked path, `specs/` — the new
isolated directory. Nothing else in the tree is modified, staged or deleted.

All twenty-six created files are under `specs/AREF-001/`; `git status --short
--untracked-files=all` lists nothing outside it.

The artefacts are deliberately left **uncommitted and unpushed**: the task
forbade pushing and forbade opening or modifying a PR, and leaving them
untracked makes `git status --short` itself the non-modification proof.

### Behavioural non-interference, checked rather than assumed

Two further checks, because "no diff" proves the files are unchanged, not that
the tool's behaviour is unchanged by a new top-level directory.

**Self-scan.** `python3 -m actenon_scan scan .` over the whole repository:
69 files scanned, **0 findings**, 0 analysis errors. `validate.py` is not
agent-reachable, calls no sink, and writes nothing, so the self-scan-clean
property holds with `specs/` present.

**Test parity against a pristine checkout.** The suite was run twice — once in
the working tree with the artefacts present, once against a clean extraction of
`b8a6a62` (`git archive HEAD | tar -x -C /tmp/...`), both excluding the slow
corpus and benchmark directories:

```
working tree :  25 failed, 531 passed, 119 skipped, 1 xfailed, 16 subtests
pristine HEAD:  25 failed, 531 passed, 119 skipped, 1 xfailed, 16 subtests
```

Identical, including the failure list. The 25 failures are pre-existing in this
environment (missing optional extras and tooling: Go and TypeScript
tree-sitter parsers, the protocol pin's dependency, git/gh-dependent install
tests) and are **not** attributable to AREF-001. They were not investigated
further and not fixed — both would be scanner work this task prohibits.

## 30. Artefact manifest and recommendation

### Files created

Twenty-six files, all under `specs/AREF-001/`, nothing anywhere else: thirteen
markdown documents, one validator, four JSON schemas, one draft catalogue, five
schema-instance examples, and the two manifest files.

```
specs/AREF-001/README.md
specs/AREF-001/00-SCOPE-AND-FREEZE.md
specs/AREF-001/01-EVIDENCE-AVAILABILITY.md
specs/AREF-001/02-ARCHITECTURE.md
specs/AREF-001/03-DATA-MODEL.md
specs/AREF-001/04-INTERFACES.md
specs/AREF-001/05-INVARIANTS.md
specs/AREF-001/06-ARCHITECTURE-QUESTIONS.md
specs/AREF-001/07-RISKS-AND-FALSIFICATION.md
specs/AREF-001/08-BLOCKED-DECISIONS.md
specs/AREF-001/09-IMPLEMENTATION-PLAN.md
specs/AREF-001/10-CONTRADICTION-CHECK.md
specs/AREF-001/REPORT.md
specs/AREF-001/validate.py
specs/AREF-001/schema/resource-effect.schema.json
specs/AREF-001/schema/resource-effect-catalogue.schema.json
specs/AREF-001/schema/rei-report-fragment.schema.json
specs/AREF-001/schema/aref-001-manifest.schema.json
specs/AREF-001/catalogue/resource-effect-catalogue.draft.json
specs/AREF-001/examples/resource-effect.valid.json
specs/AREF-001/examples/resource-effect.invalid.json
specs/AREF-001/examples/catalogue.valid.json
specs/AREF-001/examples/catalogue.invalid.json
specs/AREF-001/examples/rei-report-fragment.valid.json
specs/AREF-001/MANIFEST.json
specs/AREF-001/MANIFEST.sha256
```

### SHA-256 manifest

Per-file digests are in `MANIFEST.json` (schema-validated) and in
`MANIFEST.sha256` (the flat `sha256␣␣path` form, checkable with
`sha256sum -c`). `MANIFEST.json` and `MANIFEST.sha256` are excluded from their
own inventory, and the manifest deliberately carries **no timestamp**, so it is
reproducible from the files alone:

Both commands run from the repository root, because manifest paths are
repository-relative:

```bash
python3 specs/AREF-001/validate.py --print-manifest | diff - specs/AREF-001/MANIFEST.json
sha256sum -c specs/AREF-001/MANIFEST.sha256
```

### Recommendation

> ## ARCHITECTURE NOT READY

The architecture is complete, internally consistent, schema-validated, and
free of contradictions after three were found and resolved. Fourteen decisions
are frozen with reasons grounded in this repository's own code and its own
recorded failures. Twelve invariants are specified with named test obligations.
Four JSON schemas validate, and nineteen negative cases are provably rejected.

It is **not ready for implementation** because six decisions are blocked on
evidence that is not accessible in this environment, and five of those six are
unrecoverable if guessed wrong: a wrong answer to B-01 permanently conflates two
error sources, a wrong answer to B-02 destroys the diffability that justified
closing the vocabulary, a wrong answer to B-04 ships a false *narrowing* claim,
a wrong answer to B-05 costs credibility that survives a rollback, and a wrong
answer to B-06 converts a presentation error into a soundness one.

Declaring readiness on that basis would be a false assurance about an
architecture whose entire design rationale is that false assurance is worse than
a reviewable false positive.
