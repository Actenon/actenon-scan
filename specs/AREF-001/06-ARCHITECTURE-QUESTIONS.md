# AREF-001 §6 — The seven architecture questions

## 6.0 Provenance of the questions

The task required that AREF-001 "answer all seven explicit architecture
questions". The seven questions were **not transmitted verbatim** with the
task text. Rather than answer questions that were not asked, or silently pick
seven convenient ones, they are derived below from the constraints the task and
the repository do state, and then frozen as Q1–Q7 so that a reviewer holding
the original list can diff against them.

Derivation basis:

| Source | What it demands an answer to |
|---|---|
| `docs/ARCHITECTURE.md` "No semantic API models" | *What* is being modelled (→ Q1) |
| `docs/ARCHITECTURE.md` principle 3, `blast_radius.py` "RULE 5" | *Where* it sits and whether detection can change (→ Q2) |
| `docs/ARCHITECTURE.md` "Where to add new analysis" | Whether the model is closed or open, and how it extends (→ Q3) |
| `docs/ARCHITECTURE.md` principle 1 (`UNKNOWN` never promoted) | How unknowns are represented (→ Q4) |
| `repository/` layer composition (`certainty.py`, `taint.py`, `authority_binding.py`) | How it composes with what exists (→ Q5) |
| Task 4c `--resource-boundary` opt-in precedent; `report/json_out.py` legacy-key policy | How it is gated and rolled out (→ Q6) |
| `CONTRIBUTING.md` benchmark-integrity rules; the reachability study's hostile self-audit | How it is validated and what would falsify it (→ Q7) |

**If the original seven differ, Q1–Q7 must be re-derived.** The frozen
decisions D-01…D-14 are independent of the question wording, so a mismatch
costs a rewrite of this file and nothing else.

---

## Q1 — What exactly does REI infer, and what does it deliberately refuse to infer?

**Infers**, per sink call site, five things: the effect verb (reusing
`EffectType`), the resource *kind* (a new closed enum of twenty), the resource
*selector* (the source text of the selecting expression plus its syntactic
origin), the *scope* (`single` / `set` / `all` / `unknown`), and the
*controllability* of the selector (reusing `TaintLattice`).

**Refuses to infer**, in v0, and each refusal is a frozen decision rather than
a missing feature:

| Refusal | Decision | Reason |
|---|---|---|
| Resource kind from any identifier, variable, receiver, docstring or path name | D-07 | The repository's own dominant FP mechanism. `_name_looks_db` matched by unanchored substring; `"sandbox"` contains `"db"`; a shell executor was reported as destructive SQL at HIGH |
| Resource identity across function boundaries | X-06 | There is no interprocedural taint in the codebase. A selector that is a parameter is reported *as a parameter*, not chased |
| Scope from a predicate (SQL `WHERE`, glob, recursive flag) | B-04 | Requires statement parsing; unauthorised without evidence |
| Tenancy | §2.5 | No static signal exists. An absent field is honest; a guessed one is not |
| Authorisation | §2.5 | REI says what a call acts on. Whether that is permitted is the authority-binding question, and where it cannot be established the state stays `UNKNOWN / RUNTIME VERIFICATION REQUIRED` |

The refusals are the more important half of the answer. A resource inferencer
that guesses is worse than none, because the guess arrives wearing the same
formatting as a fact.

---

## Q2 — Where does REI sit, and can it regress existing precision or recall?

**Placement:** a non-gating annotation layer, after detection, after
reachability, after guards, after the optional repository layer. Its only
output is a field on an already-final record (D-01). Its engine delta is one
call site guarded by a flag (§4.2).

**Can it regress precision or recall? No — and the "no" is structural, not
measured.** Precision, recall and soundness are all computed from the
`findings` list. REI has no code path that reaches that list: `annotate_capabilities`
mutates `Capability` objects in place and returns only counters, and
`ResourceEffect` is frozen (§4.1). Invariant **I-01** pins the property with an
ordered-list equality assertion, and **I-02** pins severity separately because
severity feeds exit codes.

This is the strongest available form of the argument and it is why the placement
was frozen first. A layer that *could* change a finding would need its own
precision measurement before shipping — which would need the evidence that is
missing. A layer that provably cannot change a finding needs only
`AREF-001-T01`.

**What it can still regress:** reader trust and wall-clock time. A wrong
`resource:` line on a correct finding makes the correct finding look
unreliable. That risk is real, is not covered by any invariant, and is
R-01/R-02 in [07-RISKS-AND-FALSIFICATION.md](07-RISKS-AND-FALSIFICATION.md).
It is also the direct reason the layer is opt-in (D-11) and the direct reason
the verdict is NOT READY.

---

## Q3 — Is the model closed or open-ended, and how does it extend?

**Closed, on both axes, with a mandatory sentinel on each.**

- Effect verbs: closed to `EffectType` (D-04). REI adds no member and no
  parallel taxonomy. Sentinel: `unknown_effect`.
- Resource kinds: closed to `ResourceKind`, twenty members (D-05). Sentinel:
  `unknown_resource`.
- Scope: closed, four members. Sentinel: `unknown`.
- Unresolved reasons: closed, ten members (§3.8 U-4).

**Extension path**, deliberately identical in shape to the one
`docs/ARCHITECTURE.md` already documents for `EffectType`: add the member, add
the mapping, bump the schema `enum`, add the test. The schema bump is the
friction that matters — it makes a vocabulary change visible in a diff to
someone who is not reading the Python.

**Why closed.** Three properties depend on it, and all three are properties this
repository already wants. A closed set can be diffed between releases, which is
what makes "this change grants your agent a new class of power" computable —
the stated purpose of the capability model in `actenon_scan/capability.py`. A
closed set can be mapped onto authority action labels; free text cannot. And a
closed set makes a malformed catalogue fail at load rather than at render, which
matters because a catalogue that degrades silently to all-unknown is
indistinguishable from a repository with no resources.

**What is *not* closed:** the *membership* of `ResourceKind`. Twenty members
derived from thirty-one shipped rules and sixteen categories is a plausible
starting vocabulary, not a measured one. That is B-02, and it is one of the six
reasons for the NOT READY verdict.

---

## Q4 — How are unknowns represented, and can an unknown become a safety claim?

**Representation:** four rules, §3.8. Unknown is a *value* (`unknown_resource`,
`scope: unknown`, `certainty: unknown`), never an omitted key. Every site gets a
record (I-03). Every unknown carries a machine-readable
`unresolved_reason` from a closed set of ten (U-4). Every unknown is counted in
a mandatory disclosure counter emitted in every format, always (D-13, I-11).

**Can an unknown become a safety claim? No, and three separate mechanisms are
frozen to prevent it:**

1. **Type.** `unknown_resource` is a member of the enum, so there is no state in
   which the field is missing and a consumer defaults it to something benign.
2. **Predicate.** `is_determined()` is the only sanctioned consumer test, and it
   requires *both* a determined kind *and* certainty above `unknown` (§4.1).
   The obvious wrong test — `kind != UNKNOWN_RESOURCE` — is documented as
   forbidden precisely because it admits a determined kind on an
   unknown-certainty record.
3. **Rendering.** Unknowns are rendered as `resource: not determined
   (<reason>)` or omitted, never as a negative claim (U-2). No report string may
   read as "narrow scope" or "no resource" when the truth is "not established".

**Why the closed reason set is the load-bearing part.** Counting reasons is what
makes the catalogue improvable. `rule_id_not_in_catalogue` means the next unit
of work is coverage; `declared_argument_absent` means a declaration is wrong;
`selector_is_dynamic` means the language genuinely defeats the analysis. Free
text would be unreadable in aggregate — which is the state D-13 exists to
escape, not to reproduce in a new field.

---

## Q5 — How does REI compose with the layers that already exist?

| Existing layer | Composition | Direction |
|---|---|---|
| Sink rules (`detectors/sinks.py`, `rules/default_rules.json`) | REI is keyed by the rule ID they emit, after normalisation (D-14). It adds no pattern, no module name, no function name | REI consumes |
| Reachability (`detectors/reachability.py`) | Supplies the certainty ceiling (D-08, I-05). REI never adds or removes a reachability signal, and `resource_boundary` stays an entrypoint class with no resource meaning (D-12, I-08) | REI consumes |
| Guards (`detectors/guards.py`) | No interaction in v0. A guard's presence does not change a resource, and a resource does not change a guard verdict | independent |
| `EffectType` / `effect_summary.py` | Supplies the effect vocabulary (D-04). REI does **not** participate in `propagate_effects` in v0 — interprocedural resource propagation is out of scope (X-06) | REI consumes |
| `taint.py` | Supplies `controllability` (D-03). REI runs no taint analysis of its own; where the existing function-local dataflow does not reach, `controllability` is `unknown` | REI consumes |
| `certainty.py` | Supplies the lattice and `combine_certainty` (D-08) | REI consumes |
| `authority_binding.py` | **The intended consumer, but not in v0.** REI supplies the missing `resource` term of the six-term binding problem. Whether v1 wires it in is B-06 | REI would produce |
| `capability.py` | REI annotates `Capability` in place. No new `CapabilityState`; `GUARD_FOUND` / `REVIEW_REQUIRED` semantics are untouched | REI annotates |
| Cache (`cache.py`) | No interaction. The per-file content-hash cache does not cover the repository layer today; REI inherits that and claims no cached correctness (§2.5) | independent |
| Cross-language (`repository/cross_language_reach.py`, `detectors/go.py`, `detectors/typescript.py`) | REI is keyed by rule ID, so TS and Go sites are annotatable — provided normalisation is language-aware, which is D-14 and is why the draft catalogue covers their rule IDs | REI consumes |

**The consistent direction is worth naming: REI consumes from six layers and
produces for one, and the one is not yet connected.** That asymmetry is the
architecture's main structural claim — REI is a leaf, so it can be added and
removed without disturbing anything upstream. It is also the reason the
usefulness question is entirely deferred: a leaf that nothing reads is only
useful to a human reader, and whether a human reader is helped is a measurement
nobody here has made.

---

## Q6 — How is REI configured, gated, and rolled out without breaking consumers?

**Gating.** Opt-in for at least one minor release: `--resource-effects`
(default off), config `resource_effects.enabled` (default `false`), Action input
`resource-effects` (default `false`) — D-11, §4.4.

**Precedent, not invention.** Two layers in this repository shipped opt-in for
the same class of reason. `--repository-analysis` shipped off by default.
`--resource-boundary` was *made* opt-in in "Task 4c", on the stated ground that
"a route decorator is not evidence that an agent is involved" — that is, a
signal was demoted because it answered a different question than the headline
one. REI's field answers a genuinely new question, and one release behind a flag
is the cheapest way to learn what it breaks in consumers nobody enumerated.

**Config placement.** `resource_effects` is a new **top-level** key, not a member
of `reachability` (D-12). Nesting it under `reachability` would put two
different meanings of "resource" in one object, which is the conflation commit
`f472a57` had to repair. This requires extending `_KNOWN_KEYS` in
`actenon_scan/rules/loader.py` in the implementing work order, or the loader's
own unknown-key warning fires on a documented key — recorded as an
implementation obligation in §4.4, **not** done here.

**Consumer compatibility.** Additive and absent-when-off (D-10, I-09). JSON
gains new top-level keys and a new optional per-record object; no existing key
changes type or meaning. SARIF changes only the properties bag — `level` in
particular does not move, because it drives code-scanning severity in consumers
that have never heard of REI. With the flag off, output is byte-identical to
today's, which `AREF-001-T09` pins with a golden file.

**Rollout sequence** (specified, not executed — see
[09-IMPLEMENTATION-PLAN.md](09-IMPLEMENTATION-PLAN.md)): schema and catalogue
first, inference behind the flag second, output surfaces third, disclosure
counters with the first output change and not later, default-on **never**
without the B-05 measurement.

---

## Q7 — How will REI be validated, and what result would falsify this architecture?

**Two distinct validations, and conflating them is the failure mode to avoid.**

*Safety validation* — that REI makes nothing worse — is the twelve invariants
in [05-INVARIANTS.md](05-INVARIANTS.md). It needs no corpus and no new evidence.
It is mechanically checkable and it is complete.

*Usefulness validation* — that an inferred resource is correct and that
knowing it changes a reader's decision — needs measurement against real code:
a per-rule selector-extraction rate, a per-kind false-classification rate, and a
scope-correctness rate. **That evidence is exactly what REI-001, REI-001B and
REI-002 would supply, and it is not accessible** ([01-EVIDENCE-AVAILABILITY.md](01-EVIDENCE-AVAILABILITY.md)).
No proxy was substituted and no experiment was re-run, per the task's explicit
instruction.

**The four results that would falsify this architecture**, stated as
predictions so that they can fail:

| # | Falsifier | What it would refute | Forced response |
|---|---|---|---|
| F-1 | Declarative argument-position extraction succeeds on fewer than half of real sink sites | D-06 — that a data-only catalogue is sufficient | Either accept an all-unknown layer as honest but useless, or reopen code-based extraction with a measured FP budget. Not a tweak |
| F-2 | `scope` is `unknown` for substantially every site | The usefulness of the whole record: `single` vs `all` was D-03's justification | REI v0 has no reason to ship. Close B-04 first or abandon |
| F-3 | Twenty `ResourceKind` members prove to be the wrong granularity — a single member absorbs most sites, or most sites need a member that does not exist | D-05's membership (B-02) | Revise the vocabulary *before* shipping. A vocabulary change after release breaks the diffability that justified closing the enum |
| F-4 | Readers shown a resource line make *worse* decisions than readers shown none | D-01 — the premise that an annotation is harmless | Withdraw the layer. This is the only falsifier that no static measurement can reach, and the strongest argument for keeping it opt-in |

**What validation must not be.** Not "the fixtures pass". A layer whose
catalogue matches its own fixtures and nothing else would pass all twelve
invariants, report `unknown` for every real site, and be indistinguishable from
correct on the evidence available here. `CONTRIBUTING.md` Rule 3 exists because
this repository has already had a benchmark number moved by adjusting a fixture
instead of fixing a detector; the same failure is available to REI, and no
invariant in §5 would catch it. The disclosure counter (D-13) is the only
instrument that would, which is why it is frozen as mandatory rather than
recommended.
