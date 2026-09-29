# AREF-002 — Delta against AREF-001

**Status:** frozen. Normative. Part of the AREF-002 architecture freeze.
**Parent:** [AREF-002.md](AREF-002.md)
**Subject:** `specs/AREF-001/` — retained unmodified, hashes preserved, status
`SUPERSEDED DESIGN CANDIDATE / NOT AUTHORITATIVE`.

Every one of AREF-001's fourteen frozen decisions is classified below as
**KEEP**, **MODIFY**, **REJECT** or **DEFER**. AREF-001's six blocked decisions
are also resolved, because the evidence that blocked them has since been
supplied.

> **No decision is preserved merely because AREF-001 called it frozen.** Each
> was re-derived from the founding principle — *a consequential effect is a
> claim to be proved, not a sink to be matched* — and kept only where that
> derivation independently produces it.

---

## 1. What AREF-001 got right, and why it still failed

AREF-001 was correct about **hygiene** and wrong about **ontology**.

Its hygiene decisions — do not gate findings, do not change severity without
measurement, disclose your own failures in counters, never infer from names,
keep output additive and versioned, do not overload an existing term — were
derived from this repository's own recorded failures and are re-derived
identically under AREF-002. Five of them are kept outright.

Its ontology decisions — the unit of inference is a *sink call site*, the effect
vocabulary is the existing `EffectType`, resource knowledge lives in a *per-rule
catalogue* keyed by rule ID, and the whole layer *annotates* findings — all
presuppose that an effect is something a rule has already found. Under those
decisions an effect cannot exist where no rule fired, which is exactly the
failure R04 measured: 0 of 17 manually identified consequential paths detected,
with **13 of 17 first broken at "H — semantic resource-effect recognition"**.
Four decisions are rejected for this reason and they are the answer to
[REPORT.md](REPORT.md) Q9.

AREF-001's `ARCHITECTURE NOT READY` verdict was itself correct and is not
disturbed.

---

## 2. Summary

| # | AREF-001 decision | Disposition |
|---|---|---|
| D-01 | REI is a non-gating annotation layer | **REJECT** (ontology) |
| D-02 | The unit of inference is the sink call site — exactly one record | **REJECT** (ontology) |
| D-03 | Five inferred components: effect, kind, selector, scope, controllability | **MODIFY** |
| D-04 | The effect vocabulary is `EffectType`; no parallel taxonomy | **REJECT** (ontology) |
| D-05 | The resource vocabulary is a new closed enum with a mandatory sentinel | **DEFER** |
| D-06 | Selector extraction is declared as data, never per-rule code | **REJECT** (ontology) |
| D-07 | `unknown` is the default; no name-based resource inference | **KEEP** |
| D-08 | Certainty reuses `AnalysisCertainty`, weakest link, capped by reachability | **MODIFY** |
| D-09 | No severity change in v0 | **MODIFY** |
| D-10 | Output is additive, versioned, and absent when off | **KEEP** |
| D-11 | Opt-in for at least one minor release | **KEEP** |
| D-12 | "Resource boundary" and "resource effect" never share a name | **KEEP** |
| D-13 | A disclosure counter is mandatory, not optional | **KEEP** |
| D-14 | Rule-ID normalisation is explicit, language-aware and total | **MODIFY** |

Counts: **KEEP 5 · MODIFY 4 · REJECT 4 · DEFER 1.**

Rejected **because they preserved the sink-centric ontology**: D-01, D-02, D-04,
D-06.

---

## 3. Decision-by-decision

### D-01 — "REI is a non-gating annotation layer" → **REJECT**

**What it said.** REI never creates, suppresses, reorders or re-scores a
finding; its sole output is a `resource_effect` field attached to an existing
`Capability`, mirrored onto the corresponding `Finding`.

**Why rejected.** The rejected part is *annotation layer*, not *non-gating*. An
annotation on an existing finding can only describe things that already became
findings, so the set of describable effects is the set of rule hits. That is the
gate, expressed as a data-model dependency rather than as a conditional.
AREF-002's `EffectClaim` is a **first-class domain object with its own identity**
`(capability_id, invocation_id, effect_class)`, instantiated from an invocation
and existing perfectly well with no finding, no rule and no annotation host.

**What survives.** The non-gating property, strengthened and relocated. REI
still never suppresses or re-scores an existing Actenon finding, but now for a
different reason: claims are a parallel output, not a modifier. The underlying
constraints — `blast_radius.py`'s "RULE 5: detection must not change. These
helpers only GROUP and RANK existing findings; they do not filter, add, or
reclassify" and `docs/ARCHITECTURE.md` principle 3 — are honoured by
construction. They appear in AREF-002 as an integration constraint
([implementation_plan.md](implementation_plan.md) §7), not as the shape of the
domain model.

**Consequence if AREF-001 had been implemented.** The R04 H-class failure would
be structurally preserved: 13 of 17 missed paths had no rule to annotate.

---

### D-02 — "The unit of inference is the sink call site" → **REJECT**

**What it said.** One `(file, line, col, rule_id)` tuple yields exactly one
`ResourceEffect` — never zero, never more than one.

**Why rejected.** The unit carries `rule_id` in its identity. An invocation with
no rule match has no identity under D-02 and therefore cannot produce a record
at all. "Exactly one, possibly unknown" sounds conservative but the conservatism
applies only *within* the rule-matched population; outside it the cardinality is
zero, silently.

AREF-002's unit is the **invocation** — every call site in a capability's
analysed region, rule-matched or not. Identity is
`(capability_id, invocation_id, effect_class)`, and `rule_id` appears nowhere in
it.

**What survives.** The *reason* D-02 gave for its cardinality, which was sound:
a reader must be able to count sites and count unknowns against the same
denominator. AREF-002 satisfies that far better, because its denominator is
invocations enumerated rather than rules matched, and the ratio is reported in
the coverage ledger ([AREF-002.md](AREF-002.md) §10). D-02's "possibly unknown"
becomes AREF-002's `ABSTAIN` verdict, which is a claim, not a missing field.

One cardinality change is deliberate: one invocation can produce several claims,
one per effect class. That is not a join problem, because effect class is part of
the identity.

---

### D-03 — "Five inferred components" → **MODIFY**

**What it said.** `ResourceEffect` = (`effect`, `kind`, `selector`, `scope`,
`controllability`).

**Modified how.** The five components were a flat description of a matched sink.
AREF-002 splits them along the only line that matters — *what must be proved*
versus *what is merely described*:

| AREF-001 component | AREF-002 |
|---|---|
| `effect` | replaced by the **effect class** plus five proof obligations (`IMPLEMENTATION`, `ACTIVATION`, `BOUNDARY`, `OPERATION`, `PERSISTENCE`) |
| `kind` | folded into the `TARGET` descriptor; no closed taxonomy in v1 (see D-05) |
| `selector` | folded into the `TARGET` descriptor as coordinates with per-field resolution state |
| `scope` | retained inside `TARGET`; **never** an obligation, and explicitly not a severity input in v1 (see D-09) |
| `controllability` | becomes the `CONTROL` descriptor, split into `TRIGGER_CONTROL`, `TARGET_CONTROL`, `CONTENT_CONTROL` |

**What survives and why.** D-03's best insight is kept: `scope` is the component
that changes a reader's decision, because `DELETE FROM users WHERE id = ?` and
`DELETE FROM users` are the same rule, category, severity and `EffectType` and
differ only in scope. AREF-002 keeps that distinction and keeps
`controllability` sourced from the existing `TaintLattice` rather than a parallel
notion, since the argument-sensitive work at commit `f472a57` already established
that "what the model controls" is a per-argument taint property.

**What is added.** The split into `TRIGGER_CONTROL` / `TARGET_CONTROL` /
`CONTENT_CONTROL` is forced by REI-002: a fixed-target effect was still
`PROVEN_EFFECT` with `TRIGGER_CONTROL = SUPPORTED` and `TARGET_CONTROL =
REFUTED`. A single scalar `controllability` cannot express that, and any design
that made it gate the verdict would contradict a measured result
([proof_obligations.md](proof_obligations.md) §3).

---

### D-04 — "The effect vocabulary is `EffectType`" → **REJECT**

**What it said.** Reuse the existing twenty-member `EffectType` enum; introduce
no parallel effect taxonomy.

**Why rejected.** `EffectType` is a **sink classification vocabulary**. Its
members name the kind of API that was matched, and it is populated by
`_RULE_ID_TO_EFFECT`, a per-rule-ID mapping. Adopting it as the effect ontology
means the ontology of effects is the catalogue of rules — the exact identity the
founding principle forbids. It also hard-wires the conflation that makes the
architecture wrong: one rule ID maps to one effect, so a single match
simultaneously "establishes" boundary, operation and persistence with no separate
evidence for any of them.

AREF-002's vocabulary is **effect classes with declared obligation sets**. v1
populates exactly one, `EXTERNAL_PERSISTENT_STATE_EFFECT`; nine further classes
are declared-but-unpopulated with obligation sets that deliberately exclude
`PERSISTENCE` ([AREF-002.md](AREF-002.md) §11.3). `EffectType` cannot express
those at all: a message emission is not a persistent-state mutation, and forcing
it to be one is requirement 18's explicit prohibition.

**What survives.** The spirit of "no gratuitous parallel taxonomy". `EffectType`
is not deleted, not changed, and remains the vocabulary of Actenon's existing
sink findings. A rule-derived evidence packet may cite its `EffectType` as
provenance. It simply has no authority over whether an effect exists.

**Incidental confirmation.** The mapping's own state shows the hazard of treating
it as an ontology: `_RULE_ID_TO_EFFECT` has 32 entries against 31 Python rule IDs
with a set difference of `{EXEC-SHELL-GO}`, and `effect_for_rule_id` returns
`None` for 8 of the 9 Go IDs because normalisation strips only `-WEAK` and
`-UNBOUND`. Under D-04 those gaps are missing effects. Under AREF-002 they are
missing *evidence packets*, and the claims still exist.

---

### D-05 — "A new closed `ResourceKind` enum with a mandatory sentinel" → **DEFER**

**What it said.** Twenty closed members plus `unknown_resource`.

**Why deferred rather than kept or rejected.** v1 needs no resource taxonomy.
`EXTERNAL_PERSISTENT_STATE_EFFECT`'s obligations are settled by contract and
implementation evidence; the resource *kind* is a `TARGET` descriptor field used
for presentation and grouping, and free-form coordinates with resolution states
serve that without a closed enum.

AREF-001's own analysis of this is accepted intact and is the reason for
deferral rather than rejection: B-02 recorded that the twenty members were
derived from what the *shipped rules* suggest rather than from what real code
contains, that "those are different populations, and the difference is the whole
question", and that vocabulary churn after release destroys the diffability that
motivated closing the enum in the first place — irrecoverably, because earlier
reports are already written in the old vocabulary.

**Disposition.** No closed resource vocabulary is frozen by AREF-002. If one is
introduced later it must be derived from an observed frequency table over real
sites with an explicit "needed a member that does not exist" bucket — which is
exactly the measurement B-02 named, and which R05/R06 can produce as a
by-product ([validation_protocol.md](validation_protocol.md) §7.5). Deferring
costs nothing now and preserves the one property that cannot be recovered later.

---

### D-06 — "Selector extraction is declared as data, never per-rule code" → **REJECT**

**What it said.** A data-only catalogue keyed by rule ID, supplying argument
positions and keywords for extracting the resource selector, with no per-rule
code anywhere.

**Why rejected.** The catalogue is keyed by rule ID, so it can only describe what
a rule matched; it is the sink-centric ontology in data form. Its cardinality
tells the story — roughly one entry per rule ID against a corpus of 31 Python
plus 9 TypeScript plus 9 Go rule IDs — a bounded table of known things in a
problem whose defining difficulty is unknown things.

AREF-002 replaces it with the **evidence acquisition ladder**
([evidence_acquisition.md](evidence_acquisition.md)): a mechanism keyed by *what
kind of evidence is obtainable*, not by *which rule fired*, which applies
identically to a rule Actenon has and an SDK it has never seen.

**What survives, and it is important.** D-06's motivation was to prevent per-rule
special-case code, and AREF-002 adopts that prohibition and widens it. No
provider-specific signatures, no per-package effect tables, no vendor identifier
lists — required by the task's STRICT RULES and enforced as invariant
`AREF-002-E12` and validation obligation `AREF-002-V05`. AREF-001 wanted rule
knowledge in data rather than code; AREF-002 wants it in **evidence** rather than
either.

The AREF-001 tension its own contradiction check flagged — that `arg_keywords`
is a name match against an argument label, in tension with D-07 — dissolves
here: under AREF-002 any packet whose only anchor is an identifier is
`HYPOTHESIS_ONLY` and can move nothing, so exact-versus-substring keyword
matching is no longer a soundness question.

---

### D-07 — "`unknown` is the default; no name-based inference" → **KEEP**

**What it said.** The default is `unknown`, and no resource is inferred from a
name.

**Kept, generalised, and made the strongest rule in the architecture.** Under
AREF-002: names may generate hypotheses but never establish an effect
(requirement 10); any packet whose only anchor is an identifier is
`HYPOTHESIS_ONLY` and cannot move an obligation state
([evidence_acquisition.md](evidence_acquisition.md) §5.3); and the default state
of every obligation is `UNKNOWN` with the default verdict `ABSTAIN`.

The evidentiary basis is narrowed to what actually holds. Name independence rests
on **REI-001B** — package remasking, second-vocabulary masking, lexical adversary,
30/30 over 30 cases with 165 counterfactual runs. **REI-001 is permanently
INCONCLUSIVE**: its mandatory public/member/variable name-masking counterfactual
had zero valid runs because the experimental transformer renamed a JSON schema
key, and it was not repaired after reveal. No confirmatory weight is placed on
REI-001 anywhere in AREF-002.

The repository's own recorded defect is the concrete reason this is absolute: an
unanchored substring match in `_name_looks_db` let `"sandbox"` satisfy `"db"`, so
a shell executor was reported as destructive SQL at HIGH severity.

---

### D-08 — "Certainty reuses `AnalysisCertainty`, weakest link, capped by reachability" → **MODIFY**

**What it said.** One certainty scalar per record, drawn from the existing
`AnalysisCertainty` enum (`proven`, `strong`, `heuristic`, `unknown`,
`unsupported`, `analysis_error`), combined across components by weakest link and
capped by the reachability certainty.

**Modified how.** A single scalar cannot express what REI-002 requires, because
it cannot say *which part* is uncertain. AREF-002 replaces the scalar with
**five independent per-obligation `ProofState`s** plus **one top-level verdict**.
`BOUNDARY = SUPPORTED` with `OPERATION = UNKNOWN` is a specific, actionable
statement; "certainty: heuristic" is not.

**What survives.** Three things, all load-bearing.

1. **Weakest link**, now as a conjunction: `PROVEN_EFFECT` requires *all five*
   necessary obligations `SUPPORTED`. One `UNKNOWN` yields `ABSTAIN`.
2. **Capped by reachability**, now as an obligation: reachability is
   `ACTIVATION`, and it can independently be `UNKNOWN`, `REFUTED` or `ERROR`
   rather than merely lowering a number.
3. **The separation of `analysis_error` from `unknown`**, which AREF-001 got
   right and which AREF-002 promotes to a first-class `ProofState` `ERROR` and a
   first-class verdict `ANALYSIS_ERROR`. "We did not find out" and "our analysis
   broke" require different responses.

`AnalysisCertainty` itself is untouched and continues to serve existing findings.
Whether a claim verdict is ever projected onto it is an integration question
deferred to [implementation_plan.md](implementation_plan.md) §7.

---

### D-09 — "No severity change in v0" → **MODIFY**

**What it said.** REI changes no severity in v0; `scope: all` does not escalate.

**Modified how.** The prohibition is kept for v1 and its scope is widened: **no
AREF-002 verdict, obligation state or descriptor changes any existing finding's
severity, category or exit-code contribution in v1.** That covers more surface
than D-09 did, because AREF-002 produces more kinds of signal.

The modification is that AREF-002 also freezes the **condition under which the
prohibition could be lifted**, which AREF-001 could not do. B-01 blocked
escalation for want of a measured false-positive rate; R05/R06 preregister
exactly that measurement, with a `PROVEN_EFFECT` precision threshold of ≥ 0.90
and evidence fidelity of 1.00 ([validation_protocol.md](validation_protocol.md)
§8). Severity integration is gated on meeting them, and on a separate decision
recorded after the results are in.

B-01's warning is preserved as the reason for the gate: once escalation ships,
every later precision measurement conflates "the sink rule was wrong" with "the
effect inference was wrong", because both produce the same symptom — a HIGH
finding a triager rejects — and the two error sources become permanently
inseparable.

---

### D-10 — "Output is additive, versioned, and absent when off" → **KEEP**

Kept unchanged and extended to the new artefacts. Claims, receipts and the
coverage ledger are additive top-level output carrying a schema version; when the
layer is disabled the keys are absent rather than empty.

One addition, which is a requirement rather than a preference: **when the layer
is enabled, the coverage ledger is never absent.** Emitting claims without the
ledger would let "0 `PROVEN_EFFECT`" read as "no effects", which requirement 17
forbids ([AREF-002.md](AREF-002.md) §10).

---

### D-11 — "Opt-in for at least one minor release" → **KEEP**

Kept, with the rationale strengthened rather than weakened. AREF-002 is a larger
change than AREF-001 proposed and rests on controlled-corpus evidence only —
REI-001B 30/30 with 165 counterfactual runs and REI-002 36/36 with 126
counterfactual runs, both on constructed corpora. Controlled-corpus success is a
reason to attempt a real-world freeze, not evidence of real-world effectiveness.

Default-on is gated on R05/R06 meeting the preregistered thresholds, which is the
decision B-05 could not take and which is now preregistered.

---

### D-12 — "'Resource boundary' and 'resource effect' never share a name" → **KEEP**

Kept and observed throughout. `resource_boundary` already means an *entrypoint
class* — an HTTP route handler — in this codebase, and commit `f472a57` fixed a
defect caused by exactly that conflation. AREF-002 therefore uses `BOUNDARY`
strictly as a proof obligation about egress from analysed state, never as an
entry surface, and reserves distinct names for distinct concepts:

| Term | Meaning in AREF-002 |
|---|---|
| `CAPABILITY` | a model-reachable entry surface |
| `INVOCATION` | a call site within a capability's analysed region |
| `BOUNDARY` (obligation) | egress from analysed state into an external system |
| `TARGET` (descriptor) | the external resource acted upon |
| `EffectClaim` / `EffectReceipt` | the claim and its auditable record |

`resource_boundary`'s existing meaning is untouched. Any implementation that
reuses the identifier for the obligation is a naming violation, tested by
`AREF-002-T21` (registered in [implementation_plan.md](implementation_plan.md)
§6).

---

### D-13 — "A disclosure counter is mandatory, not optional" → **KEEP**

Kept and **promoted** from a counter pair to a first-class artefact, the
**coverage ledger** ([AREF-002.md](AREF-002.md) §10,
`coverage_ledger.schema.json`). This is the AREF-001 decision that survives most
intact, because it was derived from a real shipped failure rather than from the
rule engine.

That failure is the precedent: transitive reachability shipped enabled with **2
followed edges against 3,297 unfollowed**, caught **0 of 22** confirmed cases,
and was invisible until an explicit `transitive_unfollowed_count` disclosure was
added. AREF-002 generalises the single counter into structural self-reporting:
highest tier reached, stop reason, budget exhaustion by budget name, descent
frontier enumerated with reasons, claims instantiated versus investigated, and
the literal statement that abstained and uninvestigated claims are not negative
results.

---

### D-14 — "Rule-ID normalisation is explicit, language-aware and total" → **MODIFY**

**What it said.** Normalisation of rule IDs across languages must be explicit,
language-aware and total, so that a Go `-GO`-suffixed ID maps to the same effect
as its Python counterpart.

**Modified how.** The requirement is retained but **demoted from a soundness
concern to an evidence-provenance concern**. Under AREF-001 a normalisation miss
meant a missing effect, which is why D-14 needed to be total. Under AREF-002 a
normalisation miss means a missing *evidence packet*: the claim still exists, the
obligations are `UNKNOWN`, the verdict is `ABSTAIN`, and the coverage ledger
reports the gap by language.

Normalisation still matters and is still frozen as explicit and language-aware,
because packet provenance must name the rule correctly and because
cross-language coverage comparison is a validation output. What changes is the
blast radius of getting it wrong.

The concrete gap is unchanged and is now merely a coverage fact: 31 Python sink
rule IDs, 9 emitted by the TypeScript detector, 9 emitted by the Go detector with
a `-GO` suffix, and `effect_for_rule_id` returning `None` for 8 of those 9
because normalisation strips only `-WEAK` and `-UNBOUND`. AREF-002 additionally
requires the ledger to report per-language claim and verdict distributions, so
that a language-skewed rule corpus shows up as skewed *investigation priority*
rather than as silent absence of effects
([evidence_acquisition.md](evidence_acquisition.md) §7).

---

## 4. AREF-001's blocked decisions, resolved

AREF-001 blocked six decisions for want of the REI evidence. That evidence is now
available, and five of the six are resolved by the change of ontology rather than
by the evidence itself.

| Id | AREF-001 question | Resolution under AREF-002 |
|---|---|---|
| B-01 | Does `scope: all` escalate severity? | **Deferred to a post-validation gate.** No severity effect in v1 (D-09 as modified); lifting requires the preregistered R05/R06 thresholds to be met and a separate recorded decision. B-01's conflation warning is the reason for the gate, not an objection to it. |
| B-02 | Is the twenty-member `ResourceKind` vocabulary right? | **Moot for v1 and deferred.** No closed resource vocabulary is frozen (D-05). Any future one must come from an observed frequency table with a "needed a member that does not exist" bucket. |
| B-03 | Which rules can have their selector extracted declaratively? | **Dissolved.** There is no per-rule selector catalogue (D-06 rejected). The equivalent question — which evidence tiers are actually reachable — is answered per claim by the stop reason and aggregated in the coverage ledger. |
| B-04 | Is SQL statement parsing in v0? | **Answered: yes, as ladder tier L7, with abstention on unknown semantics.** REI-002's own conclusion for unrecognised SQL is to abstain, which AREF-002 freezes: a parsed statement is `PROBATIVE` for `OPERATION`; an unparsed one yields `UNKNOWN`, never a keyword-prefix guess. B-04's feared error direction — a false *narrowing* claim — is prevented by that rule. |
| B-05 | What threshold makes the layer default-on? | **Preregistered.** `PROVEN_EFFECT` precision ≥ 0.90, semantic positive recall ≥ 0.30, evidence fidelity = 1.00, inappropriate abstention ≤ 0.20, required-abstention accuracy ≥ 0.90, with a run-invalidating condition at abstention rate > 0.95 ([validation_protocol.md](validation_protocol.md) §8). |
| B-06 | Does the effect record feed authority binding in v1? | **Answered: no.** `AUTHORITY` is a descriptor and *authority is not an obligation of effect* (REI-002). It is recorded in the receipt and never gates a verdict ([proof_obligations.md](proof_obligations.md) §3.3). |

---

## 5. AREF-001 invariants carried forward

AREF-001's twelve invariants `I-01`…`I-12` and their test obligations
`AREF-001-T01`…`T12` are superseded as a set, because eight of them are
predicated on rejected decisions (a per-site record keyed by rule ID, a closed
resource enum, a catalogue with no rule-ID literals in code). They are not
deleted and remain readable in `specs/AREF-001/05-INVARIANTS.md`.

Four have direct successors:

| AREF-001 | AREF-002 successor |
|---|---|
| `I-01` / `I-02` — REI never gates a finding or changes severity | D-09 as modified; integration constraint in [implementation_plan.md](implementation_plan.md) §7 |
| `I-04` — no name-based inference | `AREF-002-T03`, `AREF-002-E05`, `AREF-002-E08` |
| `I-08` — `resource_boundary` is never overloaded | `AREF-002-T21` |
| `I-11` — disclosure counters are mandatory and share a denominator | `AREF-002-T19`, coverage ledger schema |

---

## 6. What this delta does not do

It does not modify, delete, re-hash or re-verdict AREF-001. `specs/AREF-001/`
remains byte-identical, its `MANIFEST.json` and `MANIFEST.sha256` continue to
verify against 24 hashed files totalling 237,251 bytes, and its
`ARCHITECTURE NOT READY` verdict stands as the correct conclusion of that freeze.
AREF-001's status is `SUPERSEDED DESIGN CANDIDATE / NOT AUTHORITATIVE` — a
record of a design that was derived without the evidence, retained so that the
correction is auditable.
