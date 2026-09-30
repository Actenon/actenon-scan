# AREF-002 — Implementation plan

**Status:** frozen as a **specification**. Nothing in this document has been
executed. No production code, configuration, rule or test has been written or
modified by this freeze.
**Parent:** [AREF-002.md](AREF-002.md)

This document states what building AREF-002 would involve: the slices, their
order, their acceptance criteria, the test registry, the integration decisions
that are deliberately deferred, and the invariants that must hold at every step.

> **Not implemented.** `git diff -- actenon_scan tests specs/AREF-001` is empty.
> The only files created by AREF-002 are under `specs/AREF-002/`.

---

## 1. Constraints the implementation inherits

These are not negotiable and are not AREF-002's inventions; they are this
repository's existing commitments.

| Constraint | Source |
|---|---|
| Detection must not change — helpers GROUP and RANK existing findings, never filter, add or reclassify | `actenon_scan/report/blast_radius.py`, "RULE 5" |
| Existing per-file findings are never suppressed | `docs/ARCHITECTURE.md` principle 3 |
| Never move a benchmark number by changing a fixture | `CONTRIBUTING.md` Rule 3 |
| False assurance is worse than a reviewable false positive | repository stance |
| `resource_boundary` keeps its existing meaning: an entrypoint class | commit `f472a57` |

The first two mean the claim layer is **parallel output**, not a modifier of
findings. The third means every validation number comes from a hashed,
pre-sealed ground truth ([validation_protocol.md](validation_protocol.md) §4).
The fourth is why `ABSTAIN` is the default verdict and why the coverage ledger is
mandatory. The fifth is a naming prohibition, tested by `AREF-002-T21`.

---

## 2. Shape of the change

The claim layer sits **beside** the existing pipeline, consuming capabilities and
producing claims, receipts and a ledger. It does not sit inside `detect_sinks`,
does not require a sink match to run, and does not write into `Finding`.

```
_collect_files ──► detect_sinks ──► detect_reachability ──► guards ──► Finding / Capability
                                                                   │
                                          (capabilities, and sink matches as EVIDENCE ONLY)
                                                                   ▼
                              invocation enumeration ──► claim instantiation
                                                                   ▼
                              evidence acquisition (ladder, budgeted descent)
                                                                   ▼
                              obligation states ──► counter-evidence ──► verdict
                                                                   ▼
                              EffectClaim · EffectReceipt · CoverageLedger
```

Invocation enumeration is new work and is the load-bearing part: it must enumerate
**every** call site in a capability's analysed region, independent of rule
matching. Existing sink matching becomes one evidence producer feeding the
acquisition layer.

---

## 3. Slices

Each slice is independently testable and independently revertible, and each ends
with the layer still off by default. Ordering is by dependency, not by appetite.

### Slice 1 — Domain model and schemas

Types for `EffectClaim`, `ImplementationCandidate`, `EvidencePacket`,
`ProbeOutcome`, `EffectReceipt`, `CoverageLedger`, and the closed vocabularies.
Serialisation validated against the frozen schemas in this directory.

*Acceptance:* every schema validates its positive examples and rejects its
negative examples; round-trip serialisation is lossless; no type carries a
`rule_id` in its identity.

### Slice 2 — Invocation enumeration

Enumerate all call sites in a capability's analysed region, per language, with
stable `invocation_id`s.

*Acceptance:* on a fixture where the sink corpus matches nothing, every call site
is still enumerated; enumeration is deterministic; ids are stable across runs and
across unrelated edits elsewhere in the file.

This slice is where the architecture is won or lost. If enumeration is
rule-influenced anywhere, requirement 2 fails and the rest is decoration.

### Slice 3 — Claim instantiation by non-refutation

Instantiate one claim per `(capability, invocation, enabled effect class)` unless
proven inert. v1 has one enabled class, so one claim per invocation.

*Acceptance:* `AREF-002-T01` and `AREF-002-T02` pass; claim count equals
invocation count on a fixture with no rule matches; every claim's initial state is
five `UNKNOWN` obligations and verdict `ABSTAIN`.

### Slice 4 — Evidence packets and admissibility

Packet type, the `PROBATIVE` / `HYPOTHESIS_ONLY` decision, verbatim extract
capture and locator recording. Sink matches become packets here, admissibility
keyed by `match.type`.

*Acceptance:* `AREF-002-T03`, `AREF-002-E03`, `AREF-002-E05`, `AREF-002-E06`,
`AREF-002-E08` pass; a fidelity checker re-reads every locator and compares bytes.

The fidelity checker is written **in this slice**, not later. It is the cheapest
possible defence against the worst possible defect, and it is a declared
disqualifying condition of validation.

### Slice 5 — Obligation state machine and verdict function

The §4.2 assignment rules, §4.3 aggregation, and the §5.1 verdict function from
[proof_obligations.md](proof_obligations.md), including `NO_EFFECT` closure
C1–C6.

*Acceptance:* `AREF-002-T04`…`T11`, `T13`…`T16` pass; the state function is
order-independent under packet permutation; closure is unit-tested condition by
condition, each in isolation.

### Slice 6 — Ladder tiers L0–L2

Local syntax/binding, local bodies and wrapper chains, declarations.

*Acceptance:* a locally wrapped write is resolved through the wrapper;
`AREF-002-D07` passes — a partially followed chain settles nothing the unfollowed
remainder would have settled.

### Slice 7 — Bounded descent, budgets, frontier

The seven budgets, deterministic traversal order, cycle handling, per-run caching,
and frontier recording.

*Acceptance:* `AREF-002-D01`…`D07`, `D10`…`D12` pass; a deliberately tiny budget
produces `ABSTAIN` with `BUDGET_EXHAUSTED` and a populated frontier, never a
guessed obligation.

### Slice 8 — Ladder tiers L3–L5

Package provenance, manifests and lockfiles, pinned dependency source when
present in the tree.

*Acceptance:* `AREF-002-D08` passes — every dependency-sourced packet carries
package name and version resolution, including `UNPINNED`; `AREF-002-D09` passes —
no network access, no installation, no execution of analysed code.

### Slice 9 — Ladder tiers L6–L7

Machine-readable contracts and underlying operation semantics.

*Acceptance:* `AREF-002-T06` and `AREF-002-T07` pass — an HTTP POST with no
contract yields `OPERATION`/`PERSISTENCE` `UNKNOWN`, and identical source
differing only in the operation contract yields different `OPERATION` states;
`AREF-002-E07` passes — an unparsed statement yields `UNKNOWN`, never a
keyword-prefix inference.

Slice 9 is the highest-risk slice, because L6/L7 availability in real repositories
is the unsolved problem named in [REPORT.md](REPORT.md) Q10. It is built anyway
and early enough to measure, because the measurement is the point.

### Slice 10 — Counter-evidence probes

The closed registry from [proof_obligations.md](proof_obligations.md) §7, with
`found` / `not_found` / `incomplete` outcomes and the `BLOCKING` gate.

*Acceptance:* `AREF-002-T12` passes — an incomplete `BLOCKING` probe forces
`ABSTAIN` even with all five obligations otherwise `SUPPORTED`; every registered
probe has a positive and a negative fixture.

### Slice 11 — Receipts and coverage ledger

The eleven-answer receipt and the ledger, in every output format.

*Acceptance:* `AREF-002-T18` and `AREF-002-T19` pass; a run with zero
`PROVEN_EFFECT` emits a ledger and no output path renders it as "safe", "clean" or
"no effects"; the frontier is enumerated up to its cap with the true total
reported.

### Slice 12 — Integration, off by default

Opt-in flag, additive versioned output, absent keys when off, and the existing
gates demonstrably unchanged.

*Acceptance:* `AREF-002-V09` passes — precision 16/16, soundness 6/6 and the
recall figures are byte-identical with the layer on and off; no severity,
category or exit code changes.

### Slice 13 — Validation execution

Execute [validation_protocol.md](validation_protocol.md): preregister, seal
ground truth, run once, report all eight measurement families, and run the
`AREF-002-V04` empty-rule-corpus control.

*Acceptance:* the protocol is followed without amendment; the outcome is one of
the §8.6 vocabulary.

### Slice 14 — Post-validation decisions

Only after slice 13, and only as separately recorded decisions: default-on
(B-05), severity integration (B-01), a resource-kind vocabulary if the observed
frequency table justifies one (B-02, D-05), and additional effect classes.

---

## 4. Ordering rationale

Slices 1–5 build the ontology and its semantics before any acquisition, so that
the first thing that exists is *claims with honest `ABSTAIN` verdicts*. That
output is already useful — it is a census of unproven possible effects with
reasons — and it makes every later slice measurable as an increase in what can be
settled.

The inverse order is the trap. Building acquisition first produces a pile of
evidence with nowhere principled to put it, and the pressure to let a
`HYPOTHESIS_ONLY` signal settle something becomes overwhelming. Building
`PROVEN_EFFECT` before `ABSTAIN` produces a scanner that shows findings.

---

## 5. Risks

| Risk | Mitigation | Residual |
|---|---|---|
| Claim explosion — every call site is a claim | Instantiation is cheap; investigation is budgeted and prioritised; the gap is the ledger | Output volume is large; presentation must default to `PROVEN_EFFECT` plus ledger summary, with `ABSTAIN` claims available but not dumped |
| Abstain-on-everything | Measured directly; a run with abstention > 0.95 is `INVALID` | The architecture may be honest and nearly useless on repositories without vendored dependencies — **the primary residual risk** |
| L6/L7 evidence rarely available | Measured as tier histogram and first-broken-component N | Unsolved; [REPORT.md](REPORT.md) Q10 |
| Admissibility leakage under delivery pressure | Two-value vocabulary; `AREF-002-T03`; audited in validation; declared an architecture failure, not a tuning failure | Requires discipline, not just tests |
| Performance | Budgets; per-run caching; marginal per-tier cost accounting | L5 on a large `node_modules` may be expensive; the budget bounds it visibly |
| Non-determinism under truncation | Total ordering in [dependency_descent.md](dependency_descent.md) §3.3 | Cross-platform path normalisation must be exercised on every supported OS |
| Silent reintroduction of the sink gate | `AREF-002-T02` and the `AREF-002-V04` empty-corpus control | A control run is cheap and must be kept in CI, not run once |

---

## 6. Test registry

Tests are written **before** the code in their slice, because every id below is an
architectural property rather than a regression guard.

| Registry | Source | Ids |
|---|---|---|
| Obligations, states, verdicts, contradictions, probes | [proof_obligations.md](proof_obligations.md) §8 | `AREF-002-T01`…`T20` |
| Evidence acquisition and admissibility | [evidence_acquisition.md](evidence_acquisition.md) §9 | `AREF-002-E01`…`E12` |
| Descent, budgets, frontier | [dependency_descent.md](dependency_descent.md) §8 | `AREF-002-D01`…`D12` |
| Validation obligations | [validation_protocol.md](validation_protocol.md) §9 | `AREF-002-V01`…`V10` |

One additional test is registered here because it is a naming constraint rather
than a semantic one:

| Id | Invariant |
|---|---|
| `AREF-002-T21` | No AREF-002 identifier, field name or output key reuses `resource_boundary` or any existing name whose meaning differs. `resource_boundary` keeps its existing meaning — an entrypoint class — and the obligation is named `BOUNDARY` in its own namespace. |

Slice-to-registry mapping:

| Slice | Ids |
|---|---|
| 1 | schema validation, `AREF-002-T18` (structure only), `AREF-002-T21` |
| 2 | enumeration determinism, `AREF-002-T02` (existence half) |
| 3 | `AREF-002-T01`, `AREF-002-T02` |
| 4 | `AREF-002-T03`, `E03`, `E05`, `E06`, `E08` |
| 5 | `AREF-002-T04`…`T11`, `T13`…`T16`, `T20` |
| 6 | `AREF-002-E01`, `E02`, `D07` |
| 7 | `AREF-002-D01`…`D06`, `D10`…`D12`, `T15`, `E09`, `E10` |
| 8 | `AREF-002-D08`, `D09`, `E11`, `E12` |
| 9 | `AREF-002-T05`…`T07`, `E07` |
| 10 | `AREF-002-T12` |
| 11 | `AREF-002-T17`, `T18`, `T19` |
| 12 | `AREF-002-V09` |
| 13 | `AREF-002-V01`…`V08`, `V10` |

---

## 7. Deferred integration decisions

Each is deferred **with its gate stated**, so that deferral is a decision rather
than an omission.

| Decision | Deferred until | Gate |
|---|---|---|
| Default-on | after slice 13 | all §8.1 thresholds met, no §8.2/§8.5 violation ([validation_protocol.md](validation_protocol.md)); AREF-001 B-05 |
| Severity or exit-code influence | after slice 13, then a separate recorded decision | `PROVEN_EFFECT` precision ≥ 0.90 and fidelity 1.00; AREF-001 B-01's conflation warning is the reason for the gate |
| Whether a verdict projects onto `AnalysisCertainty` | after slice 11 | must not change any existing finding's certainty; AREF-001 D-08 as modified |
| Whether claims attach to `Finding` for reporting convenience | after slice 11 | must not make claim existence depend on a finding; a presentation join only |
| Network or registry fetch of pinned dependency source | not in v1 | requires a separate security and reproducibility review; L5 is tree-local in v1 ([evidence_acquisition.md](evidence_acquisition.md) §2.6) |
| A closed resource-kind vocabulary | after slice 13 | an observed frequency table with a "needed a member that does not exist" bucket; AREF-001 B-02 / D-05 |
| Additional effect classes | after slice 14 | one class at a time, each with its own obligation set and its own validation; requirement 19 |
| Wiring the existing unused `cfg.py` control-flow graph | not in v1 | `ACTIVATION` uses existing reachability in v1; a CFG is an accuracy improvement to be measured separately |

Nothing in this table may be implemented early on the grounds that it would be
convenient. Each gate exists because taking the decision without the measurement
is unrecoverable in the specific way AREF-001's B-01 described: once escalation
ships, "the rule was wrong" and "the inference was wrong" produce the same
symptom and become permanently inseparable.

---

## 8. Definition of done for the architecture, not the code

AREF-002 is complete as an architecture when this directory's artefacts are
frozen, hashed and internally consistent. It is complete as an **implementation**
only after slice 13 reports an outcome from the §8.6 vocabulary. Those two are
deliberately different milestones, and conflating them is how a controlled-corpus
result becomes a real-world claim.
