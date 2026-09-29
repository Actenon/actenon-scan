# Mechanical M0 repair contract

This contract targets the reviewed implementation at
`a93b013383ce773b10708d3f30b2a1660e141527`. **No runtime repair has been performed.**
Later repair must preserve sink-independent genesis, set-valued candidates,
immutability/serialization guarantees and existing findings. It must not start
evidence acquisition or M1. The following tests are requirements for that task,
not changes to the current production test tree.

| Finding | SPEC CHANGE | RUNTIME CHANGE | TEST REQUIRED | EXPECTED RESULT |
|---|---|---|---|---|
| H1: candidate IMPLEMENTATION errors disappear | A, D: aggregate all five obligations; labels never overwrite states | In `claim.py` `aggregate_claim_states`, `_validate_claim`, `check_candidate_states`, remove selection-derived state replacement; validate candidate IMPLEMENTATION evidence/errors; derive labels as specified | `H1_error_erased`, `H1_error_bad_selection`, `H1_agreement_hides_error`, valid single/multi error, error-as-abstain; reorder candidate set | Required candidate ERROR survives; aggregate ERROR and ANALYSIS_ERROR; stronger verdict/label input rejected |
| H2: contradictory typed polarity accepted | E: exact registry tuples and uncertainty meaning | `evidence.py` `EvidenceAssertion`, `EvidencePacket._check_predicate` and vocabulary tables validate predicate/obligation/polarity/kind/tier; add typed binding records; retain unknown predicates only as hypotheses | All H2 polarity/transport/unregistered negatives; positive registered packets; unknown hypothesis keeps UNKNOWN; independently typed test-double effect facts | Ephemeral/rollback/dry-run cannot support durable persistence; no-op cannot support mutation; transport cannot settle operation/persistence |
| H3: tier authorizes precedence | F: selected witness plus linked body evidence | Extend `Contradiction` serialization with precedence provenance; replace `_check_precedence` tier comparison with selection-packet and body-path validation | H3 tier, unlinked body, package source, missing provenance, other-source identity negatives; valid direct and helper precedence; test both winning polarities | Missing selected-body provenance leaves CONFLICTING; a falsely resolved record is rejected; valid precedence retains both sides |
| H4: uncertainty erases persistence opposition | G: unresolved conflict before uncertainty | `check_states_against_packets` and `check_undetermined_commit` share the amended state order; remove forced-UNKNOWN short circuit; closure checks retained unresolved opposition | `valid_uncertainty_preserves_conflict`, H4 erasure, H4 other-obligation negative closure; ERROR plus conflict | Opposing unresolved evidence remains CONFLICTING; NO_EFFECT forbidden; ERROR remains ANALYSIS_ERROR |
| H5: loaded receipt accepts open-frontier NO_EFFECT | H: receipt snapshots and identical C1–C6 checks | `EffectReceipt.from_claim`, `from_dict`, `_validate_receipt` validate the embedded EffectClaim and all structured projections; load/write version 0.1.1 and conditional closure | Valid four-verdict receipts, missing closure, top-level strengthening, altered snapshot still with relevant frontier, lossless round trips | Open relevant frontier prevents NO_EFFECT even when both receipt and snapshot are edited; no strengthened projection |
| H6: impossible ledger population | I: necessary union/disjointness bounds, explicit error units | `CoverageLedger._check_verdicts_against_states`, `_check_arithmetic`, `AnalysisErrorCounts` and `from_claims` enforce the frozen equations and breakdown meanings | H6 impossible settled population, mismatched total/marginals/primary-cause partition; valid overlapping-error populations and ledgers recomputed from valid claims | Detectable impossibilities rejected; legitimate cross-obligation overlap preserved; acceptance does not claim full marginal realizability |
| M1: FOUND blanket veto | J: completion separate from found semantics | `_proven_effect_blockers` checks missing/incomplete BLOCKING probes only; found packets enter normal proof machinery; receipt projection preserves them | Hypothesis FOUND positive, precedence-resolved FOUND positive; missing/incomplete otherwise-supported claims; probative unresolved opposition | Completed FOUND alone is not a veto; missing/incomplete still blocks PROVEN_EFFECT |
| M2: inconsistent candidate aggregation | A: complete exception-preserving table | `aggregate_obligation` implements ERROR then CONFLICTING then unanimity; all call sites use it | All 25 ordered pairs; 125 triples, associativity and permutations; S/R divergence, C+U, E+C whole claims | Deterministic table exactly as frozen; no candidate danger/safety ranking |
| M3: opaque singleton unrepresentable | B: UNRESOLVED_IDENTITY | Add vocabulary/codec support, selection/cardinality validation and transition checks; retain omitted-state shorthand only for unique established selection | `valid_opaque_abstain`, opaque false label/support/omitted states, established shorthand; genesis with empty rule IDs; transitions to all four existing labels | All five UNKNOWN, opaque singleton, ABSTAIN, no sink; one record never establishes identity |
| M4: NO_EFFECT schema unsatisfiable | C: property declared, conditional requirement retained | Serialize claim/receipt closure against amended schemas; reference 0.1.1; do not modify old frozen schema | Four verdict examples; valid closure; omitted/false closure; unexpected top-level property rejection | NO_EFFECT becomes satisfiable exactly with its required schema/semantic closure |
| M5: schema check skips silently | K: dependency mandatory in conformance CI | Required conformance dependency/job; remove `importorskip` or equivalent optional success from architecture verification; production runtime dependency remains optional | Normal conformance run; missing-verifier subprocess; CI failure if import unavailable | Missing verifier is nonzero gate failure; no SKIPPED→SUCCESS |

## Repair sequencing and acceptance

First update vocabularies and wire records, then typed assertion checks, candidate
aggregation/selection, precedence and uncertainty, closure/receipts, ledger bounds,
and mandatory conformance CI. No step may infer new facts just to satisfy a schema.
Unknown or missing provenance cannot be migrated into support.

Use this amendment's schemas, registry and authored fixtures as acceptance inputs.
Retain unaffected M0 validation: unique identities, provenance retention, immutable
sets, exact enum handling, ordinary shape errors and round-trip state preservation.
The amended semantics supersede only the conflicting expectations enumerated above.
Existing scanner findings and reports must remain unaffected. Re-run the repaired
M0 suite and relevant baseline regressions and obtain an independent review before
considering merge. This amendment's readiness is not that merge approval.

C4 remains a represented true assertion; do not add a fake completeness verifier.
Selection/body witnesses remain supplied proof records; do not implement a parser,
binding engine, transport recognizer or dependency descent during M0 repair.

M0 implementers need not invent candidate-exclusion semantics: no pruning operation
is authorized here. They must aggregate every supplied candidate. Future acquisition
refinement must meet the separate evidence-preservation requirements in selection.md.
