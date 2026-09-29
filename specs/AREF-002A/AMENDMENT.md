# Bounded normative delta

This amendment resolves the frozen review findings at M0 commit
`a93b013383ce773b10708d3f30b2a1660e141527`, against AREF-002's baseline
`b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16`. MUST, MUST NOT and REQUIRED below are
normative. Each delta is confined to the demonstrated proof-model inconsistency.

| Amendment | Findings | Normative correction | Affected AREF-002 provisions |
|---|---|---|---|
| A | M2, H1 | ERROR then CONFLICTING dominate candidate aggregation | `proof_obligations.md` §4.3; `AREF-002.md` §8.3 |
| B | M3 | Add UNRESOLVED_IDENTITY for an unestablished candidate identity/selection | `AREF-002.md` §4.2, §8.3; selection schema |
| C | M4 | Declare closure at claim top level; require it for NO_EFFECT | `effect_claim.schema.json` |
| D | H1 | Aggregate candidate IMPLEMENTATION states; a label cannot replace them | `proof_obligations.md` §2.1, §4.3 |
| E | H2 | Typed predicate/obligation/polarity/source/admissibility registry | evidence assertion schema; `evidence_acquisition.md` §5 |
| F | H3 | Record selected binding and body derivation for precedence | `proof_obligations.md` §6.3; contradiction schema |
| G | H4 | Preserve unresolved opposing facts before applying uncertainty | `proof_obligations.md` §2.5, §4.2–4.4, §5.3 |
| H | H5 | Receipt loads validate the same complete claim and closure | receipt schema and construction contract |
| I | H6 | Enforce necessary population bounds and error-count meanings | coverage ledger schema and arithmetic contract |
| J | M1 | Completed FOUND is evidence input, not an additional veto | `proof_obligations.md` §5.1, §7 |
| K | M5 | Schema verifier is a required conformance dependency | schema-conformance acceptance and CI instructions |

The literal AREF-002 selection-to-IMPLEMENTATION table is superseded. All five
claim obligations now use the aggregation function in [aggregation.md](aggregation.md).
Selection sufficiency remains an additional verdict condition. This prevents a
label from laundering an error while preserving set-valued possible implementations.

The new fields are proof provenance and self-consistency machinery: `binding` on
evidence, `precedence` on resolved contradictions, and `claim_snapshot` on receipts.
They do not introduce an effect class, obligation, descriptor or acquisition tier.
The smallest safe registry is frozen rather than guessing a complete vocabulary.
Unregistered combinations remain hypotheses and cannot settle obligations.

The unchanged ontology is:

- Claim identity: `(capability_id, invocation_id, effect_class)`, independent of rules.
- Effect class: `EXTERNAL_PERSISTENT_STATE_EFFECT` only.
- Necessary obligations: IMPLEMENTATION, ACTIVATION, BOUNDARY, OPERATION, PERSISTENCE.
- Descriptors, separate from that conjunction: TARGET, CONTROL, AUTHORITY, CONDITIONS.
- Proof states: SUPPORTED, REFUTED, UNKNOWN, CONFLICTING, ERROR.
- Verdicts: PROVEN_EFFECT, NO_EFFECT, ABSTAIN, ANALYSIS_ERROR.

`matched_rule_ids=[]` is legal. Rules are evidence sources only. Candidate sets
are never ranked by danger or safety. Transport does not prove operation or
persistence. Existing findings remain unaffected by the claim layer.

Within the amended subjects, these documents, the typed registry, corrected
schemas and validator jointly define conformance. JSON shape validation alone is
insufficient. The validator is an executable witness to these rules; a discovered
disagreement with their normative prose is a conformance defect, not permission
to reinterpret the prose. No precedence among conflicting implementation choices
is delegated to a future implementer.

Unchanged AREF-002 requirements continue to apply, including evidence fidelity,
budgets, invocation coverage, source acquisition and held-out validation. The
validator does not claim to implement those later mechanisms. C4 is explicitly a
represented assertion at M0; later acquisition/integration must substantiate it.
