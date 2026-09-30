# AREF-002A — Amendment report

**Recommendation: AREF-002A READY — M0 REPAIR MAY BEGIN**

The proof-model ambiguities identified by the adversarial review now have explicit,
versioned repair semantics. M0 has not been repaired or approved for merge. Its
review verdict remains **M0 FAIL — ARCHITECTURE VIOLATION**.

## Provenance and bounded authority

The inspected checkout is exactly `a93b013383ce773b10708d3f30b2a1660e141527`, the
frozen M0 revision of `feat/aref-002-m0-effect-claims`, reviewed against baseline
`b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16`. The local review checkout is detached at
that commit. No branch, commit or remote reference was changed.

Authoritative inputs were the immutable AREF-002 package, the M0 implementation
at that commit, and the user's frozen H1–H6/M1–M5 findings. The relevant code was
inspected independently: candidate aggregation/selection and proof validation in
`actenon_scan/effects/claim.py`; predicate compatibility in `evidence.py` and
`vocabulary.py`; receipt loading/closure in `receipt.py`; and population arithmetic
in `ledger.py`. Comments or passing implementation tests were not substituted for
the normative contract.

All new files are confined to `specs/AREF-002A/`. SHA-256 verification covers all
476 protected files in AREF-001, AREF-002, production source and existing tests;
their inventory and bytes remain unchanged. The original manifests still verify
24 AREF-001 and 26 AREF-002 files. The unchanged AREF-002 validator passes its
298 checks; that result does not repair its missing NO_EFFECT satisfiability check.

AREF-002A is a partial normative supersession, not AREF-003. The four affected
schemas receive new IDs and version `0.1.1`; old files remain historical evidence.
Unamended AREF-002 requirements remain in force. The exact deltas and source
provisions are mapped in [AMENDMENT.md](AMENDMENT.md).

## Adjudication

| Findings | Resolution |
|---|---|
| H1 / M2 | All five obligations aggregate with ERROR then CONFLICTING precedence. Selection labels cannot overwrite candidate states. |
| M3 | UNRESOLVED_IDENTITY admits an opaque singleton with all five UNKNOWN, empty rule IDs and ABSTAIN. |
| H2 | A typed registry validates direction, obligation, kind, tier and admissibility. Unknown combinations cannot settle. |
| H3 | Precedence requires selected-target binding, selected-body derivation and retained provenance; tier alone is insufficient. |
| H4 | Uncertainty cannot erase opposing facts. Unresolved conflict blocks negative closure even if another obligation is refuted. |
| H5 | A receipt validates its embedded claim and exact structured projections, including the same C1–C6 closure. |
| H6 | Necessary disjointness/union bounds reject detectable impossible populations; marginal data is not portrayed as exact correlation evidence. |
| M1 | Missing/incomplete blocking probes block proof; completed FOUND supplies evidence without an additional veto. |
| M4 | Closure is declared at top level with conditional requirements and strict additional-property handling. All four verdict branches have valid examples. |
| M5 | The conformance job requires its verifier; actual dependency absence exits nonzero rather than skipping. |

The original NO_EFFECT contradiction is a schema defect: the conditional requirement
and top-level property prohibition cannot both be satisfied. It required normative
supersession. This amendment supplies that correction without editing historical
AREF-002. The conceptual claim-before-sink architecture remains intact.

## Validation results

The default sealed conformance gate passes **86 checks, 86 passed, 0 failed**:

- Four corrected schemas are valid JSON Schema Draft 2020-12.
- **66 fixtures:** 28 accepted valid records and 38 adversarial records rejected
  for their intended reason. These include claims and receipts for every verdict.
- All 25 ordered aggregation pairs match the independently written literal table.
  All 125 triples are order-independent; associativity also holds.
- Valid records retain JSON round-trip state. Reversing candidate, packet, probe
  and contradiction order preserves every valid claim decision.
- The typed registry exactly matches its schema encoding. The unchanged ontology
  and amended selection vocabulary agree with their machine-readable declarations.
- Removing access to the schema verifier in a subprocess produces fatal exit 2.
- Protected input inventory/hashes and the complete sealed amendment inventory pass.

See [validation.md](validation.md) for the mapping of all sixteen requested
validation assurances to executable checks. [case_registry.json](case_registry.json)
records every expected result and negative rejection code; [validate.py](validate.py)
is the reproducible gate. The 86 count includes the three final inventory/seal
checks; authoring-only unsealed runs contain 83 checks and are not CI conformance.

These results establish internal normative consistency for the amended proof-record
contract. They do **not** establish repaired production behavior. No production
tests were changed or used to manufacture a pass; M0 repairs and regression testing
remain the next authorized task, subject to a separate request.

## Explicit limits

C4 is a represented true assertion at M0, not verified contributing-path completeness.
Structured binding/provenance packets are supplied facts; M0 does not acquire them
or establish their source truth. Examples use authored synthetic proof records,
not executed programs or measured source evidence. Receipt consistency is not
cryptographic sealing. Necessary ledger bounds cannot recover absent correlations.

No R05/R06/R07 repository was inspected, searched for, selected, identified, cloned
or browsed. No REI experiment was rerun. No provider signature, new effect class,
obligation, numeric confidence, dependency descent or M1 implementation was added.
No real-world validation is claimed.

## Mechanical repair readiness

[m0_repair_contract.md](m0_repair_contract.md) gives SPEC CHANGE, RUNTIME CHANGE,
TEST REQUIRED and EXPECTED RESULT for each of the eleven findings. Its runtime
targets include exact existing functions. The registry, state table, selection
transitions, provenance fields, closure rules, receipt projections and population
equations are frozen here, so an M0 repair need not invent proof semantics.

M0 candidate pruning is not authorized: every supplied candidate is aggregated.
Future acquisition may refine the set only with independent selection evidence and
retained audit history. No stateless M0 validator can detect an upstream producer
omitting an entire candidate. This is an explicit later acquisition obligation,
not a reason to weaken error preservation now.

After repair, require the amended conformance gate, production type/codec tests,
relevant unchanged scanner regressions and an independent review before merge.
This amendment authorizes no merge and does not start M1.

## Twelve requested answers

1. **Does AREF-002A preserve sink-independent EffectClaim genesis? Yes.** Empty
   matched rule IDs are valid; no rule is part of claim identity or existence.
2. **Can the initial unfamiliar opaque singleton now be represented without falsely
   supporting IMPLEMENTATION? Yes.** UNRESOLVED_IDENTITY, five UNKNOWN states, ABSTAIN.
3. **Can candidate ERROR disappear through selection? No.** Every supplied candidate
   participates in aggregation; a selection label is never exclusion evidence.
4. **Can candidate CONFLICTING disappear through uncertainty? No.** It survives
   candidate uncertainty and commit uncertainty. ERROR can take aggregate priority,
   while the discovered contradiction remains recorded.
5. **Can a typed assertion contradict its polarity and still settle? No.** Its
   probative combination is rejected; an unregistered hypothesis cannot settle.
6. **Can evidence tier alone resolve a contradiction? No.** Selected-body provenance
   and a recorded admissible precedence relationship are required.
7. **Can an unresolved contradiction coexist with NO_EFFECT? No.** C3 prevents it.
8. **Can a receipt strengthen ABSTAIN into NO_EFFECT while retaining an open relevant
   frontier? No.** Claim revalidation and receipt projection checks prevent it.
9. **Can a ledger report a settled negative population impossible under its state
   distributions? Detectable violations of the frozen necessary bounds are rejected.**
   Aggregate-only acceptance does not certify full joint realizability or closure;
   exact consistency requires the per-claim records.
10. **Does a completed FOUND blocking probe automatically veto proof? No.** Its
    evidence follows the ordinary admissibility and contradiction rules.
11. **Can schema conformance silently skip? No.** Missing verifier is a failed gate.
12. **Does this amendment require any North-Star ontology change? No.** It repairs
    consistency and provenance within the existing claim/evidence ontology.

## Created files and Git status

Created: the thirteen required Markdown documents; four corrected schemas;
`assertion_registry.json`, `amendment_contract.json`, `case_registry.json`,
`input_preservation.json`; `requirements-validation.txt`; `validate.py` and
`build_examples.py`; 66 JSON examples; and `MANIFEST.json` / `MANIFEST.sha256`.
The manifests list every file by exact path, including every individual example.
No existing file was modified. Final checkout status:

```text
?? specs/AREF-002A/
```

**AREF-002A READY — M0 REPAIR MAY BEGIN**
