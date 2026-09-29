# Future M0R1 budget-only delta — not implemented

## Keep the correct interpretation

Retain FrontierEntry.__post_init__ at claim.py:494–495: budget_name iff the frontier
reason is BUDGET_EXHAUSTED. Retain Acquisition.__post_init__ at :572–577: every edge's
budget_name appears in budget_exhausted, and a budget-exhausted stop names at least
one budget. The original fixture's rejection path through EffectClaim.from_dict →
Acquisition.from_dict → FrontierEntry.from_dict is correct. No weaker/defaulted
identity rule is authorized.

## Mechanical additions required by the exclusion-provenance clarification

1. Add immutable optional BudgetProvenance/BudgetExclusion records to Acquisition,
   exactly matching budget_provenance.schema.json. Preserve source/extract data
   and serialization. No parser, source descent or truth inference is added.
2. In _check_closure, when budget_exhausted is nonempty, require the supplied record;
   check same refuted obligation, exact retained settling-negative packet IDs,
   coverage of every candidate, exactly one witness per exhausted budget and exact
   exhausted-edge index mapping. Reject unsupported source provenance. Retain the
   existing complete-frontier and conservative might_settle checks independently.
3. Carry the acquisition field automatically through the existing EffectReceipt
   acquisition and claim_snapshot projections. Use the budget-profile claim/receipt
   schemas. Do not alter receipt proof semantics, answers or other obligations.
4. When this representation/closure cannot be established, the producer records
   ABSTAIN without closure; codecs reject a purported NO_EFFECT. Do not convert
   malformed budget identity into a semantic abstention or infer an error state.

This is a new, narrow normative guard, not evidence that M0R1 misinterpreted the
old literal-only C4 representation. Implementation still requires a separately
authorized mechanical repair. This adjudication modifies no runtime or tests.

## Acceptance/test delta

Preserve a regression that the exact historical AREF-002A fixture is invalid for
missing budget identity, and preserve its original bytes and initial failure.
Its historical VALID registry entry is superseded only by this package's corrected
fixture. An amended-profile test should validate that versioned fixture and its
new provenance record; it must not keep expecting the malformed historical bytes
to load. This is explicit normative supersession, not a silent fixture substitution.

Add Cases A–F, names-only Case D refusal, missing/bad witness references, exact
budget/edge coverage, unknown/relevant frontier refusal and receipt retention.
The existing M0R1 tests are not edited here; future conformance selection must
recognize the one superseded fixture and add a real historical-invalid regression.
Do not mark the old failing case xfail, skip it, remove its evidence, or weaken C4.
A green revalidation result cannot be claimed merely from this package's validator.

M0R1 RUNTIME CHANGE REQUIRED: YES — only the supplied budget-exclusion guard and codec.
M0R1 TEST CHANGE REQUIRED: YES — explicit single-fixture supersession plus budget cases.
No other M0R1 repair or M1 work is authorized by this delta.
