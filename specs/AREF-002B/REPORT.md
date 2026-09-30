# AREF-002B — Single-issue adjudication report

CLASSIFICATION: NORMATIVE CONTRADICTION

ROOT CAUSE: The sealed AREF-002A VALID declaration conflicts with the inherited
unconditional requirement to identify exhausted budgets. The fixture omits both
the per-edge budget_name and the acquisition's exhausted-budget list; the schema
and AREF-002A validator omitted these inherited conditions. The rule is sound and
M0R1 enforces it correctly. A budget-name-only repair additionally exposes the
narrow C4 provenance representation gap: a bare unrelated-frontier label and
C4=true suffice under AREF-002A's explicitly deferred provenance, but cannot satisfy
this task's requirement to distinguish supported irrelevance from mere assertion.
AREF-002B resolves only this budget-record conflict and representation gap.

## Independent reconstruction and competing diagnoses

- **Fixture defect: confirmed.** The concrete rejection is missing budget identity,
  not an unconditional ban on negatives when any budget is exhausted.
- **Inherited budget rule defect: disproved.** dependency_descent.md §4.3 item 3,
  line 156, requires a specific budget name; §6.1, line 242, requires it on each
  exhausted frontier edge. Neither requirement depends on relevance.
- **M0R1 interpretation defect: disproved for those requirements.** EffectClaim.from_dict
  calls Acquisition.from_dict, which constructs FrontierEntry. claim.py:494–495
  rejects the missing edge name first; :572–577 also require list membership and
  the stop's nonempty budget list. These conditions must not be weakened.
- **Normative clarification beyond identity: necessary.** proof_obligations.md
  §5.3, lines 352–353, distinguishes contributing-path exhaustion (C4) from a
  relevant unopened frontier (C5). AREF-002A closure_and_receipts.md lines 35–48
  preserves those meanings but records C4 as a true literal and defers its source
  provenance. The correction now specifies a supplied budget-exclusion proof
  record rather than pretending that M0 can acquire or verify that truth.

The historical fixture's per-edge scope is `might_settle=[OPERATION]`, whereas
its refuted obligation is PERSISTENCE. That represented scope could be unrelated;
it is not proof that all exhaustion paths are outside the rollback refutation.
Identity recording and exclusion provenance answer different questions.

## Exact observed M0R1 pressure points

The budget-only probes use the exact locally archived checkpoint
`ec4db0c2ab61c6d5b1c5d8537a9617f2d2534b30`; no current runtime behavior is taken as
normative authority. On the original fixture:

```text
INVALID: frontier entry: a budget name is recorded exactly when the reason is BUDGET_EXHAUSTED
```

Adding only the edge name also fails because it is absent from the exhausted list.
Adding both `budget_name=max_dependency_hops` and
`budget_exhausted=[max_dependency_hops]` makes it load as NO_EFFECT, with no separate
exclusion witness. The unchanged runtime's `FrontierEntry.is_relevant_to` at :497–499
checks only missing/empty scope or membership; _check_closure at :1236–1239 requires
complete frontier accounting and rejects relevant edges. That behavior correctly
implements the prior represented-scope convention, including conservative UNKNOWN.
It does not supply the new distinction demanded between Cases C and D.

The corrected AREF-002B fixture adds those two identity fields plus one source-linked,
refutation-linked exclusion record. Its chosen budget identity is an authored
normative premise; the missing historical identity cannot be recovered by guessing.
Its witness extract is verified against an actual versioned fixture proof-record
file. These are authored premises, not acquired implementation facts or empirical
validation. The old runtime rejects the new budget_provenance field until the
bounded codec/closure delta is separately implemented.

## Cases A–F

CASE A: NO_EFFECT may be valid when no exhaustion is recorded and all inherited
negative closure conditions hold. No budget name/list/witness is required. Absence
of a recorded exhaustion is not a source-completeness proof.

CASE B: ABSTAIN when exhaustion contributed to the refutation; C4 cannot be true.
Budget identity remains recorded. A proposed NO_EFFECT with false C4 is invalid.
Inherited necessary ERROR precedence remains unchanged.

CASE C: NO_EFFECT may be valid only with the exhausted-budget list, each exhausted
edge's budget_name, complete frontier, same refutation across every candidate and
source-linked exclusion witnesses covering every exhausted budget and all its edges.
C4 may remain represented true. C5 must pass independently; an exclusion witness
cannot override unknown or relevant frontier scope.

CASE D: ABSTAIN when unrelatedness is merely labelled/asserted without the required
source/refutation-linked provenance. Keep identities and frontier; omit closure.
The attempted stronger NO_EFFECT is rejected rather than silently downgraded.

CASE E: ABSTAIN when relevance is UNKNOWN. Missing/empty might_settle is conservatively
relevant; C5 is not established, and unknown budget non-contribution cannot establish
C4. Neither a successful stop nor an unrelated label resolves the uncertainty.

CASE F: INVALID record when exhaustion is explicitly recorded without its budget
identity/list. It is not a semantic ABSTAIN, does not justify guessing a budget,
and is not automatically a newly assigned necessary ANALYSIS_ERROR. A producer must
record the actual provenance or report the output/analysis infrastructure failure.

## Minimal artifacts and implementation boundary

The two budget-profile schemas preserve wire schema_version 0.1.1 and use distinct
versioned normative IDs. Their budget-only structural delta is checked mechanically.
The additional schema describes the one optional acquisition proof record, required
only for exhausted NO_EFFECT. The receipt schema only retargets existing claim-schema
references; its projection/self-consistency rules remain unchanged. No evidence
assertion registry, effect class, proof-state, verdict-state, ledger or probe changes
are made. Source truth and complete enumeration remain later responsibilities.

AREF-002B REQUIRED: YES

M0R1 RUNTIME CHANGE REQUIRED: YES — narrowly add the supplied budget exclusion
record, serialization and conditional C4 guard. The existing identity interpretation
is correct. This is a new specified guard, not a retrospective general M0R1 defect.

M0R1 TEST CHANGE REQUIRED: YES — explicitly recognize the single-fixture supersession,
retain an original-fixture-invalid regression, and add Cases A–F/provenance checks.
No production or M0R1 test change was made during this adjudication.

NEGATIVE CLOSURE WEAKENED: NO

NORTH-STAR ONTOLOGY CHANGED: NO

R05/R06/R07 ACCESSED: NO

## Validation and preservation

`python -B specs/AREF-002B/validate.py` validates all three budget schemas; proves
that claim/receipt changes are confined to this issue; exercises every case and
negative witness variant for its intended reason; checks exact witness text,
historical runtime pressure points, mandatory-verifier failure and all seals.
Final validator result: **39 checks, 39 passed, 0 failed**. During authoring, the
receipt smoke projection initially included frontier_truncated in the fixed unknowns
answer, which the inherited schema forbids. The test projection was corrected to
the existing answer keys; no receipt rule or inherited schema was changed.

The six-case decisions distinguish valid ABSTAIN representations from rejected
stronger NO_EFFECT proposals and malformed identity records.

AREF-001 manifest SHA256:
`ac413f5434409fd3d096aec4e753dc7ed21eadefeec415b73293c11444ae37d9`

AREF-002 manifest SHA256:
`e1c7b4f4410ddd8b69aeaab9d6cdb566bd0e0ed123bd8a0952540f907943369b`

AREF-002A manifest SHA256:
`00ef6dd054b0f4a8ca14876147a2f5b82fecc6f4475d883bd7b49f23b60549ac`

Historical source/test bytes and manifests remain untouched. Only this package is
created. The M0R1 checkpoint remains HEAD; no commit, push, merge, M1, provider
knowledge or REI rerun is part of this task. Readiness of this amendment is not
readiness of M0R1; separately authorized budget-only implementation and revalidation
are still required. The original failed test and its historical evidence remain.

AREF-002B READY — M0R1 MAY BE REVALIDATED
