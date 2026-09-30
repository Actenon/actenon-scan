# Uncertainty, negative closure and receipts

## Per-candidate state order

For each candidate and obligation, preserve all admissible directional facts and
any contradiction record. Evaluate:

1. Declared necessary analysis error → ERROR; opposing packets remain recorded.
2. Opposing probative facts without valid recorded precedence → CONFLICTING.
3. Registered uncertainty (`commit_outcome_undetermined`) → UNKNOWN.
4. Valid recorded precedence → its winning polarity's SUPPORTED or REFUTED.
5. Positive facts only → SUPPORTED; negative facts only → REFUTED; neither → UNKNOWN.

Uncertainty facts do not enter the directional fact sets. They may prevent proof,
including after a recorded precedence resolution, but cannot erase unresolved
opposing facts. This clarifies AREF-002 §4.4's monotonicity statement: evidence is
never discarded, while newly established uncertainty can prevent a previously
supported conclusion. It cannot change CONFLICTING to UNKNOWN. ERROR still takes
priority over a conflict, which remains auditable in its contradiction record.

## Verdict and closure

After candidate aggregation: any necessary ERROR yields ANALYSIS_ERROR. All five
SUPPORTED plus SINGLE_ESTABLISHED or AGREEMENT_INVARIANT and every required
blocking probe completed yields PROVEN_EFFECT. Otherwise a represented, validated
negative closure yields NO_EFFECT. Everything else is ABSTAIN.

NO_EFFECT requires the following C1–C6, for one named refuted obligation:

| Condition | Required validation |
|---|---|
| C1 | No OPAQUE_EXTERNAL or DYNAMIC_UNRESOLVED candidate |
| C2 | The same non-IMPLEMENTATION necessary obligation is REFUTED by admissible evidence for every candidate |
| C3 | No necessary aggregate CONFLICTING state and no retained unresolved contradiction |
| C4 | Represented assertion: no budget exhaustion on an acquisition path contributing to the refutation |
| C5 | Complete, untruncated frontier accounting; no unopened edge relevant to that refuted obligation |
| C6 | No necessary ERROR |

An unopened edge with missing/empty `might_settle` is conservatively relevant.
Only explicitly unrelated frontier entries can coexist with NO_EFFECT. A global
budget-exhausted stop is not automatically a C4 failure if the asserted exhaustion
was on an unrelated path. Conversely, a global successful stop is not proof of C4.

**C4 at M0 is a represented assertion only.** Its true literal is required by the
closure schema. M0 cannot prove contributing-path completeness. Later acquisition
and integration must supply its provenance; this amendment adds no false proof
of completeness. Validators must not describe accepting C4 as having established
that the search actually covered every contributing path.

The closure object is a declared top-level property in the amended claim schema,
retaining `additionalProperties=false`. It is required on NO_EFFECT and absent
on other verdicts, matching M0's existing closure-record convention. Missing
closure cannot produce NO_EFFECT. A closed refuted obligation cannot excuse an
unresolved contradiction on another necessary obligation.

## Receipt self-consistency

The amended receipt includes a mandatory `claim_snapshot` using the amended
EffectClaim schema. This reuses the claim's full semantics, avoiding a second,
weaker negative-proof model. Its eleven answers remain unchanged in purpose.

Construction **and loading/deserialization** MUST:

1. Validate the embedded claim's shape, typed evidence, candidates, proof states,
   contradictions, probes, acquisition state, verdict and C1–C6 closure.
2. Require exact common identity, effect class, verdict, packet, probe and
   acquisition projections. Top-level closure must equal the claim's closure.
3. Require implementation/candidate answers and descriptor answers to match the
   claim. A selected candidate ID is legal only for SINGLE_ESTABLISHED.
4. Require answer states and settling packet references to match the claim.
   Overridden and uncertainty packets cannot be listed as settling evidence.
   UNKNOWN/ERROR have no settling packet IDs; CONFLICTING retains both fact sides.
5. Preserve contradiction records, found counter-evidence, missing/incomplete
   blocking probes and unresolved/frontier fields. Only NO_EFFECT can carry
   `is_negative_result=true`; no receipt may render an unresolved claim as safe.

Free explanatory prose is not an independent source of proof and cannot override
the validated fields. These checks establish self-consistency, **not cryptographic
tamper evidence**, truth of supplied source facts, or history integrity. Altering
both claim and receipt cannot authorize an open-frontier negative: the embedded
claim is revalidated rather than trusted as a seal.
