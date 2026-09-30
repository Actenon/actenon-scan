# Candidate identity and selection

Add **UNRESOLVED_IDENTITY**: the identity or selected-target binding needed to
establish selection has not been proved. It is neither SINGLE_ESTABLISHED nor an
analysis error. The initial unfamiliar invocation MUST be representable as:

```text
matched_rule_ids = []
implementation_candidates = { one OPAQUE_EXTERNAL candidate }
candidate obligations = { all five UNKNOWN }
claim obligations = { all five UNKNOWN }
selection_state = UNRESOLVED_IDENTITY
verdict = ABSTAIN
evidence_packets = []
```

One candidate record is not evidence that its implementation is known. OPAQUE_EXTERNAL
and DYNAMIC_UNRESOLVED cannot carry IMPLEMENTATION=SUPPORTED. Obtaining a body or
contract changes the candidate description with evidence; relabeling alone does not.

## Binding witnesses

A PROBATIVE `implementation_is` assertion requires a structured `binding` record:
`relation`, `invocation_id`, `from` locator, `to` locator. Its packet also carries
the existing kind, tier, candidate ID, locator and verbatim-extract provenance.

| Relation | Meaning |
|---|---|
| SELECTED_TARGET | The invocation binds to this actual implementation target |
| POSSIBLE_TARGET | This body/contract identity is established as a possible target |
| RESOLVED_CALL | A body-to-body call edge used in a recorded derivation path |

The first two can support that candidate's IMPLEMENTATION when they identify the
same invocation and exactly the candidate's locator. A RESOLVED_CALL alone cannot
settle top-level implementation selection. A target locator alone, a package name,
or a candidate-count assertion is never a binding witness.

## Deterministic labels and transitions

After validating per-candidate evidence and computing aggregates, apply these
rows in order. Recompute after any valid evidence/candidate refinement.

| Condition | Required selection state |
|---|---|
| Any required candidate IMPLEMENTATION=ERROR | SELECTION_ERROR |
| Any candidate IMPLEMENTATION is not SUPPORTED | UNRESOLVED_IDENTITY |
| One candidate, supported identity, and a PROBATIVE SELECTED_TARGET binding from this invocation to its locator | SINGLE_ESTABLISHED |
| One supported possible identity without that actual selected-target witness | UNRESOLVED_IDENTITY |
| Several supported candidate identities, identical states on all other necessary obligations | AGREEMENT_INVARIANT |
| Several supported candidate identities, disagreement on another necessary obligation | UNRESOLVED_DIVERGENT |

Thus genesis can transition to SINGLE_ESTABLISHED only with actual binding
evidence; to AGREEMENT_INVARIANT only after establishing each candidate identity
and comparing every necessary state; to UNRESOLVED_DIVERGENT only after establishing
the alternatives and retaining their disagreement; and to SELECTION_ERROR on a
necessary identity-analysis error. Labels describe the evidence; they do not make it.

All candidates carry explicit obligation states. Retain the old wire shorthand
only for exactly one SINGLE_ESTABLISHED candidate: omitted candidate states mean
the claim's complete state vector, validated against the same evidence. Omission
under any other label, including the initial opaque singleton, is invalid.

## Candidate preservation and exclusion boundary

Every candidate supplied in a claim is required for aggregation. M0 constructors,
selection helpers and serializers MUST NOT prune candidates, choose the first,
or choose the safer/more dangerous one. No candidate-exclusion operation is added
by this amendment. Therefore M0 repair cannot remove ERROR through selection.

Future acquisition may refine the possible set only through independent binding
evidence that establishes which target can actually run and excludes the alternative
under the same recorded conditions. The former candidate/error record and the
selection evidence must remain auditable as a refinement, not disappear through a
label change. Implementing or proving such exclusion is outside M0. A stateless
record validator cannot detect an upstream producer omitting an entire candidate;
complete enumeration and provenance remain later obligations. This limitation
does not authorize unrecorded exclusion.
