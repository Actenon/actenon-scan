# Cross-candidate aggregation

For each necessary obligation, aggregate a **nonempty set of candidate states**:

```text
if any ERROR:           ERROR
else if any CONFLICTING: CONFLICTING
else if all SUPPORTED: SUPPORTED
else if all REFUTED:   REFUTED
else:                 UNKNOWN
```

This function applies to all five obligations, including IMPLEMENTATION.
It is deterministic, commutative, associative and insensitive to duplicate equal
states. Candidate identity and evidence must nevertheless remain distinct: equal
state vectors never justify merging candidate records or their provenance.
Empty candidate populations are invalid, not universal agreement.

| + | SUPPORTED | REFUTED | UNKNOWN | CONFLICTING | ERROR |
|---|---|---|---|---|---|
| SUPPORTED | SUPPORTED | UNKNOWN | UNKNOWN | CONFLICTING | ERROR |
| REFUTED | UNKNOWN | REFUTED | UNKNOWN | CONFLICTING | ERROR |
| UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | CONFLICTING | ERROR |
| CONFLICTING | CONFLICTING | CONFLICTING | CONFLICTING | CONFLICTING | ERROR |
| ERROR | ERROR | ERROR | ERROR | ERROR | ERROR |

SUPPORTED versus REFUTED across **different** possible implementations means
UNKNOWN: unresolved implementation selection can change the answer. Opposing
admissible facts about the **same** implementation mean CONFLICTING unless the
recorded selected-body precedence rule resolves them. ERROR and CONFLICTING are
discovered epistemic facts; selection uncertainty must not erase them.

IMPLEMENTATION remains non-refutable. REFUTED rows above apply to the generic
aggregation operator, not permission to construct an IMPLEMENTATION=REFUTED claim.

A selection label MUST NOT assign a proof state. In particular:

- Candidate IMPLEMENTATION=ERROR propagates to aggregate IMPLEMENTATION=ERROR and
  verdict ANALYSIS_ERROR. SINGLE_ESTABLISHED or AGREEMENT_INVARIANT cannot override it.
- Candidate CONFLICTING plus another candidate UNKNOWN remains CONFLICTING.
- If all candidate identities are established but other obligations diverge,
  IMPLEMENTATION can aggregate to SUPPORTED while selection is UNRESOLVED_DIVERGENT.
  That label still blocks PROVEN_EFFECT. The old shortcut mapping divergence to
  IMPLEMENTATION=UNKNOWN is expressly removed.

The validator checks the 25 ordered pairs against a literal truth table, every
three-state permutation, and whole-claim cases for disagreement, conflict and error.
