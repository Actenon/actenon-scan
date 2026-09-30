# CoverageLedger population consistency

All counts are nonnegative integers. Distinguish investigated claims from claims
instantiated but not investigated. Uninvestigated claims have no settled negative
meaning and MUST NOT enter the investigated verdict or proof-state distributions.

Let `N` be investigated claims; `P`, `Z`, `A`, `X` their PROVEN_EFFECT, NO_EFFECT,
ABSTAIN and ANALYSIS_ERROR counts. For each necessary obligation `o`, let
`S_o, R_o, U_o, C_o, E_o` be its proof-state counts.

## Required necessary bounds

```text
P + Z + A + X = N
S_o + R_o + U_o + C_o + E_o = N             for every o

max_o(E_o) <= X <= sum_o(E_o)
P <= min_o(S_o)
Z <= sum_{o != IMPLEMENTATION}(R_o)
R_IMPLEMENTATION = 0

P + Z + C_o + E_o <= N                     for every o
```

The error bounds are union bounds: a claim can have several errored obligations
but counts once in ANALYSIS_ERROR. Every positive requires support on every
obligation. Every negative requires at least one common-candidate refutation and
closure. ERROR and CONFLICTING on the **same obligation** are mutually exclusive
populations; neither population can be PROVEN_EFFECT or NO_EFFECT. The last bound
is equivalent to `A + X >= C_o + E_o` and must not be weakened to merely taking
their maximum. It catches H6's two claims with one ERROR and one CONFLICTING on
BOUNDARY while purporting to contain one NO_EFFECT and one ANALYSIS_ERROR.

These are sound necessary bounds, not evidence that an accepted distribution is
fully realizable or that negative closure actually held. In particular:

- ERROR and CONFLICTING on **different** obligations may belong to the same claim.
  Do not sum those marginal counts as distinct claims.
- Refuted obligations can overlap. Their sum is only an upper bound on the union.
- Aggregate states do not establish per-claim C1–C6, probes, selected bodies or
  cross-obligation correlations. Exact consistency requires validated per-claim
  records, followed by recomputation of the ledger; marginals cannot certify it.

The required rejection contract is these bounds plus the existing arithmetic
invariants; it does not authorize synthesizing correlations or treating an
aggregate-only ledger as a replacement for claims and receipts.

## Totals and breakdowns

`claims.instantiated = investigated + not_investigated`, and instantiated claims
cannot exceed enumerated invocations times enabled effect classes. The highest-tier
and stop-reason histograms count instantiated claims; the CLAIM_NOT_INVESTIGATED
stop count equals `not_investigated`. Existing optional partition/count bounds
remain in force. Partial frontier by-tier/by-reason totals cannot exceed its total.

`analysis_errors.total` is explicitly a count of **ANALYSIS_ERROR claims**, not
exceptions, packets, obligations or attempts. It equals `X`.

If `analysis_errors.by_obligation` is present, omitted obligations mean zero and
every count must equal the corresponding `E_o` marginal. Keys must be obligations.
These counts may overlap and their sum need not equal `X`.

If `analysis_errors.by_cause` is present, it assigns exactly one primary cause per
errored claim, and its sum must equal `X`. Cause classification itself is not an
effect-proof rule. Retaining all underlying failures is the responsibility of
individual records; this histogram must not count several causes as extra claims.

No unresolved or uninvestigated population may be reported as settled negative
merely because `P=0`. The ledger's interpretation remains coverage, not assurance
that the repository is safe.
