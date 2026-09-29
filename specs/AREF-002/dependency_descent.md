# AREF-002 — Bounded dependency descent: budgets, frontier, determinism

**Status:** frozen. Normative. Part of the AREF-002 architecture freeze.
**Parent:** [AREF-002.md](AREF-002.md)
**Companion:** [evidence_acquisition.md](evidence_acquisition.md) (what each tier
yields), [proof_obligations.md](proof_obligations.md) (what descent results may
settle).

This document freezes requirement 13: descent is bounded, and **budget
exhaustion produces a visible `UNKNOWN`/`ABSTAIN`, never guessed semantics**.

---

## 1. The problem descent solves

An `EffectClaim` for an unfamiliar SDK call reaches L3 cheaply — package identity
is local information. Everything that can actually settle `OPERATION` and
`PERSISTENCE` lies deeper: the pinned dependency's body (L5), a machine-readable
contract (L6), the underlying operation (L7). Reaching those tiers means walking
outward from the call site through wrappers, re-exports, modules, packages and
contract documents.

That walk is unbounded in principle. A single SDK method can transit a dozen
internal modules, a base client, a transport layer and a generated operation
table. Unbounded descent does not terminate on real repositories; naive
truncation silently mislabels; and *guessing at the truncation point* is the
failure mode this document exists to prohibit.

Descent is therefore bounded, deterministic, accounted for, and — critically —
**self-reporting**: what it did not open is part of the output.

---

## 2. Scope

Descent is the mechanism by which tiers **L1, L2, L4, L5, L6, L7** are reached.
It covers:

| Descent kind | From | To |
|---|---|---|
| wrapper descent | a call site | a local function/method body (L1) |
| declaration descent | a call site | a type/interface/stub declaration (L2) |
| provenance descent | an import | a manifest/lockfile entry (L4) |
| package descent | a package identity | pinned dependency source (L5) |
| internal descent | a dependency entry point | deeper modules inside the same dependency (L5) |
| contract descent | a package or service identity | a machine-readable contract document (L6) |
| operation descent | a resolved body | the underlying statement/command/transport operation (L7) |

Descent is **read-only and strictly local to the analysed tree**. AREF-002
freezes no network access, no package installation, no registry query, and no
execution of analysed code. What is not in the tree is `TIER_UNAVAILABLE`.

---

## 3. Traversal

### 3.1 Wrapper descent

The cheapest and highest-yield descent: follow a call into a body defined in the
workspace, and continue while the body's own effect-relevant behaviour is
delegated onward. Each followed edge is one hop and counts against
`max_dependency_hops`.

Wrapper descent stops at a body that performs the operation itself, at a body
that delegates outside the workspace (handing off to package descent), at a cycle
(§3.4), or at budget.

A partially followed wrapper chain is **not** evidence about the operation. If
descent stops mid-chain, the obligations the chain would have settled remain
`UNKNOWN` and the unfollowed edge goes on the frontier. Reporting the outermost
wrapper's *name* as the operation would be name evidence, which is
`HYPOTHESIS_ONLY`.

### 3.2 Package and internal descent

On reaching a package boundary, descent needs L4 (which version) before L5
(which source). Inside a dependency, descent continues by the same hop
accounting; there is no separate, larger allowance for third-party code. A
generated operation table inside an SDK is L6 evidence if it is machine-readable
data, and L5 evidence if it is code.

### 3.3 Deterministic order

Within a tier, candidate edges are opened in a total order computed from stable
keys, in this precedence:

1. ascending ladder tier
2. ascending hop distance from the call site
3. ascending `(normalised_path, start_line, start_column)` of the edge's syntactic
   origin
4. ascending callee symbol string, byte-wise
5. ascending candidate id

The order is fixed so that a budget-truncated run is **reproducible**: the same
workspace, configuration and budget must open the same edges and leave the same
frontier. Non-determinism under truncation would make the R05/R06 preregistration
meaningless, because a rerun could produce a different first-broken component.

Path normalisation is relative to the scan root with forward slashes, so that
ordering does not vary with the absolute checkout location or host filesystem
enumeration order.

### 3.4 Cycles and revisits

Visited nodes are keyed by `(normalised_path, symbol, tier)`. A revisit is not
followed again and does not consume budget. A cycle terminates descent along that
edge with reason `CYCLE`, which is a normal, non-error outcome and does not by
itself produce `UNKNOWN` if the obligation was already settled.

### 3.5 Sharing across claims

Acquired artefacts — parsed files, resolved packages, parsed contracts — are
cached per run and shared across claims. Caching affects cost, never semantics:
a cached artefact yields the same packets, with the same extracts, as a fresh
read. `max_files_opened` and `max_bytes_read` count *distinct* artefacts, so
sharing genuinely increases reach; `max_dependency_hops` is per claim, so one
expensive claim cannot consume another's allowance.

---

## 4. Budgets

### 4.1 The frozen budget vocabulary

Seven budgets. Names and scopes are frozen; default values are configuration and
are recorded in [architecture_manifest.json](architecture_manifest.json).

| Budget | Scope | Bounds |
|---|---|---|
| `max_ladder_tier` | per claim | the highest tier descent may attempt |
| `max_dependency_hops` | per claim | followed edges from the call site |
| `max_files_opened` | per run | distinct artefacts read |
| `max_bytes_read` | per run | total bytes of artefact read |
| `max_wall_ms_per_claim` | per claim | wall time investigating one claim |
| `max_claims_investigated` | per run | claims scheduled for investigation |
| `max_implementation_candidates` | per claim | candidates retained |

### 4.2 Why these seven

Each bounds a distinct divergence. `max_ladder_tier` bounds depth of *kind*;
`max_dependency_hops` bounds depth of *distance*; `max_files_opened` and
`max_bytes_read` bound the run's I/O independently of claim count;
`max_wall_ms_per_claim` bounds pathological single claims (a generated file with
a 40,000-line operation table); `max_claims_investigated` bounds breadth, since
instantiation is universal and cheap ([AREF-002.md](AREF-002.md) §4.2);
`max_implementation_candidates` bounds candidate-set explosion at dynamic sites.

### 4.3 Exhaustion is a first-class outcome

On exhaustion, for the affected claim:

1. descent stops on the affected path;
2. every necessary obligation not already settled by admissible evidence stays
   `UNKNOWN` — **no default, no assumption, no inference from what was seen so
   far**;
3. the stop reason `BUDGET_EXHAUSTED` is recorded with the specific budget name;
4. the unopened edges go on the frontier (§6);
5. the verdict is `ABSTAIN` unless an obligation was already legitimately
   `REFUTED` **and** closure C1–C6 holds — and C4 explicitly fails if the
   exhausted path contributed to that refutation
   ([proof_obligations.md](proof_obligations.md) §5.3);
6. the run's `budget_exhaustion` counters increment in the coverage ledger.

`max_claims_investigated` exhaustion is different in one respect: the claim is
never investigated at all, its stop reason is `CLAIM_NOT_INVESTIGATED`, and it is
counted separately in the ledger. An uninvestigated claim is the most dangerous
possible thing to render as a negative result, so the ledger reports it as its
own line.

### 4.4 Prohibited responses to exhaustion

| Prohibited | Why |
|---|---|
| assuming the unresolved callee does what its name suggests | requirement 10; name evidence is `HYPOTHESIS_ONLY` |
| assuming a mutation because the package is "a database library" | provider-specific inference; prohibited by the STRICT RULES |
| assuming persistence because dispatch was observed | REI-002: dispatch is not persistence |
| assuming no effect because nothing was found | requirement 17; absence of evidence is not evidence of absence |
| silently lowering `max_ladder_tier` to make a run finish | hides the truncation the ledger exists to show |
| retrying with a larger budget and reporting only the second run | makes the preregistered protocol unfalsifiable |

### 4.5 Prioritisation under a breadth budget

When `max_claims_investigated` binds, claims are selected by a deterministic
priority:

1. claims whose capability is model-reachable with higher taint on the trigger
2. claims with `HYPOTHESIS_ONLY` signals present — **including sink-rule
   hypotheses**, which is exactly and only what such evidence is for
3. claims whose next tier is available at low cost
4. the total order of §3.3 as the final tie-break

Prioritisation is where legacy rule knowledge earns its keep: a `name_call` match
cannot settle anything, but it is a perfectly good reason to investigate one
claim before another. Prioritisation must never change a verdict, only the order
in which verdicts are attempted, and the ledger reports the priority policy
identifier so that a run's ordering can be reproduced.

---

## 5. Pinning and reproducibility

### 5.1 Version identity is part of the evidence

Any packet from L5, L6 or L7-via-dependency records the package name and the
resolved version. An obligation settled from `boto3` source is settled from a
*specific* `boto3`; without the version the extract cannot be re-verified and
evidence fidelity (§6.2 of [evidence_acquisition.md](evidence_acquisition.md)) is
unenforceable.

### 5.2 Resolution order for the pinned version

1. a lockfile entry (`uv.lock`, `poetry.lock`, `package-lock.json`,
   `pnpm-lock.yaml`, `yarn.lock`, `go.sum`)
2. an exact pin in a manifest (`==`, exact `version`, `go.mod` require)
3. metadata of a dependency tree actually present in the workspace
   (`*.dist-info/METADATA`, `node_modules/**/package.json`, module cache path)

The first that resolves wins, and which one was used is recorded.

### 5.3 Unpinned dependencies cap descent

If no version can be resolved, descent may still read source that is physically
present (that source is the ground truth for this tree), and the packet is marked
`version_resolution: UNPINNED`. If no source is present either, L5 is
`TIER_UNAVAILABLE` and descent stops. An unpinned, absent dependency is never
substituted by a "typical" or "latest" version's semantics — that would be
reasoning about code that is not in the repository under analysis.

---

## 6. The frontier

### 6.1 Definition

The **frontier** is the set of descent edges that were *identified as relevant
and not opened*. It is the architecture's record of its own ignorance and is
required output on every claim.

Each frontier entry records: the edge's origin locator; the target as far as it
is known (symbol, package, contract document); the tier it would have reached;
the obligation(s) it might have settled; and why it was not opened
(`BUDGET_EXHAUSTED` with the budget name, `TIER_UNAVAILABLE`,
`MAX_TIER_REACHED`, `CANDIDATE_LIMIT`, `ACQUISITION_ERROR`).

### 6.2 What the frontier is used for

1. **Closure.** C5 requires the frontier relevant to a refuted obligation to be
   empty before `NO_EFFECT` ([proof_obligations.md](proof_obligations.md) §5.3).
   A non-empty relevant frontier makes `NO_EFFECT` unavailable — this is the
   mechanism that makes "we did not look" impossible to report as "nothing
   there".
2. **Coverage.** Frontier size, by tier and by reason, is a required ledger
   field.
3. **Diagnosis.** In R05/R06, frontier contents identify which tier would have
   needed to be reachable for a missed effect to be found — feeding
   first-broken-component categories N and O
   ([validation_protocol.md](validation_protocol.md) §7).
4. **Prioritisation.** A large frontier concentrated on one package is a signal
   about where reach is worth improving; it is a research output, not a
   justification for a provider-specific shortcut.

### 6.3 The frontier must not be summarised away

A count is not sufficient. The frontier is enumerated in the receipt up to a
configured cap, with the cap and the true total both reported. A "frontier: 412"
with no content is not auditable; and an omitted frontier would let an `ABSTAIN`
masquerade as a thorough negative.

### 6.4 The silent-failure precedent

This repository has already shipped exactly the failure the frontier prevents:
transitive reachability was enabled with **2 followed edges against 3,297
unfollowed**, catching 0 of 22 confirmed cases, and the defect was invisible
until an explicit `transitive_unfollowed_count` disclosure was added. The
frontier generalises that disclosure and makes it structural rather than a single
counter, which is why it is a required field and not a diagnostic flag.

---

## 7. Accounting

Every run reports, in the coverage ledger:

- claims instantiated, scheduled, investigated, and not investigated
- per-budget exhaustion counts, by budget name
- hops followed and hops declined
- distinct artefacts opened and bytes read, by tier
- highest-tier-reached histogram over claims
- stop-reason histogram over claims
- frontier size by tier and by reason
- wall time, and the count of claims that hit `max_wall_ms_per_claim`

Accounting is the input to R05/R06's performance accounting
([validation_protocol.md](validation_protocol.md) §7.4) and to the "abstained
because" analysis that decides whether the architecture's abstention is
principled or merely unreachable evidence.

---

## 8. Invariants and test obligations

| Id | Invariant |
|---|---|
| `AREF-002-D01` | Descent terminates on every input; no unbounded recursion, no unbounded breadth. |
| `AREF-002-D02` | For fixed workspace, configuration and budget, the opened-edge set and the frontier are identical across runs. |
| `AREF-002-D03` | Budget exhaustion never changes an obligation from `UNKNOWN` to `SUPPORTED` or `REFUTED`. |
| `AREF-002-D04` | Budget exhaustion on a contributing path makes `NO_EFFECT` unreachable (C4). |
| `AREF-002-D05` | A non-empty frontier relevant to the refuted obligation makes `NO_EFFECT` unreachable (C5). |
| `AREF-002-D06` | Every unopened relevant edge appears on the frontier with a reason; the reason distinguishes budget from unavailability. |
| `AREF-002-D07` | A partially followed wrapper chain settles no obligation the unfollowed remainder would have settled. |
| `AREF-002-D08` | Every L5/L6/L7-via-dependency packet records package name and version resolution, including `UNPINNED`. |
| `AREF-002-D09` | No descent performs network access, package installation, or execution of analysed code. |
| `AREF-002-D10` | Caching changes cost only: cached and uncached runs produce identical packets and extracts. |
| `AREF-002-D11` | Prioritisation changes only investigation order; two runs with different priority policies and unbounded budget produce identical verdicts. |
| `AREF-002-D12` | An uninvestigated claim is reported with reason `CLAIM_NOT_INVESTIGATED` and is never counted as a negative. |
