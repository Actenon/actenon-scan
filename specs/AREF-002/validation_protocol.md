# AREF-002 — Held-out validation protocol: R05 / R06 (preregistered)

**Status:** frozen. Normative. Preregistered **before any candidate repository
has been selected, inspected, searched for, identified or obtained.**
**Parent:** [AREF-002.md](AREF-002.md)

> **No repository has been selected or inspected.** This protocol is written
> entirely in terms of *criteria and procedure*. It names no candidate, contains
> no repository identity, and was not informed by browsing, searching or cloning
> any candidate. R07 is likewise not selected, not inspected and not described.

Preregistration is the point of this document. A protocol written after seeing
the repositories cannot distinguish a prediction from an explanation, and the
architecture's central claim — that it can reason about code it has never seen —
is exactly the kind of claim that is trivial to fake retrospectively.

---

## 1. What R05 and R06 are for

R05 and R06 are held-out, real-world validations of the AREF-002 architecture.
They exist to **falsify** it. The frozen prior evidence is controlled-corpus
only — REI-001B 30/30 over 30 cases with 165 counterfactual runs, REI-002 36/36
over 36 cases with 126 counterfactual runs — and R04 is the one real-world
measurement available: **0 of 17** manually identified consequential paths
detected, **13 of 17** first broken at semantic resource-effect recognition.

R05/R06 therefore answer one question: **does claim-first, evidence-led effect
inference recover any of the semantic recall that the sink-centric architecture
measured at zero, without manufacturing effects and without abstaining on
everything?**

What they cannot do is establish that the architecture is *correct*. Two
repositories are two repositories. They can show it is broken, show where, and
show whether its uncertainty semantics hold under conditions nobody constructed.

---

## 2. Selection criteria (frozen; no selection performed)

### 2.1 Required properties

A candidate qualifies only if **all** hold:

| # | Criterion |
|---|---|
| S1 | A real, public, non-synthetic repository that exposes AI-agent-reachable capabilities (MCP server, tool/function-calling surface, agent framework integration, or equivalent) |
| S2 | Contains at least one plausible external-state-affecting operation reachable from a capability, assessed **only after** selection is locked (§2.4) |
| S3 | Has a resolvable commit SHA that can be pinned in the preregistration |
| S4 | Has a dependency manifest, so that L4 is in principle reachable |
| S5 | Not present in any Actenon benchmark, corpus, fixture, research target list or published disclosure (§3) |
| S6 | Not authored or contributed to by anyone involved in specifying AREF-002 |
| S7 | Large enough to be non-trivial and small enough for exhaustive manual ground truth: an order of magnitude comparable to R04's 17 paths, not 1 path and not 500 |
| S8 | Licence permits local analysis and quotation of extracts in a report |

### 2.2 Language spread — a property of the pair

The **pair** must satisfy: one member predominantly TypeScript/JavaScript, the
other predominantly Go or Python. This mirrors the language spread of REI-001B
and REI-002 and tests the language-skew hazard directly — the rule corpus is
31 Python sink IDs against 9 TypeScript and 9 Go, and the architecture claims
that skew now affects *priority* rather than *existence*.

This is a constraint on the pair, not a description of any repository. Which
member is which is decided at selection time.

### 2.3 Disqualifiers

| # | Disqualifier |
|---|---|
| X1 | Appears in `tests/benchmark/pinned_repos.json`, `tests/corpus/`, `research/reachability-ground-truth/`, or `research/industry-scan/targets.json` |
| X2 | Was the subject of any prior Actenon disclosure or case study, including R04's subject |
| X3 | Was inspected, browsed, searched for or cloned during AREF-001 or AREF-002 specification |
| X4 | Selected because a preliminary Actenon run on it looked good |
| X5 | Contains no dependency manifest or no capability surface |

X4 deserves emphasis: **running the scanner is not permitted as a selection
instrument.** Selection is on the criteria above, then the commit is pinned, then
the scan happens once.

### 2.4 Selection order — and why it is strict

1. This protocol is frozen and hashed (§4).
2. Candidates are enumerated against S1, S3–S8 and X1–X5 **without reading their
   effect-relevant code** beyond what S1 and S4 require.
3. The pair is chosen and the commit SHAs are pinned.
4. Ground truth is produced manually and blind (§5).
5. The scan runs once, with the preregistered configuration.
6. Results are computed and compared against the preregistered thresholds.

S2 is assessed only at step 4. A repository chosen *because* it contains effects
that Actenon happens to handle is not a held-out validation, and the difference
between steps 2 and 4 is the whole guarantee.

---

## 3. Contamination rules

### 3.1 Exclusions

| Source | Why |
|---|---|
| `tests/benchmark/pinned_repos.json` | benchmark numbers already depend on it |
| `tests/corpus/` | fixtures; already shaped by the scanner |
| `research/reachability-ground-truth/` | already used to tune reachability |
| `research/industry-scan/targets.json` | already scanned |
| R04's subject, at any commit | already analysed in depth; its 17 paths are known |
| any repository named in a prior disclosure | the outcome is known |
| any repository inspected while specifying AREF-001 or AREF-002 | not held out |

### 3.2 Specification contamination

No AREF-002 artefact may be amended after a candidate is inspected, except by a
dated, hashed amendment that states what was learned and why the change is not a
fit to the observation. An unamended silent edit invalidates the run.

### 3.3 Implementation contamination

The implementation is frozen at a commit before the scan. No code, rule, budget,
threshold or configuration change may be made between seeing R05/R06 results and
recording them. Changes *after* recording are permitted, produce a new
implementation commit, and require a fresh held-out repository — never a re-run
on R05/R06.

### 3.4 Ground-truth contamination

Ground truth is produced by a procedure that does not read Actenon output for the
repository (§5). If it is produced after a scan has been seen, the run is invalid.

---

## 4. Preregistration record

Before the scan, a preregistration file is written and its SHA-256 recorded:

| Field | Content |
|---|---|
| `protocol_version` | the SHA-256 of this document |
| `implementation_commit` | the pinned scanner commit under test |
| `architecture_commit` | the commit containing `specs/AREF-002/` |
| `configuration` | the complete effective configuration, verbatim |
| `budgets` | all seven values from [dependency_descent.md](dependency_descent.md) §4.1 |
| `enabled_effect_classes` | must be exactly `["EXTERNAL_PERSISTENT_STATE_EFFECT"]` |
| `repository_refs` | owner/name plus commit SHA for R05 and R06 |
| `ground_truth_sha256` | SHA-256 of the sealed ground-truth file |
| `ground_truth_sealed_at` | timestamp, before the first scan |
| `thresholds` | every threshold in §8, verbatim |
| `falsifiers` | every falsifier in §9 |
| `priority_policy_id` | the investigation-priority policy identifier |
| `analyst_ids` | who produced ground truth, who ran the scan |

The ground-truth hash is committed **before** the first scan. That single hash is
what makes "we did not move the goalposts" checkable rather than asserted, and it
is the mechanism the repository's own `CONTRIBUTING.md` Rule 3 demands — never
move a benchmark number by changing a fixture.

---

## 5. Manual ground-truth procedure

### 5.1 Blindness

Ground truth is produced by manual reading, before any AREF-002 output for the
repository is seen. The analyst may use the repository, its dependencies, its
documentation and any public API contract. The analyst may not use Actenon
output, the sink-rule corpus, or the ladder as a checklist.

### 5.2 Unit of ground truth

The unit is a **(capability, invocation, effect class)** triple — the same
identity the architecture uses — recorded at `(path, line, column)` against the
pinned commit. The unit is deliberately not "a finding": R04's 17 paths were
paths, and an architecture that changed the unit to suit itself would not be
comparable.

### 5.3 Labels

Each enumerated invocation reachable from a capability gets exactly one label:

| Label | Meaning |
|---|---|
| `EFFECT` | does produce an external persistent state effect |
| `NO_EFFECT` | provably does not, on the analyst's reading |
| `INDETERMINATE_BY_SOURCE` | cannot be determined from source evidence *by a human with the same access* |

`INDETERMINATE_BY_SOURCE` is the label that makes abstention measurable. Without
it, every abstention is a miss and the architecture's central honesty property
cannot be scored. Its criterion is "a competent human reading the same tree
cannot determine it", not "the analyst did not bother".

### 5.4 Required per-unit fields

For `EFFECT` units: the resource acted on; the boundary mechanism; the operation
and what establishes it; the persistence mechanism and what establishes it; the
deepest ladder tier a human needed; and whether the evidence a human used is
present in the tree or came from outside it.

The last field is the crucial one. If a human needed documentation that is not in
the repository, then an architecture that reads only the tree **cannot** be
expected to reach `PROVEN_EFFECT`, and its abstention there is correct rather
than a miss. This field is what separates "the architecture failed" from "the
evidence was not there" — the distinction [REPORT.md](REPORT.md) Q10 identifies
as the deepest unsolved problem.

### 5.5 Adjudication and sealing

Disagreements are resolved by a second reader and the resolution recorded. The
file is then sealed and hashed. After sealing, ground truth changes only by a
dated, hashed erratum stating the reading error; the original remains.

---

## 6. Denominators

Stated explicitly because every metric in §7 is meaningless without them, and
because a shifting denominator is the easiest way to make a bad result look good.

| Denominator | Definition |
|---|---|
| `D_invocations` | invocations enumerated from capabilities, per ground truth |
| `D_effect` | units labelled `EFFECT` — **the semantic positive denominator** |
| `D_no_effect` | units labelled `NO_EFFECT` — **the negative denominator** |
| `D_indeterminate` | units labelled `INDETERMINATE_BY_SOURCE` |
| `D_claimed_proven` | units on which the scanner returned `PROVEN_EFFECT` |
| `D_claimed_no_effect` | units on which the scanner returned `NO_EFFECT` |
| `D_abstain` | units on which the scanner returned `ABSTAIN` |
| `D_error` | units on which the scanner returned `ANALYSIS_ERROR` |
| `D_uninvestigated` | claims instantiated but never investigated |

Two rules are frozen:

1. **`D_effect` is the recall denominator and it is fixed by ground truth, not
   by what the scanner enumerated.** If the scanner never enumerates an
   invocation, that is a miss with a first-broken component, not a reduction of
   the denominator.
2. **`D_indeterminate` is excluded from precision and recall and scored
   separately** (§7.3). Including it in recall would penalise correct abstention;
   including it in precision would reward it.

---

## 7. Measurements

All eight measurement families are reported separately. **No composite score is
computed**: a single number would let one family compensate for another, which is
exactly the gaming the thresholds in §8 exist to prevent.

### 7.1 `PROVEN_EFFECT` precision

```
precision = |PROVEN_EFFECT ∩ EFFECT| / D_claimed_proven
```

Every false `PROVEN_EFFECT` is individually analysed: which obligation was
wrongly `SUPPORTED`, which packet supported it, its tier, its admissibility, and
whether a counter-evidence probe should have caught it.

An `INDETERMINATE_BY_SOURCE` unit returned as `PROVEN_EFFECT` counts as a
**precision failure**, not a neutral outcome. Claiming proof where a human with
the same access cannot determine the answer is the strongest possible signal that
the proof machinery leaks.

### 7.2 Semantic positive recall

```
recall = |PROVEN_EFFECT ∩ EFFECT| / D_effect
```

The direct comparison against R04's **0 / 17**. Reported both overall and split
by whether the human's evidence was present in the tree (§5.4), because the two
sub-populations test different things: the first tests the architecture, the
second tests the reach of local evidence.

A secondary, clearly labelled figure is also reported: **claim-level recall**, the
fraction of `EFFECT` units for which a claim was *instantiated at all*. This
isolates requirement 2 — under the sink-centric architecture, 13 of R04's 17
misses never produced a candidate object. Claim-level recall near 1.00 with low
`PROVEN_EFFECT` recall means the ontology is right and the evidence reach is
short, which is a completely different diagnosis from both being low.

### 7.3 Appropriate abstention accuracy

Measured on `D_indeterminate` and on `EFFECT`/`NO_EFFECT` units where required
evidence was absent from the tree:

```
required_abstention_accuracy = |ABSTAIN ∩ abstention_required| / |abstention_required|
inappropriate_abstention_rate = |ABSTAIN ∩ (EFFECT ∪ NO_EFFECT) with in-tree evidence| / |units with in-tree evidence|
```

`abstention_required` = `INDETERMINATE_BY_SOURCE` units, plus units whose
determination required evidence absent from the tree.

Every abstention carries its stop reason, so the report separates *principled*
abstention (`NO_FURTHER_TIER` where no tier could settle it) from *reach-limited*
abstention (`TIER_UNAVAILABLE`) from *configuration-limited* abstention
(`BUDGET_EXHAUSTED`) from *scheduling-limited* abstention
(`CLAIM_NOT_INVESTIGATED`). Those four have different remedies and must never be
reported as one number.

`NO_EFFECT` is scored here too, and strictly: every `NO_EFFECT` return is checked
against `D_no_effect` **and** against closure C1–C6
([proof_obligations.md](proof_obligations.md) §5.3). A `NO_EFFECT` on an `EFFECT`
unit is a **false negative of the most serious kind** — the only verdict that
makes a safety claim — and is reported as its own line, never folded into
recall.

### 7.4 Evidence fidelity

For every packet cited in every emitted receipt:

```
fidelity = |packets whose extract is byte-identical to the located source| / |packets|
```

Checked mechanically by re-reading the locator and comparing bytes, and checked
by hand on a sample. Threshold is exactly **1.00** (§8.3). REI-001B and REI-002
both measured 100%; a real-world figure below 1.00 means the architecture cites
text that is not there, which is disqualifying regardless of precision.

Also reported: the fraction of dependency- and contract-sourced packets carrying
package name and version resolution, which must be 1.00
(`AREF-002-D08`).

### 7.5 Coverage

From the coverage ledger, cross-checked against ground truth:

- capabilities discovered versus capabilities in ground truth
- invocations enumerated versus `D_invocations`
- claims instantiated, scheduled, investigated, uninvestigated
- verdict distribution and per-obligation state distribution
- highest-tier-reached histogram, overall and for `EFFECT` units
- stop-reason histogram
- frontier size by tier and reason
- per-language distribution of the above

The tier histogram restricted to `EFFECT` units is the single most informative
output of the whole exercise: it says *how deep the architecture actually got on
the cases that mattered*. As a by-product this also produces the resource-kind
frequency table with a "needed a member that does not exist" bucket that
AREF-001's B-02 named as its closing measurement
([aref_001_delta.md](aref_001_delta.md) §4).

### 7.6 Analysis errors

`D_error`, by obligation and by cause, with the frequency of `ANALYSIS_ERROR`
verdicts and every crash, parse failure and internal exception. Reported
separately from abstention: an error is a bug, an abstention is a coverage fact,
and merging them would let a broken run look like a cautious one
(`AREF-002-T16`).

### 7.7 Budget exhaustion

Per-budget exhaustion counts by budget name; claims affected; and — critically —
the count of `EFFECT` units whose verdict was `ABSTAIN` with reason
`BUDGET_EXHAUSTED`. That last number distinguishes "the architecture cannot do
this" from "we configured it too small", and it is the only one of the eight
families whose remedy is a configuration change.

### 7.8 Unresolved reasons

The full stop-reason and frontier-reason histograms, plus for every `EFFECT` unit
not returned as `PROVEN_EFFECT` the specific reason, at the level of the
obligation that remained unsettled and the tier that would have settled it.

### 7.9 First-broken-component analysis

For every `EFFECT` unit not returned as `PROVEN_EFFECT`, exactly one earliest
failing component is recorded. Categories A, B, F, H are carried forward from
R04's taxonomy so that the two studies are directly comparable; I–O are new and
exist because AREF-002 has more places to break.

| Code | Component |
|---|---|
| A | capability discovery / registration |
| B | handler extraction |
| F | interprocedural resolution |
| H | semantic effect recognition — *the R04 category, 13 of 17* |
| I | implementation candidate resolution |
| J | `ACTIVATION` evidence |
| K | `BOUNDARY` evidence |
| L | `OPERATION` evidence |
| M | `PERSISTENCE` evidence |
| N | ladder tier not reached (with the tier and the reason) |
| O | budget exhausted (with the budget name) |
| P | claim never instantiated |
| Q | claim instantiated but never investigated |
| R | counter-evidence probe incomplete |
| S | contradiction unresolved (`CONFLICTING`) |

**The headline comparison is category H against R04's 13 of 17, and category P
against R04's structural inability to instantiate.** If P is non-trivial, the
claim-first inversion is not working as specified, because requirement 2 says a
claim exists regardless of rule coverage. If H collapses and N/O dominate, the
ontology is right and the *evidence reach* is the bottleneck — which is the
outcome [REPORT.md](REPORT.md) Q10 predicts as most likely.

### 7.10 Performance accounting

Wall time overall and per claim; claims investigated per second; distinct
artefacts opened and bytes read by tier; peak memory; cache hit rate; claims that
hit `max_wall_ms_per_claim`; and the marginal cost of each ladder tier — the
additional wall time and I/O attributable to enabling L5, L6 and L7.

Marginal tier cost is recorded because a tier that is expensive and never settles
anything is a candidate for removal, and a tier that is cheap and settles a lot
is a candidate for a larger budget. Both are post-validation decisions, not
mid-run adjustments.

---

## 8. Thresholds and outcome rules

Every threshold is preregistered. Meeting them is a **necessary** condition for
proceeding to default-on integration, never a sufficient one.

### 8.1 Primary thresholds

| Metric | Threshold | Rationale |
|---|---|---|
| `PROVEN_EFFECT` precision | **≥ 0.90** | the repository's existing precision gate is strict and a false HIGH is its most expensive single error; "false assurance is worse than a reviewable false positive" cuts both ways |
| Semantic positive recall | **≥ 0.30** | R04 measured 0/17; any non-trivial recovery is the result being tested. A higher bar would be unfalsifiable posturing on two repositories |
| Evidence fidelity | **= 1.00** | REI-001B and REI-002 both measured 100%; anything less is fabricated evidence |
| Required-abstention accuracy | **≥ 0.90** | the architecture's core honesty claim |
| Inappropriate abstention rate | **≤ 0.20** | bounds abstaining where the evidence *was* in the tree |
| False `NO_EFFECT` on `EFFECT` units | **= 0** | the only verdict making a safety claim; one instance falsifies the closure rules |

### 8.2 Anti-gaming rules

Both directions are closed, because each threshold above is individually
satisfiable by a degenerate architecture.

**Against precision-by-abstention.** A run is **INVALID**, not merely poor, if
`D_abstain / D_invocations > 0.95`. An architecture that abstains on everything
achieves perfect precision and zero information, and reporting that as a pass
would be dishonest. Additionally, precision ≥ 0.90 is only creditable when recall
≥ 0.30 is *also* met: the two are reported and judged as a pair, never
separately, and a precision figure computed on fewer than 10 `PROVEN_EFFECT`
returns is reported with its count and treated as indicative only.

**Against recall-by-unsupported-claims.** Every `PROVEN_EFFECT` is audited for
the admissibility of the packets that settled each obligation. If **any**
obligation was moved by a `HYPOTHESIS_ONLY` packet, the run **FAILS on
architecture**, irrespective of its metrics. Recall obtained by relaxing what
counts as proof is not recall. Similarly, recall is only creditable when
false-`NO_EFFECT` is 0 and fidelity is 1.00.

### 8.3 Fidelity is disqualifying

A single packet whose extract is not byte-identical to its locator fails the run.
There is no partial credit. The defect is reported, fixed, and a new held-out
repository is required — R05/R06 cannot be re-run after a fix (§3.3).

### 8.4 Admissibility leakage is an architecture failure, not a tuning failure

If a `HYPOTHESIS_ONLY` packet is found to have moved an obligation state, the
correct response is **not** to adjust a threshold, tighten a rule or re-classify
the packet. It is to record that the architecture's central guarantee did not
hold in implementation, fix the implementation, and validate on fresh
repositories. Invariant `AREF-002-T03`; discussion in
[evidence_acquisition.md](evidence_acquisition.md) §5.5.

### 8.5 Provider-specific patches are prohibited

Between preregistration and reporting, the implementation may not gain:

- a signature, rule, table or heuristic naming a specific provider, SDK, package
  or service observed in R05 or R06
- a special case keyed on a package name, module path, host or identifier from
  those repositories
- a rule added because it makes an R05/R06 case pass
- a budget or threshold tuned against R05/R06 results

This is the task's STRICT RULES applied to validation, and it is also the only
way the measurement means anything: an architecture patched per provider is a
catalogue again, and a catalogue is what R04 falsified. Generic improvements
discovered through R05/R06 are legitimate, must be recorded as such with their
rationale, and require fresh held-out repositories to validate.

### 8.6 Outcome vocabulary

| Outcome | Condition |
|---|---|
| `SUPPORTED` | all §8.1 thresholds met on both repositories, no §8.2 violation, no §8.5 violation |
| `PARTIALLY_SUPPORTED` | thresholds met on one repository, or recall met with precision between 0.80 and 0.90 — reported with the specific gap and no integration change |
| `REFUTED` | precision < 0.80, or recall ≈ 0 (no material improvement on R04's 0/17), or any false `NO_EFFECT`, or fidelity < 1.00 |
| `INVALID` | abstention rate > 0.95, contamination, or a protocol violation |
| `ARCHITECTURE_FAILURE` | admissibility leakage, or an obligation settled by an inadmissible source |

`REFUTED` with H collapsed and N/O dominant is a *specific and useful* refutation:
it means the ontology is right and the evidence-acquisition problem
([REPORT.md](REPORT.md) Q10) is the binding constraint. `REFUTED` with P
non-trivial is a *general* refutation: claim instantiation itself does not work
as specified, and the architecture must change.

---

## 9. Validation obligations

Properties R05/R06 must test explicitly, in addition to the metrics.

| Id | Obligation |
|---|---|
| `AREF-002-V01` | Claim-level recall on `EFFECT` units is reported separately from `PROVEN_EFFECT` recall, isolating requirement 2. |
| `AREF-002-V02` | Every emitted verdict has a schema-valid receipt whose `answers` object contains all eleven required keys. |
| `AREF-002-V03` | **The unfamiliar-SDK property.** For at least one `EFFECT` unit whose callee matches **no** rule in the sink corpus, a claim is instantiated and investigated, and its receipt names the tiers reached. This is the direct test of [AREF-002.md](AREF-002.md) §13; failure means the claim-first inversion did not hold in implementation. |
| `AREF-002-V04` | Re-running with the sink-rule corpus emptied changes no claim's existence and no claim's stop reason; it may change only packets and priority (`AREF-002-T02`). This run is a control and is reported alongside the main run. |
| `AREF-002-V05` | No provider-specific signature, table or identifier list is present in the implementation commit under test (§8.5). |
| `AREF-002-V06` | Two runs with identical configuration produce identical verdicts, packets, extracts and frontiers (`AREF-002-D02`). |
| `AREF-002-V07` | Every `ABSTAIN` carries a highest-tier-reached, a stop reason, an unresolved-obligation list and a frontier size (`AREF-002-T17`). |
| `AREF-002-V08` | No output path renders zero `PROVEN_EFFECT` as "safe", "clean" or "no effects" (`AREF-002-T19`); checked on every emitted format. |
| `AREF-002-V09` | The existing scanner gates are unchanged by enabling the layer: precision 16/16, soundness 6/6 and the recall figures are byte-identical with the layer on and off. |
| `AREF-002-V10` | No obligation belonging only to a declared-unpopulated future effect class is read by the v1 verdict function (`AREF-002-T20`). |

`AREF-002-V04` is worth its cost. It is the only direct experimental test that the
sink-centric gate is gone, and it is a counterfactual in exactly the style of
REI-001B's remasking and REI-002's operation-contract swap — the technique the
frozen evidence used to establish its own invariants.

---

## 10. What R05/R06 will falsify or support

**Support, if thresholds are met:** that claim-first effect inference recovers
measurable semantic recall on real code where the sink-centric architecture
measured zero; that a claim can be instantiated and investigated for an SDK with
no rule; that the uncertainty semantics hold on unconstructed code, with
abstention concentrated where evidence is genuinely absent; and that evidence
fidelity survives outside a controlled corpus.

**Falsify:** any of the above. Specifically — that claim instantiation is
universal (category P); that `PROVEN_EFFECT` means what the conjunction says
(precision, and audited admissibility); that `NO_EFFECT` closure is sound (any
false `NO_EFFECT`); that abstention is principled rather than blanket (the 0.95
invalidation rule); that the ladder reaches evidence that exists (categories N
and O); and that receipts cite real text (fidelity).

**Neither supports nor falsifies:** whether the architecture generalises beyond
two repositories; whether the nine declared-unpopulated effect classes are
correctly specified; whether any effect actually occurred at runtime; and whether
authority, severity or reporting integration is right. Those are out of scope by
construction, and claiming otherwise from two repositories would repeat the
overreach this freeze exists to correct.
