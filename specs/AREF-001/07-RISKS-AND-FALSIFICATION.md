# AREF-001 §7 — Risk register and falsification

## 7.1 Risk register

Likelihood and impact are the freeze author's judgement, stated so they can be
disagreed with. "Mitigated by" names a frozen decision or invariant; risks with
no mitigation are marked so explicitly rather than being given a reassuring one.

| ID | Risk | L | I | Mitigated by | Residual |
|---|---|---|---|---|---|
| R-01 | A wrong `resource:` line on a correct finding makes the correct finding look unreliable, and the reader discounts the whole report | med | high | D-11 opt-in; D-08 certainty cap; U-2 rendering rules | **Yes — unmitigable without B-05.** The primary reason for the NOT READY verdict |
| R-02 | The layer resolves almost nothing, and an all-unknown report is read as "no resources here" | **high** | high | D-13 mandatory counters; I-11 including the all-unknown case | Low. This is the one high-likelihood risk with a complete mitigation, because the repository already paid for the lesson |
| R-03 | The catalogue is quietly reimplemented in Python, one provider at a time, until it is the `_name_looks_db` defect again | med | high | D-06 data-only; I-10 structural grep assertion | Medium. A grep assertion is crude and a determined contributor can route around it |
| R-04 | Two meanings of "resource" in one report; readers conflate an HTTP entrypoint with the object a sink acts on | med | med | D-12 naming mandate; I-08 independence test | Low, *if* D-12 survives review. It is the decision most likely to be dismissed as pedantry, and the repository has already shipped this exact defect once (`f472a57`) |
| R-05 | `scope` is `unknown` everywhere, so the component that justified the record carries no information | **high** | med | Disclosed by D-13 rather than fixed | **Yes.** Honest but useless is still useless — falsifier F-2 |
| R-06 | Go and TypeScript sites annotate as `language_not_supported` while the report implies coverage | med | med | D-14 language-aware normalisation; draft catalogue covers TS and Go rule IDs | Low |
| R-07 | Severity escalation is added later "since we have scope now", without a measured FP rate | med | **high** | D-09 frozen no-escalation; I-02 | Medium. A frozen decision is a document, not a lock; only I-02's test is mechanical |
| R-08 | Performance: locating a call node per capability re-walks ASTs | low | low | Annotation is O(capabilities), not O(files); ASTs are already parsed and passed in (§4.2) | Low. `check_perf_gate.py` already exists as the instrument |
| R-09 | `ResourceKind` membership churns after release, breaking the release-to-release diffability that justified closing the enum | med | med | B-02 must close *before* v0 ships | Medium |
| R-10 | The freeze is edited in place as decisions change, destroying its value as a reviewable baseline | med | med | §0.7: supersede with AREF-002, never edit | Medium — process only, nothing mechanical |
| R-11 | Consumers depend on REI internals during the release in which they are most likely to move | low | med | §4.5 exports only the data types, not the inference entry point | Low |
| R-12 | The missing REI evidence turns out to contradict a *frozen* decision, not just a blocked one | low | **high** | Separation of D-01…D-14 from B-01…B-06; §0.7 supersession | **Yes.** Unquantifiable without the evidence. R-12 is the honest reason a freeze built on absent evidence cannot be called ready |

### On R-02 and R-05 being the two high-likelihood risks

Both are "the layer produces unknowns". They are separated because their
mitigations differ in kind. R-02 is a *presentation* failure — an all-unknown
report misread as a clean one — and it is fully mitigable with a counter, which
is why D-13 is frozen as mandatory. R-05 is a *capability* failure — the layer
genuinely cannot answer the question that motivated it — and no amount of
disclosure fixes it. Conflating them would let a counter look like a solution to
both.

## 7.2 Falsification criteria

Restated compactly from [06-ARCHITECTURE-QUESTIONS.md](06-ARCHITECTURE-QUESTIONS.md)
Q7, with the threshold and the measurement that would settle each. Thresholds
are stated as *decision rules*, not as predictions about what the answer is.

| # | Falsifier | Threshold | Measured by |
|---|---|---|---|
| F-1 | Declarative extraction is insufficient | selector resolved (origin not `absent` and not `dynamic`) on < 50% of real sink sites | REI-001 |
| F-2 | Scope carries no information | `scope == unknown` on > 90% of real sink sites | REI-001 |
| F-3 | The vocabulary is wrong | any single `ResourceKind` absorbs > 50% of determined sites, **or** > 20% of sites need a member that does not exist | REI-001 |
| F-4 | Annotation harms the reader | readers shown the line adjudicate *worse* than readers shown none | REI-002 or a human study |

Each threshold is a number chosen in advance so that the measurement cannot be
argued after the fact. Whether they are the *right* numbers is itself open to
review — but a threshold set before the data is the only kind that can fail.

## 7.3 Precision budget

REI cannot change precision as measured (D-01, I-01): precision is computed from
findings, and REI does not touch findings. The relevant budget is therefore not
the precision benchmark but the **annotation error rate**, which the repository
currently has no instrument for.

The freeze's position: a resource annotation is *wrong* if a human reading the
call site would name a different `kind` or a narrower `scope`. Until an
instrument for that exists, the only defensible budget is the one D-08 and §3.7
already impose — `certainty` capped at `strong`, `proven` unreachable — which
means every annotation is, on its face, a claim the reader may override.

This is weaker than a measured budget and is stated as weaker. It is B-05.

## 7.4 What could go wrong that this freeze does not cover

Named explicitly, because a risk register that looks complete is more dangerous
than one that admits its edges.

- **Rule semantics drift.** A future edit to `default_rules.json` widens
  `DATA-DELETE-SQL` to a new receiver family; the catalogue still says
  `database_row_set`; the annotation is now wrong for the new members and no
  test notices. A catalogue/rule coherence gate would catch it. None is
  specified, because the shape of such a gate depends on B-02 and B-03.
- **Multi-resource calls.** `shutil.copytree(src, dst)` acts on two paths.
  D-02 freezes one record per site, so one of them is unrepresented. This is a
  known, deliberate loss of information; whether it matters is a frequency
  question only the missing evidence can answer.
- **Effect/resource mismatch.** Nothing forbids a catalogue entry pairing
  `money_refund` with `filesystem_path`. A coherence check over
  (`EffectType`, `ResourceKind`) pairs is possible and is **not** specified —
  the plausible pair set is a measurement, not a judgement, and inventing one
  here would be exactly the kind of guess §1 forbids.
- **The reader's actual question.** REI answers "what does this act on". A
  reader may want "what would this cost me". Those are different, and the second
  is not on any roadmap in this repository.

## 7.5 Interaction with existing CI gates

| Gate | Effect of REI as frozen | Why |
|---|---|---|
| `pytest tests/` | Adds ~12 obligations; changes no existing test | Additive layer |
| `scripts/check_benchmark_integrity.py` | No effect | No benchmark fixture is touched. `CONTRIBUTING.md` Rule 3 is not engaged |
| `scripts/check_corpus_triage.py` | No effect | Finding set unchanged (I-01), so triage entries stay in bijection |
| `scripts/check_coverage_contract.py` | No effect | No sink rule added or removed; `docs/COVERAGE.md` rows unchanged |
| `scripts/check_perf_gate.py` | Small risk, flag-gated | R-08 |
| `scripts/check_version_coherence.py` | Requires a CHANGELOG entry in the implementing work order | Existing project rule |
| `.github/workflows/link-check.yml` | Applies to this directory's markdown now | All links here are relative and resolve; no external URL is used |
| self-scan clean | No effect | `specs/AREF-001/validate.py` contains no sink call and is not agent-reachable |

## 7.6 Freeze expiry

AREF-001 describes `b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16`. It must be
re-validated if any of the following changes, because each is load-bearing for a
frozen decision:

| Trigger | Invalidates |
|---|---|
| `EffectType` membership changes | D-04, §3.2, the schema `enum`, T07 |
| `default_rules.json` sink IDs change | D-14, the draft catalogue, §10.4 |
| `AnalysisCertainty` or `TaintLattice` membership changes | D-03, D-08, §3.5, §3.7 |
| `resource_boundary_*` naming changes | D-12 |
| An interprocedural taint layer lands | X-06, and Q1's refusal list |
| REI-001 / REI-001B / REI-002 become accessible | B-01…B-06, and therefore the verdict |

The last row is the one that matters. AREF-001's verdict is a function of
evidence availability, so the arrival of the evidence is not a minor update — it
is the event that supersedes this document.
