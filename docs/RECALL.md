# Recall — the first honest number

**Status:** NOT YET COMPUTABLE. Methodology documented. Sample collection required.
**Data:** [`tests/benchmark/recall-denominator.json`](../tests/benchmark/recall-denominator.json)
**Methodology:** [`tests/benchmark/recall_methodology.md`](../tests/benchmark/recall_methodology.md)
**Author:** Agent A3 — recall denominator study (Task 5-A3)

---

## Honest framing, upfront

- **This is a SAMPLE, not a census.** The 25 pinned repos contain ~21,308
  files ([`docs/COVERAGE.md`](COVERAGE.md)). We have not labeled them all.
- **The sample size is small (N=21 verified labels). The confidence interval
  is wide, and worse — it is meaningless** (see §"Why the verified CI is
  meaningless" below).
- **The labels are author-produced and may contain errors.** Every verified
  label cites a file:line in a pinned repo so a second labeler can
  reproduce or contest it, but no second labeler has yet done so.
- **This is the first recall measurement in this product category. It may
  be uncomfortable. That is the reason to publish it.**

A security tool that publishes only precision publishes only the question
"of the things we reported, how many were real?" That question is necessary
but not sufficient. The question users actually need answered is "of the
real risks in my codebase, how many did you surface?" That is recall. The
reason no static agent-safety tool publishes it is that the answer is
uncomfortable. This document publishes it anyway, with the caveat that the
honest answer at the present sample size is "we do not yet know — but here
is what we can say."

---

## The headline

> **Recall denominator: NOT YET COMPUTABLE.**
>
> Methodology documented. Sample collection required.
>
> We have 21 verified labels — all of them sinks scan caught. We have zero
> verified labels for sinks scan missed, because we have not hand-labeled
> any file scan reported as clean. The verified recall is therefore 21/21
> = 100%, which is a tautology and not a measurement.
>
> Across the 25 pinned repos, we **estimate** scan misses between **5 and
> 50** agent-reachable unguarded consequential actions, with a point
> estimate of 20. This corresponds to an **estimated recall range of
> 29.6% to 80.8%** (point estimate 51.2%). **This range is an estimate,
> not a measurement. It is derived from coverage gaps, not from sampling.
> It has no statistical coverage.**

The number nobody has is uncomfortable, and the honest framing is that
nobody yet has the number either. What this document provides is the
methodology to produce it, the data we have, and a clearly-labelled
estimate of where the truth probably lies.

---

## What we have: 21 verified true positives

Scan's corpus run
([`tests/benchmark/corpus-results.json`](../tests/benchmark/corpus-results.json))
produced 22 findings across the 25 pinned repos. Hand triage
([`tests/benchmark/corpus-triage.json`](../tests/benchmark/corpus-triage.json))
classified 21 as true positives and 1 as a recorded false positive
(github-mcp-server `actions.go:172`, tracking issue #81 — the function is
not directly agent-reachable; the scanner cannot determine this without
interprocedural analysis).

These 21 true positives are the **verified labels** in
[`tests/benchmark/recall-denominator.json`](../tests/benchmark/recall-denominator.json).
Each one cites a real file:line in a pinned repo. They are:

| Repo | File:line | Sink | Rule | Entrypoint |
|---|---|---|---|---|
| mcp-servers | src/memory/index.ts:117 | fs.writeFile | FILE-WRITE | registration |
| mcp-python-sdk | examples/mcpserver/text_me.py:48 | client.post | NET-EGRESS | decorator (@mcp.tool) |
| crewai | lib/crewai-tools/.../enterprise_adapter.py:255 | requests.post | NET-EGRESS | base_class |
| crewai | lib/crewai-tools/.../brightdata_serp.py:224 | requests.post | NET-EGRESS | base_class |
| crewai | lib/crewai-tools/.../contextual_rerank_tool.py:69 | requests.post | NET-EGRESS | base_class |
| crewai | lib/crewai-tools/.../crewai_platform_action_tool.py:70 | requests.post | NET-EGRESS | base_class |
| crewai | lib/crewai-tools/.../generate_crewai_automation_tool.py:52 | requests.post | NET-EGRESS | base_class |
| crewai | lib/crewai-tools/.../parallel_search_tool.py:104 | requests.post | NET-EGRESS | base_class |
| crewai | lib/crewai-tools/.../patronus_eval_tool.py:145 | requests.post | NET-EGRESS | base_class |
| crewai | lib/crewai-tools/.../patronus_predefined_criteria_eval_tool.py:95 | requests.post | NET-EGRESS | base_class |
| metagpt | examples/build_customized_agent.py:48 | subprocess.run | EXEC-SHELL | base_class (Action) |
| metagpt | metagpt/ext/android_assistant/actions/manual_record.py:54 | open('w') | FILE-OPEN-WRITE | base_class (Action) |
| metagpt | metagpt/ext/android_assistant/actions/parse_record.py:121 | open('a') | FILE-OPEN-WRITE | base_class (Action) |
| metagpt | metagpt/ext/android_assistant/actions/parse_record.py:130 | open('w') | FILE-OPEN-WRITE | base_class (Action) |
| metagpt | metagpt/ext/cr/actions/modify_code.py:109 | open('w') | FILE-OPEN-WRITE | base_class (Action) |
| superagi | superagi/tools/email/send_email.py:85 | smtp.send_message | COMMUNICATION-SEND | base_class |
| superagi | superagi/tools/file/append_file.py:70 | open('a+') | FILE-OPEN-WRITE | base_class |
| superagi | superagi/tools/file/delete_file.py:61 | os.remove | DATA-DELETE-OS | base_class |
| superagi | superagi/tools/file/read_file.py:68 | open('wb') | FILE-OPEN-WRITE | base_class |
| superagi | superagi/tools/file/read_file.py:99 | os.remove | DATA-DELETE-OS | base_class |
| superagi | superagi/tools/slack/send_message.py:50 | slack.chat_postMessage | COMMUNICATION-SEND | base_class |

Plus 1 verified false positive (github-mcp-server actions.go:172), labeled
with `agent_reachable: false` because the function is a helper, not a
registered tool handler. It does not count toward the recall denominator.

---

## What we do not have: verified misses

To compute recall, the denominator must include the false negatives — the
agent-reachable unguarded consequential actions scan **did not** report.
We have zero verified labels for these.

**Why:** producing a verified miss requires cloning a pinned repo at its
pinned SHA (see [`tests/benchmark/pinned_repos.json`](../tests/benchmark/pinned_repos.json)),
hand-labeling 20+ files per repo across 3+ repos
(see [`tests/benchmark/recall_methodology.md`](../tests/benchmark/recall_methodology.md)
§3.2), and recording each verified miss with its real file:line. In the
environment that produced this document, the pinned repos could not be
cloned at their pinned SHAs. The constraints
([`tests/benchmark/recall_methodology.md`](../tests/benchmark/recall_methodology.md)
§7.5) therefore require that any unverified miss be labeled
`"verified": false` and not count toward the recall formula.

This is the discipline that distinguishes an honest recall number from a
marketing number. A security tool that publishes a recall figure without
showing its false-negative labels is asking the reader to trust a
denominator it cannot produce. This document declines to ask that.

---

## Why the verified CI is meaningless

The verified sample is 21 labels, all of which scan caught. The Wilson 95%
confidence interval for 21/21 is **[0.845, 1.000]**.

This interval is **meaningless** and we publish it only to be transparent
about why. The reason: every verified label in
[`tests/benchmark/recall-denominator.json`](../tests/benchmark/recall-denominator.json)
was sourced from [`tests/benchmark/corpus-triage.json`](../tests/benchmark/corpus-triage.json)
— which is the hand-triage of findings scan **already reported**. We
have hand-labeled **zero** files scan reported as clean. A sample drawn
exclusively from scan's reported findings cannot produce a verified miss
by construction. The verified recall is therefore a tautology, not a
measurement.

The lower bound of [0.845, 1.000] does not bound the true recall. The
true recall is unknown because we have not measured any false negatives.
This is the bias acknowledged in
[`tests/benchmark/recall_methodology.md`](../tests/benchmark/recall_methodology.md)
§7.2 (selection bias) and §7.5 (coverage-gap estimation bias).

---

## The estimate (clearly labelled)

Since a verified denominator is not yet computable in this environment,
we publish an **estimate** derived from coverage gaps. The estimate is in
[`tests/benchmark/recall-denominator.json`](../tests/benchmark/recall-denominator.json)
under the `summary.estimated_*` fields, with six `verified: false` label
entries documenting the structural sources of likely misses.

### Estimate basis

The estimate is derived from the coverage table in
[`docs/COVERAGE.md`](COVERAGE.md):

| Architecture | Status | Implication for recall |
|---|---|---|
| `r01` MCP tool decorator | COVERED | scan catches these (1 TP in corpus) |
| `r02` MCP request handler (TS) | COVERED | scan catches these (1 TP in corpus) |
| `r03` Tool base class | COVERED | scan catches these (19 TPs in corpus) |
| `r04` Function-tool decorator | PARTIAL | scan fires on fixtures; only corpus candidate was an FP. May miss real TPs. |
| `r05` Custom agent loop | **NOT COVERED** | scan does not even try — pre-triage returned 10/10 FPs. Likely source of substantial misses in agent-loop frameworks. |
| `r06` Action/observation dispatcher | **NOT COVERED** | historical; OpenHands restructured away. May be 0 misses or small. |
| `r07` Raw tool-schema dispatch | PARTIAL | scan fires on fixtures, zero candidates on 7,354 corpus files. May miss real TPs. |

### Per-architecture estimate of misses

| Architecture | Likely-affected repos | Estimated misses (lower-upper) | Reasoning |
|---|---|---|---|
| `r05` custom agent loop | openhands (2202 files, 0 findings), autogen (671 files, 0 findings), agno (4255 files, 2 findings) | 5–35 | Largest blind spot. OpenHands at 2202 files with zero findings is the most suspicious data point in the corpus: an agent coding assistant of that size almost certainly has consequential sinks in custom loops scan cannot see. |
| `r06` action/observation | openhands (restructured away) | 0–3 | Historical pattern. May be zero if architecture has fully migrated. |
| `r04` @function_tool | openai-agents (840 files, 0 findings) | 0–3 | PARTIAL. Either scan correctly finds zero beyond the FP, or it misses some. Cannot determine without hand-labeling. |
| `r07` raw tool-schema | (any repo with a tool schema) | 0–2 | PARTIAL. Zero candidates on 7,354 files at zero precision cost. May be genuinely absent or may be missed. |
| Other PARTIAL architectures (r08, r09, r10) | various | 0–7 | Each PARTIAL by definition. Net misses small but non-zero. |
| **Total** | | **5–50** | **Point estimate: 20** |

### Estimate arithmetic

- Worst case (50 misses): recall = 21 / (21 + 50) = 21/71 = **29.6%**
- Point estimate (20 misses): recall = 21 / (21 + 20) = 21/41 = **51.2%**
- Best case (5 misses): recall = 21 / (21 + 5) = 21/26 = **80.8%**

### Estimate range

> Across the 25 pinned repos, we estimate scan misses between **5 and 50**
> agent-reachable unguarded consequential actions, with a point estimate of
> 20. This corresponds to an **estimated recall range of 29.6% to 80.8%**
> (point estimate 51.2%).

**This range is an estimate, not a measurement.** It is derived from
coverage gaps in [`docs/COVERAGE.md`](COVERAGE.md), not from sampling. It
has no statistical coverage. The lower bound (29.6%) is the worst case
under the assumption that each NOT COVERED and PARTIAL architecture
contributes its upper-bound count of misses; the upper bound (80.8%) is
the best case under the assumption that each contributes its lower-bound
count. Neither bound is a confidence interval.

### Why the range is wide

The width of the range encodes the depth of our ignorance about the
denominator. We have not hand-labeled any file scan reported as clean.
We do not know whether OpenHands' zero findings reflect a true absence of
agent-reachable unguarded consequential actions, or a structural blind
spot in scan (it almost certainly reflects the latter — OpenHands is an
agent coding assistant with 2202 files and zero findings is not
credible). The range will narrow only when verified labels are added per
[`tests/benchmark/recall_methodology.md`](../tests/benchmark/recall_methodology.md)
§8.

---

## Why the honest answer is uncomfortable

The estimate's point (51.2%) and lower bound (29.6%) are uncomfortable
for a security product. They should be. A scanner that admits its recall
might be as low as 30% is a scanner a user treats as one signal among
several, not as a clean bill of health. That is the correct posture for
static analysis in this product category.

The alternative — publishing only the verified recall of 21/21 = 100% —
would be technically defensible (it is the verified measurement) and
practically misleading (it implies scan catches everything, which it does
not). This document declines to publish the misleading number alone. The
verified measurement is published alongside the estimate and the
explanation of why the verified measurement is uninformative.

A security tool that publishes only the question it can answer well is a
security tool that converts a real risk into a false sense of safety.
That is the failure mode [`docs/COVERAGE.md`](COVERAGE.md) exists to
prevent. This document extends that posture from coverage to recall.

---

## What would be needed to produce a verified recall figure

Per [`tests/benchmark/recall_methodology.md`](../tests/benchmark/recall_methodology.md)
§8:

1. **Clone the 25 pinned repos at their pinned SHAs** (in
   [`tests/benchmark/pinned_repos.json`](../tests/benchmark/pinned_repos.json)).
   The fetch URL pattern is
   `https://github.com/{repo}/archive/{sha}.tar.gz`.

2. **Hand-label 20 files per repo across 3 repos** (60 files total),
   stratified per methodology §3.2:
   - 1 framework repo (suggest `agno` — large, low findings, suspicious)
   - 1 application repo (suggest `openhands` — large, zero findings,
     suspicious)
   - 1 mcp_server repo (suggest `mcp-atlassian` — zero findings despite
     wrapping an external API)

3. **For each file, follow the labeling protocol** in methodology §4:
   - Identify every agent-reachable function (use scan's reachability
     module)
   - Walk its body and transitive call tree (use scan's
     `--repository-analysis` call graph)
   - For each sink call, label `agent_reachable`, `guarded`,
     `guard_dominates`
   - Classify into agent-reachable-unguarded / agent-reachable-guarded /
     not-agent-reachable
   - Cross-reference with scan's output for the same SHA

4. **Append verified=true entries to**
   [`tests/benchmark/recall-denominator.json`](../tests/benchmark/recall-denominator.json)
   with the real `repo`/`file`/`line`/`sink_call_text`. No fabrication.

5. **Recompute the summary block.** The Wilson 95% CI updates with the
   new `n`. At N=60 with, say, 12 missed of 33 labeled
   agent-reachable-unguarded sinks (21 carried over + 12 newly labeled),
   recall = 21/33 = 63.6%, Wilson 95% CI ≈ [0.45, 0.79]. That would be
   the first honest, statistically-defensible recall figure in this
   product category.

6. **Update this document** with the new number, the new interval, and
   the date. Leave the previous estimate in a "prior estimate" section so
   the history of the number is visible.

---

## Blockers

- **Pinned repo access.** The pinned repos could not be cloned at their
  pinned SHAs in the environment that produced this document (network
  constraints). All 25 SHAs are in
  [`tests/benchmark/pinned_repos.json`](../tests/benchmark/pinned_repos.json);
  reproduction requires either network access or local mirrors at the
  pinned SHAs.
- **Hand-labeling time.** The methodology targets 60 hand-labeled files
  (20 per repo across 3 repos). At ~15 minutes per file (identify
  entrypoints, walk call tree, label each sink, cross-reference scan
  output), that is ~15 person-hours of triage. The corpus triage in
  [`tests/benchmark/corpus-triage.json`](../tests/benchmark/corpus-triage.json)
  took longer; this is a smaller investment.
- **Second labeler for bias check.** The methodology acknowledges
  ([`tests/benchmark/recall_methodology.md`](../tests/benchmark/recall_methodology.md)
  §7.1) that labeler bias is real. A second labeler should re-triage a
  20% random subsample (12 of 60) and the disagreement rate should be
  published. Not a blocker for the first measurement; a blocker for
  claiming the measurement is unbiased.

---

## What this document is, and is not

**Is:** the first honest attempt to publish a recall denominator for
Actenon Scan, with the methodology to extend it, the data we have, and a
clearly-labelled estimate of where the truth probably lies.

**Is not:** a verified recall figure. That requires the work in §"What
would be needed". Until that work is done, the honest verdict is
**NOT YET COMPUTABLE. Methodology documented. Sample collection
required.**

This document is published before that work is done because the order
matters: a methodology written after the sample is rationalised by the
sample; a methodology written first can be wrong about the sample but not
in a self-serving direction.

---

## References

- [`tests/benchmark/recall-denominator.json`](../tests/benchmark/recall-denominator.json)
  — the labeled ground-truth data
- [`tests/benchmark/recall_methodology.md`](../tests/benchmark/recall_methodology.md)
  — the methodology document
- [`tests/benchmark/pinned_repos.json`](../tests/benchmark/pinned_repos.json)
  — the 25 pinned repos
- [`tests/benchmark/corpus-results.json`](../tests/benchmark/corpus-results.json)
  — scan's findings on the corpus (22 findings, 21 TP)
- [`tests/benchmark/corpus-triage.json`](../tests/benchmark/corpus-triage.json)
  — hand triage of every finding (21 TP, 1 FP)
- [`tests/benchmark/corpus-evidence.json`](../tests/benchmark/corpus-evidence.json)
  — architecture coverage evidence (r01-r04)
- [`tests/benchmark/baseline.json`](../tests/benchmark/baseline.json)
  — the scoreboard
- [`docs/COVERAGE.md`](COVERAGE.md) — the coverage contract
- [`actenon_scan/rules/default_rules.json`](../actenon_scan/rules/default_rules.json)
  — the sink rules scan looks for
