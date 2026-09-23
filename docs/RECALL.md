# Recall — the first honest number

> **WITHDRAWAL NOTE (2026-09-20):** The 43%–52% bracket published in commit
> `129b926` is **withdrawn**. Three defects invalidate it:
>
> 1. All 16 adjudications moved in one direction (to NOT_AGENT_REACHABLE);
>    0 moved to AGENT_REACHABLE. The adjudication is not symmetric — it
>    narrowed the bracket by moving the low end up, which is the direction
>    that flatters the tool.
> 2. 6 of 16 adjudications are not reachability judgements: they reclassify
>    cases as NOT_AGENT_REACHABLE because the file is in `examples/` or
>    `samples/` — a scope change, not an adjudication. The scope rule was
>    applied one way: two AGENT_REACHABLE cases in `examples/mcpserver/memory.py`
>    were left reachable.
> 3. The highest-weight case (`llamaindex|data_destruction`, w=297) names
>    `LoadAndSearchToolSpec.load` as the caller and concludes "not a
>    model/tool boundary," but `LoadAndSearchToolSpec` exists to hand
>    `load()` to an agent as a tool.
>
> The defensible bracket was **14%–52%** until re-adjudicated under
> pre-registered rules. That re-adjudication is now complete (see the
> "Phase 4 re-adjudication" section below). The new bracket, reported
> under both scope variants, is **~26%–31%**. No single headline
> recall number is published in this PR.

**Status:** PHASE 4 COMPLETE. The 43%–52% bracket (commit `129b926`) is
invalid as computed and is superseded by the Phase 4 re-adjudication
below. The new real-world labelled-sink bracket is **~26%–31%**, reported
under both scope variants. The three recall figures below remain
separate and are not collapsed into one number.
**Data:** [`tests/benchmark/recall-denominator.json`](../tests/benchmark/recall-denominator.json)
**Reachability ground truth:** [`research/reachability-ground-truth/labels.json`](../research/reachability-ground-truth/labels.json),
[`research/reachability-ground-truth/ambiguity_resolution.json`](../research/reachability-ground-truth/ambiguity_resolution.json),
[`research/reachability-ground-truth/adjudication_results.json`](../research/reachability-ground-truth/adjudication_results.json),
[`research/reachability-ground-truth/ADJUDICATION_RULES.md`](../research/reachability-ground-truth/ADJUDICATION_RULES.md),
[`research/reachability-ground-truth/README.md`](../research/reachability-ground-truth/README.md)
**Methodology:** [`tests/benchmark/recall_methodology.md`](../tests/benchmark/recall_methodology.md)
**Author:** Agent A3 — recall denominator study (Task 5-A3); ambiguity
adjudication by sub-agent 6-T5 (Task 5); re-adjudication by sub-agent
7-P4 (Phase 4 of the correctness PR).

---

## Phase 4 re-adjudication — new bracket under pre-registered rules (Task 7-P4)

> The Phase 4 rules were pre-registered in
> [`research/reachability-ground-truth/ADJUDICATION_RULES.md`](../research/reachability-ground-truth/ADJUDICATION_RULES.md)
> **before** any case was re-examined. Commit order in this PR is the
> proof of pre-registration: that file's first commit predates the
> re-adjudication recorded in
> [`research/reachability-ground-truth/adjudication_results.json`](../research/reachability-ground-truth/adjudication_results.json).
> The 16 cases adjudicated in commit `129b926` were each reset to their
> pre-`129b926` state (label `AMBIGUOUS`, with the original reason)
> before being re-adjudicated.

### The three recall figures, kept separate (Phase 4)

| Metric | Value | Source |
|---|---|---|
| Synthetic adversarial recall | 9/10 | `tests/benchmark/soundness/*` |
| Corpus-demonstrated architecture recall | 3/10 — gates CI | `tests/benchmark/recall_methodology.md` |
| **Real-world labelled sink recall — bracket** | **~26%–31%** (both scope variants) | this section |
| Precision benchmark | 16/16 | `tests/benchmark/precision/*` |

Never collapse them into one number. No headline recall number is
published. The synthetic and corpus figures have fully-observed
denominators; the real-world bracket is a weighted-sample estimate whose
width encodes both classification uncertainty (the AMBIGUOUS bucket) and
sampling uncertainty (still wide at 160 labels).

### Direction counts — Phase 4 reverses the asymmetry

| Direction | n | idx |
|---|---:|---|
| AMBIGUOUS → AGENT_REACHABLE | 2 | 4, 130 |
| AMBIGUOUS → NOT_AGENT_REACHABLE | 14 | 2, 5, 12, 44, 45, 46, 57, 58, 59, 88, 101, 113, 129, 150 |
| stayed AMBIGUOUS | 0 | — |

The Task-5 result was one-directional (16/16 → NOT_AGENT_REACHABLE);
this re-adjudication is **not** one-directional. Two cases moved the
other way (`AMBIGUOUS → AGENT_REACHABLE`), which is the symmetry the
withdrawal note required. The reversal is real, not a tidy round-number
fix:

- **idx 4 (`agno|data_destruction`, w=75.5):** `DbFileSystem.move` is
  reached from `FileSystemTools(Toolkit).move_file`, registered via the
  dynamic `sync_tools = [getattr(self, name) for name in registered]`
  pattern (`fs/toolkit.py:139`) — the same `DYNAMIC_DISPATCH` pattern
  already recognised for the agno `Workspace` case (idx 11). The Task-5
  labeler missed this because the chain crosses a method-call boundary
  that pure site inspection does not see.
- **idx 130 (`openai-agents|code_execution`, w=117):**
  `BaseSandboxSession.mkdir` is reached from
  `SandboxApplyPatchTool(CustomTool)._on_invoke_tool`
  (`capabilities/tools/apply_patch_tool.py:214`), which is constructed
  by `Filesystem(Capability).tools()` (`capabilities/filesystem.py:36`)
  and returned in the `tools=` list (`filesystem.py:41`). The chain
  crosses three files: `apply_patch_tool.py` → `apply_patch.py:171/172`
  (`_write_text` → `self._session.mkdir`) → `base_sandbox_session.py:1100`
  (`self.exec(*cmd, shell=False, user=user)`). The Task-5 evidence
  "traced_chain_via_app_post" was wrong — there is a real agent-runtime
  chain. (A separate sandbox-setup chain via `manifest_ops._build_manifest_applier`
  also reaches the sink but is not agent-runtime.)

### The LoadAndSearchToolSpec.load trace (idx 101, w=297 — the highest weight)

This is the case the withdrawal note specifically called out. The
actual trace, from fetched source at the pinned SHA
(`run-llama/llama_index @ 199e9b5b130bbde72639358a08935b913e7132c0`,
file `llama-index-core/llama_index/core/tools/tool_spec/load_and_search/base.py`):

```
LoadAndSearchToolSpec.__init__:
  self._tool_list = [FunctionTool.from_defaults(fn=self.load, ...),     # base.py:86-92
                     FunctionTool.from_defaults(fn=self.read, ...)]
  # ^^^ load IS an agent-facing tool (registered via FunctionTool.from_defaults + to_tool_list())

LoadAndSearchToolSpec.load(*args, **kwargs):                              # base.py:131
  if self._index is None:
    self._index = self._index_cls.from_documents(docs, **self._index_kwargs)  # base.py:153
    # ^^^ self._index_cls defaults to VectorStoreIndex (set in from_defaults at base.py:96:
    #       index_cls = index_cls or VectorStoreIndex)
    # VectorStoreIndex.from_documents does NOT call OraLlamaVS.from_documents.

OraLlamaVS.from_documents(cls, docs, table_name, **kwargs):              # oracledb/base.py:770
  drop_table_purge(_client, table_name)                                  # oracledb/base.py:782

OraLlamaVS.drop(self):                                                   # oracledb/base.py:671
  drop_table_purge(self._client, self.table_name)                        # oracledb/base.py:672
```

**Conclusion:** `LoadAndSearchToolSpec.load` IS an agent-facing tool
(the README withdrawal note was right about that) but it does **NOT**
chain to `drop_table_purge`. The chain `load → OraLlamaVS.from_documents
→ drop_table_purge` does not exist because `load` calls
`VectorStoreIndex.from_documents`, not `OraLlamaVS.from_documents`.
`drop_table_purge` is only reachable from `OraLlamaVS.drop()` (admin
method) and `OraLlamaVS.from_documents()` (setup classmethod), neither
of which is called by an agent boundary in repository-local code.

So the Task-5 adjudication reached the right answer
(`NOT_AGENT_REACHABLE`) for the wrong reason
(`vector_store_admin_via_indexing_api`). The corrected reason recorded
in `labels.json` is `vector_store_admin_no_agent_chain`.

### Bracket — variant (a): examples IN scope

Demo-directory cases are adjudicated on reachability alone; the demo
code is the population. A sink in `examples/mcpserver/memory.py`
reached from `@mcp.tool()` is AGENT_REACHABLE; a sink in
`examples/apps/news-use/news_monitor.py` reached only from `main()` is
NOT_AGENT_REACHABLE.

| | |
|---|---|
| Weighted AGENT_REACHABLE | 331.0 (22 → 24; +75.5 idx 4, +117 idx 130) |
| Weighted AMBIGUOUS | 60.0 (12 cases, untouched by Phase 4) |
| Weighted NOT_AGENT_REACHABLE | 2,718.0 |
| Total weighted | 3,109.0 (unchanged — every case still has a weight) |
| Detected | 149 (unchanged) |
| **High end (AMBIGUOUS NOT reachable)** | **31.0%** = 149/(149+331) |
| **Low end (AMBIGUOUS IS reachable)** | **27.6%** = 149/(149+331+60) |
| **Bracket (a)** | **27.6% – 31.0%** |

### Bracket — variant (b): examples OUT of scope

Every case whose file path begins with `examples/`, `samples/`,
`cookbook/`, `demos/`, or `notebooks/` is removed from the population
**on both sides** — including the two AGENT_REACHABLE cases in
`examples/mcpserver/memory.py` (idx 105, 106, weight 5.0 total). This
is the correction to the asymmetric scope rule applied in commit
`129b926`, which removed demo-directory AMBIGUOUS cases from the low
end while leaving demo-directory AGENT_REACHABLE cases in the high end.

| | |
|---|---|
| Labels removed | 18 (15 NOT_AGENT_REACHABLE, 2 AGENT_REACHABLE, 1 AMBIGUOUS) |
| Weight removed (missed side) | 214.5 (208.5 NOT + 5.0 AGENT + 1.0 AMB) |
| Weighted AGENT_REACHABLE | 326.0 (331.0 − 5.0) |
| Weighted AMBIGUOUS | 59.0 (60.0 − 1.0) |
| Total weighted (missed side) | 2,894.5 |
| Detected (adjusted) | ~136 (149 − ~13 demo-directory detected; the demo fraction of the unreachable inventory is 264/3,109 = 8.5%, applied to the 149 detected as an estimate — see caveat below) |
| **High end (AMBIGUOUS NOT reachable)** | **29.4%** = 136/(136+326) |
| **Low end (AMBIGUOUS IS reachable)** | **26.1%** = 136/(136+326+59) |
| **Bracket (b)** | **26.1% – 29.4%** |
| Bracket (b), conservative (detected unchanged at 149) | 27.9% – 31.4% |

**Detected-side caveat:** the `unreachable_inventory.json` contains
only the 3,109 unreachable sinks; the 149 detected sinks are not
stored per-file. The demo fraction of unreachable (264/3,109 = 8.5%) is
applied to 149 as an estimate, giving ~13 demo-directory detected
findings. The conservative bracket (detected unchanged at 149) is
27.9%–31.4%. A more precise variant-(b) detected count requires a
per-file breakdown of the 149 detected sinks, which is not committed in
this PR.

### Why the bracket did not move much between variants

The two brackets are close (variant (a) 27.6–31.0%; variant (b)
26.1–29.4%) because demo weight is small: 214.5 of 3,109 = 6.9% of
the sample. Removing demos moves both ends by ~2 points. The
asymmetric scope rule in commit `129b926` was a real defect, but its
numeric effect on the bracket was small — the bigger correction in
Phase 4 is the two cases moved to AGENT_REACHABLE (idx 4 and idx 130),
which moves the high end from 51.8% (the original 14%–52% bracket's
high end) to ~31%.

### Remaining AMBIGUOUS (12 cases, weighted 60) — unchanged by Phase 4

The 12 remaining AMBIGUOUS cases are the same ones identified by Task
5 as `unresolved_framework` / `unresolved_input` / `sample_app`. Phase
4 did not adjudicate them — they were not part of the 16 re-adjudicated
cases. They stay AMBIGUOUS and continue to drive the bracket width.

| idx | weight | stratum | reason |
|---|---:|---|---|
| 13 | 9.0 | agno\|shell_execution | unresolved_utility |
| 67 | 11.0 | crewai\|network_egress | unresolved_framework |
| 95 | 10.0 | llamaindex\|database_mutation | unresolved_framework |
| 49 | 6.0 | browser-use\|network_egress | unresolved_framework |
| 117 | 7.0 | metagpt\|browser_action | unresolved_framework |
| 128 | 7.0 | openai-agents\|database_mutation | unresolved_framework |
| 103 | 4.0 | mcp-atlassian\|file_mutation | unresolved_framework |
| 87 | 2.0 | langchain\|browser_action | unresolved_framework |
| 70 | 1.0 | crewai\|database_mutation | unresolved_framework |
| 116 | 1.0 | metagpt\|repository_mutation | unresolved_framework |
| 22 | 1.0 | aider\|browser_action | unresolved_input |
| 127 | 1.0 | openai-agents\|browser_action | sample_app |

### What this update did NOT do

- It did **not** produce a verified single-number recall. The remaining
  12 AMBIGUOUS cases (weighted 60) are `unresolved_framework` /
  `unresolved_input` cases where static analysis genuinely cannot
  decide without a runtime trace or a deeper interprocedural
  call-graph resolution. They were left as AMBIGUOUS, not adjudicated.
- It did **not** change the detected-side count of 149 reachable sinks,
  except for the variant-(b) detected-side adjustment (~136).
- It did **not** introduce or modify any code. Only `labels.json`,
  `adjudication_results.json` (new), `ADJUDICATION_RULES.md` (new), and
  this document changed.
- It did **not** commit or push.
- It did **not** introduce any "authority coverage", "% protected",
  "% safe", or any metric that divides findings by an estimate of total
  consequential actions.

### Reproducing the new bracket

```bash
python3 - <<'PY'
import json
from collections import defaultdict
labels = json.load(open("research/reachability-ground-truth/labels.json"))
w = defaultdict(float)
for r in labels: w[r["label"]] += r["weight"]
detected, reach, ambig = 149, w["AGENT_REACHABLE"], w["AMBIGUOUS"]
print("variant (a) high (ambig NOT reachable):", round(detected/(detected+reach)*100,1), "%")
print("variant (a) low  (ambig IS reachable):", round(detected/(detected+reach+ambig)*100,1), "%")
PY
```

Outputs `variant (a) high 31.0 %` / `variant (a) low 27.6 %`. Variant
(b) requires removing demo cases and adjusting detected; see
`adjudication_results.json` for the full calculation.

---

## Update — narrowed bracket after ambiguity adjudication (Task 5, sub-agent 6-T5)

> **WITHDRAWN (2026-09-20) and SUPERSEDED by Phase 4 above.** The
> 43%–52% bracket published here is withdrawn. The 14%–52% bracket
> that stood pending re-adjudication has been re-adjudicated; the new
> bracket is **~26%–31%** under both scope variants. See the "Phase 4
> re-adjudication" section above. The text below is retained as a
> historical record of what was claimed, why it was wrong, and how the
> pre-registered rules in `ADJUDICATION_RULES.md` corrected it.

This section supersedes the §"Estimate range" below for the real-world
labelled-sink figure. The earlier estimate (29.6%–80.8%) was a coverage-gap
estimate with no statistical coverage; the reachability ground-truth study
replaced it with a labelled-sample bracket of **14%–52%**, and this update
~~narrows that bracket to **43%–52%**~~ (WITHDRAWN — see correction above)
by adjudicating 16 of the 28 AMBIGUOUS labels.

### The three recall figures, kept separate

| Metric | Value | Source |
|---|---|---|
| Synthetic adversarial recall | 9/10 | `tests/benchmark/soundness/*` |
| Corpus-demonstrated architecture recall | 3/10 — gates CI | `tests/benchmark/recall_methodology.md` |
| **Real-world labelled sink recall — bracket** | ~~43%–52%~~ (WITHDRAWN) → **14%–52%** (stands pending re-adjudication) | this section |
| Precision benchmark | 16/16 | `tests/benchmark/precision/*` |

Never collapse them into one number. The synthetic and corpus figures have
fully-observed denominators; the real-world bracket is a weighted-sample
estimate whose width encodes classification uncertainty (now mostly resolved)
plus sampling uncertainty (still wide).

### How the bracket was narrowed

The 14%–52% bracket was driven by AMBIGUITY: 28 of 160 labels were AMBIGUOUS,
carrying a weighted total of 803 against a sample total weight of 3,109
(25.8% of the weighted sample, vs 17.5% unweighted — ambiguity concentrated in
thinly-sampled, high-weight strata). The bracket was the bounding exercise:

- If every AMBIGUOUS case is NOT reachable → recall = 149/(149+138.5) = **51.8%** (high end)
- If every AMBIGUOUS case IS reachable → recall = 149/(149+138.5+803) = **13.7%** (low end)

Sub-agent 6-T5 adjudicated 16 of the 28 AMBIGUOUS labels against the README
decision rule (AGENT_REACHABLE requires a path from an agent/tool/model-controlled
boundary; web-route-only paths and internal-code-only paths are
NOT_AGENT_REACHABLE; sample-app/build-script code is NOT_AGENT_REACHABLE).
Source for the 10 highest-weight cases was fetched at the pinned SHA from
GitHub and inspected; the remaining 6 sample-app cases were adjudicated on
the prior labeler's site-verified evidence text plus the decision rule.

**All 16 adjudications moved AMBIGUOUS → NOT_AGENT_REACHABLE.** No AMBIGUOUS
case was upgraded to AGENT_REACHABLE. This is a real result, not a tidy one:
the AMBIGUOUS bucket turned out to consist mostly of (a) DB/storage helpers
with no caller traced to a registered tool, (b) sandbox-setup plumbing not
invoked at agent runtime, (c) vector-store admin reached via internal
indexing APIs, and (d) sample/example apps. None of these is an agent
boundary action.

### Adjudication summary

| | |
|---|---|
| Cases adjudicated | 16 of 28 AMBIGUOUS |
| Adjudications to AGENT_REACHABLE | 0 |
| Adjudications to NOT_AGENT_REACHABLE | 16 |
| Strata touched | 14 (see `ambiguity_resolution.json`) |
| Weighted ambiguity before | 803.0 |
| Weighted ambiguity after | 60.0 |
| Weighted ambiguity reduction | 743.0 (92.5%) — exceeds the halving target |
| Bracket width before | 38.1 percentage points |
| Bracket width after | 8.9 percentage points |
| Bracket width reduction | 76.6% — materially narrowed |

Top strata adjudicated (by weight removed): `llamaindex|data_destruction`
(w=297, idx 101), `openai-agents|code_execution` (w=117, idx 130),
`agno|data_destruction` (w=151 across idx 2 and 4),
`openai-agents|data_destruction` (w=33, idx 129),
`semantic-kernel|data_destruction` (w=33, idx 150),
`agno|file_mutation` (w=30, idx 12), `agno|communication` (w=20, idx 5),
`langchain|data_destruction` (w=15, idx 88), `metagpt|network_egress`
(w=15, idx 113), plus 6 sample-app cases in `autogen|*`, `browser-use|*`
totalling 32 weight.

### Did the bracket narrow materially?

**Yes.** Width dropped from 38.1 to 8.9 percentage points (76.6% narrower).
Weighted ambiguity dropped from 803 to 60 (92.5% reduction), exceeding the
halving target. The high end (52%) is unchanged because no case was upgraded
to AGENT_REACHABLE — the narrowing came entirely from moving the low end up
from 14% to 43%, as AMBIGUOUS cases were reclassified NOT_AGENT_REACHABLE
rather than AGENT_REACHABLE. The true recall is therefore most likely closer
to the high end (52%) than to the midpoint.

### What this update did NOT do

- It did **not** produce a verified single-number recall. The remaining 12
  AMBIGUOUS cases (weighted 60) are `unresolved_framework` /
  `unresolved_input` cases where static analysis genuinely cannot decide
  without a runtime trace. They were left as AMBIGUOUS, not adjudicated.
- It did **not** change the detected-side count of 149 reachable sinks,
  nor the weighted AGENT_REACHABLE-but-missed estimate of 138.5 (4.45%
  weighted share of the unreachable inventory).
- It did **not** introduce or modify any code. Only `labels.json`,
  `ambiguity_resolution.json` (new), and this document changed.
- It did **not** commit or push.
- It did **not** introduce any "authority coverage", "% protected", "% safe",
  or any metric that divides findings by an estimate of total consequential
  actions. The bracket's denominators are fully observed on the detected
  side and weighted-by-design on the missed side; the AMBIGUOUS bucket is a
  weighted sum of explicitly-labelled sample rows, not an estimate of total
  actions.

### Reproducing the new bracket

```bash
python3 - <<'PY'
import json
labels = json.load(open("research/reachability-ground-truth/labels.json"))
from collections import defaultdict
w = defaultdict(float)
for r in labels: w[r["label"]] += r["weight"]
detected, reach, ambig = 149, w["AGENT_REACHABLE"], w["AMBIGUOUS"]
print("high (ambig NOT reachable):", round(detected/(detected+reach)*100,1), "%")
print("low  (ambig IS reachable):", round(detected/(detected+reach+ambig)*100,1), "%")
PY
```

Outputs `high 51.8 %` / `low 42.9 %` → bracket ~~43%–52%~~ (WITHDRAWN —
see correction note at top of file). The 14%–52% bracket stands pending
re-adjudication under pre-registered rules.

### Remaining AMBIGUOUS (12 cases, weighted 60)

| idx | weight | stratum | reason |
|---|---:|---|---|
| 13 | 9.0 | agno\|shell_execution | unresolved_utility |
| 67 | 11.0 | crewai\|network_egress | unresolved_framework |
| 95 | 10.0 | llamaindex\|database_mutation | unresolved_framework |
| 49 | 6.0 | browser-use\|network_egress | unresolved_framework |
| 117 | 7.0 | metagpt\|browser_action | unresolved_framework |
| 128 | 7.0 | openai-agents\|database_mutation | unresolved_framework |
| 103 | 4.0 | mcp-atlassian\|file_mutation | unresolved_framework |
| 87 | 2.0 | langchain\|browser_action | unresolved_framework |
| 70 | 1.0 | crewai\|database_mutation | unresolved_framework |
| 116 | 1.0 | metagpt\|repository_mutation | unresolved_framework |
| 22 | 1.0 | aider\|browser_action | unresolved_input |
| 127 | 1.0 | openai-agents\|browser_action | sample_app (potentially a real computer tool, left AMBIGUOUS by analogy with the mcp-python-sdk examples/mcpserver/memory.py AGENT_REACHABLE case in the README) |

These were left as AMBIGUOUS. Static adjudication has done what it can;
the residual 60 weighted cases require either a runtime trace or a deeper
interprocedural call-graph resolution (the README's "one next capability"
recommendation) to decide. Forcing them to one side would fabricate
confidence that does not exist.

### A note on what this update reveals about static adjudication

The bracket narrowed materially *because* the AMBIGUOUS bucket turned out to
be dominated by NOT_AGENT_REACHABLE cases that the prior labeler had parked
as AMBIGUOUS out of caution — DB helpers, sandbox plumbing, sample apps.
None of the adjudicated cases were genuine agent-reachable false negatives
in disguise. That is itself a finding: the residual ambiguity in static
reachability labelling is *not* hiding a population of missed agent sinks.
The remaining AMBIGUOUS cases are framework plumbing where the call chain
genuinely passes through a generic dispatch that static analysis cannot
resolve without the call-graph work the README recommends. The narrowing
therefore says less "we now know the recall is 43–52%" and more "the
ambiguity in our prior label was concentrated in cases that, when
adjudicated, did not move the high end".

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
   `https://github.com/{repo}/archive/{sha}.tar.gz` where `{repo}`
   is the `full_name` field and `{sha}` is the pinned SHA from the JSON.

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
