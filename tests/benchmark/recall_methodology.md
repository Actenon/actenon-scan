# Recall Denominator Methodology

**Version:** 1.0
**Status:** Methodology documented. Sample collection required.
**Author:** Agent A3 — recall denominator study (Task 5-A3)

This document defines how to produce the first honest **recall denominator**
for Actenon Scan: the count of agent-reachable unguarded consequential actions
across the 25 pinned corpus repos, of which scan's reported findings are a
subset. It is the methodology behind [`recall-denominator.json`](./recall-denominator.json)
and [`docs/RECALL.md`](../../docs/RECALL.md).

It is published **before** a verified denominator exists. That ordering is
deliberate: a methodology written after the fact rationalises whatever the
sample happened to find. A methodology written first can be wrong about the
sample, but not in a self-serving direction.

---

## 1. Why a denominator is needed

Precision is well-measured in this project: 21/22 = 95.5%, hand-triaged,
regression-fixtured, gated in CI by
[`corpus-triage.json`](./corpus-triage.json). See
[`docs/COVERAGE.md`](../../docs/COVERAGE.md) and
[`docs/CORPUS_STUDY.md`](../../docs/CORPUS_STUDY.md).

Recall is not. [`baseline.json`](./baseline.json) reads
`"recall_corpus": 3` — that is the count of **architectures** with a
hand-triaged true positive on a pinned commit (`r01`, `r02`, `r03` in
[`corpus-evidence.json`](./corpus-evidence.json)). It is an *architecture
coverage* number, not a recall number. A security tool can cover every
architecture and still miss sinks inside architectures it nominally covers.
Conversely, a security tool can miss architectures and still surface every
sink in the repos that actually use the architectures it covers.

The denominator nobody has is this:

> Across the 25 pinned repos, how many **agent-reachable unguarded
> consequential actions** exist that scan did **not** report?

This document defines how to produce that number.

---

## 2. The target population

**Population:** all agent-reachable unguarded consequential actions across
the 25 pinned repos in [`pinned_repos.json`](./pinned_repos.json), at the
pinned commit SHA, in Python / TypeScript / Go files.

**Inclusion criteria** (an action is in the population iff all hold):

1. The action is a **consequential sink** — it matches one of the rule
   families in [`actenon_scan/rules/default_rules.json`](../../actenon_scan/rules/default_rules.json):
   `shell`, `file`, `db`, `money` (payments), `comms` (email/SMS/Slack/SES/
   SNS/Twilio), `repo` (git/GitHub mutation), `secret`, `provider-sdk`,
   `net-egress`.
2. The action is **agent-reachable**: there exists a static path from an
   agent entrypoint to the sink. Agent entrypoints are defined by scan's
   reachability module — MCP `@mcp.tool` decorators, TS `setRequestHandler`,
   `BaseTool` subclasses, `@function_tool`, `@tool`, action/observation
   dispatchers, raw tool-schema dispatch, and (not yet detected — see
   [`docs/COVERAGE.md`](../../docs/COVERAGE.md) §r05) custom agent loops.
3. The action is **unguarded**: no guard on every path to the sink dominates
   it (per scan's guard-dominance logic in
   [`actenon_scan/detectors/guards.py`](../../actenon_scan/detectors/guards.py)).
4. The guard (if present) is **not bound** to the action — this is the
   binding limitation documented in [`docs/COVERAGE.md`](../../docs/COVERAGE.md)
   §"The central limitation: parameter binding". A guard that authorises a
   different object than the sink acts on is *defeated* and the action counts
   as unguarded for the recall denominator. (Note: scan cannot verify this
   property statically; the recall denominator is by hand-label, which can
   resolve it.)

**Exclusion criteria** (an action is *not* in the population):

1. The sink is in a `__main__` block or at module import scope (not
   agent-selectable — see [`tests/benchmark/precision/p12_playwright_docs_script.py`](./precision/p12_playwright_docs_script.py)
   and the agno module-level triage correction in
   [`corpus-triage.json`](./corpus-triage.json) `corrections`).
2. The sink is in a control repo (`psf/requests`, `pallets/flask`,
   `fastapi/fastapi`, `pallets/click`, `Textualize/rich`) — control repos by
   definition contain no agent entrypoints. Any finding there is a precision
   failure, not a recall data point.
3. The sink is guarded and the guard dominates it on every path and is bound
   to the action.
4. The sink is in a test fixture or example file that is not registered as an
   agent tool (e.g. `examples/build_customized_agent.py` *is* a tool because
   it instantiates an `Action` subclass — see
   [`corpus-triage.json`](./corpus-triage.json) — but a `tests/` file with a
   `subprocess.run` call is not).
5. The file is in a language scan does not support — these are listed as
   `unsupported_files` in [`corpus-results.json`](./corpus-results.json),
   never silently counted as clean.

---

## 3. Sampling strategy

A census (label every file in every repo) is infeasible: the corpus is
~21,308 files (per [`docs/COVERAGE.md`](../../docs/COVERAGE.md)). The
sampling strategy is **stratified random sampling** with the strata chosen
to maximise information per label, because the expensive resource is human
triage time, not file count.

### 3.1 Strata

**Stratum A — by repo.** Three strata, by category in
[`pinned_repos.json`](./pinned_repos.json):

| Stratum | Repos | Rationale |
|---|---|---|
| A1 — framework | langchain, llamaindex, crewai, autogen, semantic-kernel, haystack, agno, openai-agents, pydantic-ai (9 repos) | Frameworks define the agent entrypoints scan recognises. Most agent-reachable sinks in the corpus live here. |
| A2 — application | open-interpreter, openhands, aider, gpt-engineer, browser-use, metagpt, superagi (7 repos) | Applications use the frameworks. Application code is where r05 custom agent loops and r06 action/observation dispatch live. |
| A3 — mcp_server | mcp-servers, mcp-python-sdk, github-mcp-server, mcp-atlassian (4 repos) | MCP servers use the entrypoints scan covers best (`r01`, `r02`). |
| (excluded) | requests, flask, fastapi, click, rich (5 control repos) | By definition no agent entrypoints. |

**Stratum B — by entrypoint type.** Per
[`docs/COVERAGE.md`](../../docs/COVERAGE.md) coverage table:

| Stratum | Architecture | Scan status |
|---|---|---|
| B1 | decorator (`@mcp.tool`, `@function_tool`, `@tool`) | COVERED (r01) / PARTIAL (r04) |
| B2 | registration (TS `setRequestHandler`, raw tool-schema) | COVERED (r02) / PARTIAL (r07) |
| B3 | base class (`BaseTool._run`/`_execute`) | COVERED (r03) |
| B4 | action/observation dispatcher | NOT COVERED (r06, historical) |
| B5 | custom agent loop | NOT COVERED (r05, rejected) |

**Stratum C — by sink family.** Per
[`actenon_scan/rules/default_rules.json`](../../actenon_scan/rules/default_rules.json):

| Stratum | Family | Examples |
|---|---|---|
| C1 | shell | `subprocess.run`, `os.system` |
| C2 | file | `open('w')`, `os.remove`, `shutil.rmtree` |
| C3 | db | `cursor.execute("DELETE")`, SQL mutations |
| C4 | money | `stripe.Refund.create`, `braintree` |
| C5 | comms | `smtp.send_message`, `slack.chat_postMessage` |
| C6 | repo | `git.push`, `github.create_file` |
| C7 | net-egress | `requests.post`, `httpx.post` |

### 3.2 Sample size

Target: **20 files hand-labeled per repo, across 3 repos** (60 files total),
stratified as follows:

- 1 framework repo (e.g. `agno` — large, low findings, suspicious), 20 files
- 1 application repo (e.g. `openhands` — large, zero findings, suspicious), 20 files
- 1 mcp_server repo (e.g. `mcp-atlassian` — zero findings despite being an
  MCP server that wraps an external API), 20 files

Within each repo, sample:

- 5 files chosen by `grep` for sink-rule patterns (high-confidence recall —
  these should mostly be caught)
- 5 files chosen randomly from files scan reported as clean with zero
  findings (this is where missed sinks would live if they exist)
- 5 files chosen by entrypoint pattern (`@tool`, `BaseTool` subclass,
  `setRequestHandler`, custom agent loop class with `chat()` method)
- 5 files chosen by sink-family pattern (one each from C1-C7, randomly)

A target of 60 labels gives a Wilson 95% CI narrow enough to be useful: if
scan misses K of N labeled agent-reachable unguarded sinks, the Wilson
interval around K/N bounds the true recall with the precision needed to
make a defensible claim (e.g. 50/60 = 83%, Wilson [0.71, 0.91]).

### 3.3 Selection without repo cloning

If the pinned repos cannot be cloned at their pinned SHAs (network
constraints), the sample cannot be drawn. The fallback is to estimate
the denominator from coverage gaps (see
[`docs/RECALL.md`](../../docs/RECALL.md) §"Estimated recall range") —
this is an **estimate, not a measurement**, and is published as such.

---

## 4. Labeling protocol

For each sampled file:

1. **Identify every agent-reachable function** in the file. Use scan's
   reachability module
   ([`actenon_scan/detectors/reachability.py`](../../actenon_scan/detectors/reachability.py)) to
   list candidate entrypoints, then verify by hand. Record the qualified
   name (e.g. `MyTool._execute`).

2. **Walk the function body and its transitive call tree.** For each
   function reachable from the entrypoint, list every call expression. For
   each call, determine if it matches a sink rule from
   [`actenon_scan/rules/default_rules.json`](../../actenon_scan/rules/default_rules.json).
   Use scan's repository-level call graph
   ([`actenon_scan/engine.py`](../../actenon_scan/engine.py) with
   `--repository-analysis` enabled) to enumerate the transitive call tree.

3. **For each sink call, label:**
   - `agent_reachable`: true iff there is a static path from an agent
     entrypoint to this sink
   - `guarded`: true iff a guard exists on some path to the sink
   - `guard_dominates`: true iff a guard exists on **every** path to the
     sink (per [`actenon_scan/detectors/guards.py`](../../actenon_scan/detectors/guards.py)
     dominance logic)
   - (hand-only) `guard_bound`: true iff the guard's arguments refer to the
     same variables as the sink — scan cannot verify this, but a human
     reading the code can. An unbound guard counts as not guarding.

4. **Classify each sink** into one of three buckets:

   - **agent-reachable unguarded** — counts toward the recall denominator
   - **agent-reachable guarded** — does not count (the guard protects it)
   - **not agent-reachable** — does not count (no entrypoint reaches it)

5. **Cross-reference with scan output.** For each labeled sink, look up
   whether scan reported a finding at this `file:line`. Use
   [`corpus-results.json`](./corpus-results.json) and the scan output JSON
   for the same SHA. Record `scan_caught: true`/`false` and the
   `scan_rule_id` if caught.

6. **Record in** [`recall-denominator.json`](./recall-denominator.json)
   with `verified: true`. Every `verified: true` entry MUST have a real
   `repo`/`file`/`line`/`sink_call_text` from the pinned repo. No
   fabrication.

---

## 5. Recall formula

```
recall = caught_agent_reachable_unguarded_sinks
       / total_agent_reachable_unguarded_sinks
```

where:

- `caught_agent_reachable_unguarded_sinks` = count of labels with
  `agent_reachable: true`, `guarded: false` (or `guard_dominates: false`
  or guard unbound), `scan_caught: true`, `verified: true`
- `total_agent_reachable_unguarded_sinks` = count of labels with
  `agent_reachable: true`, `guarded: false` (or `guard_dominates: false`
  or guard unbound), `verified: true` — i.e. the denominator includes
  both caught and missed

Entries with `verified: false` (estimated misses based on coverage gaps)
**do not** count toward either term. They are documented as
structurally-likely misses but are not measurements.

---

## 6. Confidence interval

Small-sample Wilson score interval at 95% confidence:

```
p_wilson = (p + z²/2n ± z * sqrt(p(1-p)/n + z²/4n²)) / (1 + z²/n)
```

where:

- `p` = sample recall (caught / total)
- `n` = total labeled agent-reachable unguarded sinks
- `z = 1.96` for 95% confidence

Why Wilson and not the normal approximation: at small `n` and extreme `p`
(near 0 or near 1), the normal approximation is biased and can produce
intervals below 0 or above 1. Wilson is bounded and well-behaved at small
n. See Brown, Cai & DasGupta (2001), "Interval Estimation for a Binomial
Proportion".

Worked example for `n=21, p=1.0` (all caught, no missed — the current
state of [`recall-denominator.json`](./recall-denominator.json)):

```
Wilson 95% CI = [0.845, 1.000]
```

**This interval is meaningless** because the sample is biased: every
label in [`recall-denominator.json`](./recall-denominator.json) with
`verified: true` comes from a finding scan already surfaced (per
[`corpus-triage.json`](./corpus-triage.json)). We have not hand-labeled
any file scan reported as clean. Until we do, the verified recall is
trivially 1.0 — and trivially uninformative.

---

## 7. Bias acknowledgment

This methodology is itself error-prone. The known biases:

1. **Labeler bias** — the human triaging a sink has an opinion about whether
   it is agent-reachable. The triage rationale strings in
   [`corpus-triage.json`](./corpus-triage.json) are themselves
   interpretive. Mitigation: every `verified: true` label MUST cite the
   file:line and quote the sink call text and the entrypoint, so a
   second labeler can reproduce or contest the verdict.

2. **Selection bias** — files chosen by `grep` for sink-rule patterns are
   biased toward sinks scan is likely to catch. Files chosen randomly from
   scan's "clean" pile are biased toward true negatives. Both biases make
   recall look better than it is. Mitigation: the stratified sampling
   in §3.2 mixes both, and the methodology records which stratum each
   label came from.

3. **Reachability bias** — scan's reachability module defines what counts
   as an agent entrypoint. A sink behind an entrypoint scan doesn't
   recognise (e.g. r05 custom agent loop) will be labeled
   `agent_reachable: false` if the labeler trusts scan, or `true` if the
   labeler reasons independently. This is the deepest bias: the recall
   measurement depends on the same definition of "agent-reachable" that
   scan uses. Mitigation: for r05 and r06 files, label
   `agent_reachable` independently of scan, then record scan's verdict
   separately.

4. **Sample size bias** — at N=60 labels, the Wilson 95% CI is wide. The
   honest framing is "scan's recall on this corpus is between X% and Y%
   with 95% confidence", not "scan's recall is Z%". Mitigation: publish
   the interval, not the point estimate.

5. **Coverage-gap estimation bias** — when repos cannot be cloned,
   [`docs/RECALL.md`](../../docs/RECALL.md) publishes an *estimate* of
   misses based on which architectures scan does not cover (r05, r06 in
   [`docs/COVERAGE.md`](../../docs/COVERAGE.md)). This estimate is a
   guess, not a measurement. It is published with `verified: false` in
   [`recall-denominator.json`](./recall-denominator.json) and is not
   included in the recall formula.

**The recall figure produced by this methodology is a sample estimate, not
ground truth.** It is more honest than no figure, and less honest than a
census. The reason to publish it is that no security tool in this product
category has published one.

---

## 8. Reproduction checklist

To extend [`recall-denominator.json`](./recall-denominator.json) with
verified misses:

1. Clone one pinned repo at its pinned SHA:
   ```
   git clone https://github.com/<org>/<repo>
   cd <repo>
   git checkout <sha>
   ```
   SHAs are in [`pinned_repos.json`](./pinned_repos.json).

2. Run scan on the cloned repo to get the current findings:
   ```
   actenon-scan --repository-analysis --format json <repo_dir> > scan.json
   ```

3. Sample 20 files per §3.2. For each file, follow §4.

4. For each verified label, append an entry to
   [`recall-denominator.json`](./recall-denominator.json) with
   `verified: true` and the real `repo`/`file`/`line`/`sink_call_text`.

5. Recompute the `summary` block. The Wilson interval
   (`confidence_interval_95`) updates with the new `n`.

6. Re-run the validation:
   ```
   python -c "import json; json.load(open('tests/benchmark/recall-denominator.json'))"
   ```

7. Update [`docs/RECALL.md`](../../docs/RECALL.md) with the new number and
   the new interval.

---

## 9. What this methodology does NOT claim

- It does not claim scan's recall is X%. It claims scan's recall **on the
  labeled sample** is X%, with a 95% CI of [Y, Z].
- It does not claim the sample is representative. It claims the sample is
  stratified by the strata that matter (repo, entrypoint, sink family),
  and the stratification is documented.
- It does not claim the labels are correct. It claims the labels are
  reproducible (each one cites the file:line and the sink call text) and
  therefore contestable.
- It does not claim the methodology is complete. It claims the methodology
  is the first honest attempt, and that future maintainers can extend it
  by following §8.

---

## 10. References

- [`docs/COVERAGE.md`](../../docs/COVERAGE.md) — the coverage contract
- [`tests/benchmark/pinned_repos.json`](./pinned_repos.json) — the 25
  pinned repos
- [`tests/benchmark/corpus-results.json`](./corpus-results.json) — scan's
  output on the corpus (22 findings, 21 TP)
- [`tests/benchmark/corpus-triage.json`](./corpus-triage.json) —
  hand-triage of every finding (21 TP, 1 FP)
- [`tests/benchmark/corpus-evidence.json`](./corpus-evidence.json) —
  architecture coverage evidence (r01-r04)
- [`tests/benchmark/baseline.json`](./baseline.json) — scoreboard
- [`actenon_scan/rules/default_rules.json`](../../actenon_scan/rules/default_rules.json)
  — sink rules scan looks for
- [`actenon_scan/detectors/reachability.py`](../../actenon_scan/detectors/reachability.py) —
  agent entrypoint recognition
- [`actenon_scan/detectors/guards.py`](../../actenon_scan/detectors/guards.py) —
  guard dominance logic
- Brown, Cai & DasGupta (2001), "Interval Estimation for a Binomial
  Proportion", *Statistical Science* 16(2):101–133 — Wilson interval
  rationale
