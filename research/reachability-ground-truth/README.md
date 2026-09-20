# Real-world reachability ground truth

**Question.** Of the consequential sinks actenon-scan currently considers
*unreachable* in real repositories, which are actually reachable from an
AI/agent-controlled execution path?

This phase changes no detection logic. It exists so the next engineering
change is driven by demonstrated false negatives rather than synthetic
fixtures or guessed framework patterns.

**Verdict: REAL-WORLD GROUND TRUTH ESTABLISHED.**

---

## Baseline (frozen before any change)

| | |
|---|---|
| Branch | `research/real-world-reachability-ground-truth` |
| Base | `origin/main` @ `25ee4f9ecc95ea254e8abb839f14f6c1994577a1` |
| Version | 1.4.0 |
| Working tree | clean |
| Tests | 599 passed, 12 skipped, 2 xfailed, 89 subtests |
| Recall (synthetic) | 9/10 |
| Recall (corpus-demonstrated) | 3/10 — gates CI |
| Precision | 15/15 |
| Soundness | 6/6 |
| Corpus | 25 repos, 21,308 Python files, 2,168 TS files |
| Coverage contract | 10 rows, 3 COVERED |
| Corpus triage | 22 findings, 21 TP, 1 recorded unfixed FP |

### Discrepancies found and reported, not silently corrected

1. **The session began on a stale branch.** `claude/soundness-s02-binding-fix-j80wfc`
   was at v0.8.0 with a history *unrelated* to `main` (no merge base; different
   root commit). `main` was already at v1.4.0 and had absorbed the earlier s02
   work. Measuring the stale line would have produced obsolete ground truth, so
   this branch was cut from `origin/main`.
2. **The "~3,001 unreachable sinks" figure does not carry over.** It came from a
   10-repo corpus at v0.8.0. Rebuilt here: **3,109** on the 25-repo corpus at
   v1.4.0. The similarity is a coincidence; the populations differ.
3. **Corpus fetch by tarball is blocked** (HTTP 403 through the agent proxy).
   `fetch_corpus.py` uses `git fetch --depth 1 <sha>` instead and asserts
   `HEAD == pinned sha`. All 25 repos matched their pinned `py_files` counts
   exactly, so the checkout is provably the pinned corpus.

---

## The s02 lesson is intact

Verified before proceeding:

- `tests/benchmark/soundness/s02_unbound.py` still contains
  `attacker = "evil_intent"; authorize(attacker)`.
- It is detected **for the intended reason**: `check_guard` returns
  `unbound=True` with *"assert-style guard dominates, but every variable it
  inspects resolves to a compile-time constant"*.
- Precision controls all produce 0 findings: `p08` Casbin multi-literal,
  `p09` `verify_pccb(proof, intent, action)`, `p10` `authorize("refund")`.
- `tests/test_counterfeit_binding.py` — 13 passed.

s02 was not rewritten.

---

## Dataset

`unreachable_inventory.json` — every consequential sink that
`detect_reachability` scores `none`, enumerated by mirroring
`engine.scan_path` exactly (same `_collect_files`, same sink matcher, same
self-package suppression).

**Both scanner layers were measured.** `scan_path` runs a *second*
reachability layer on directory targets: `repository/engine_augment.py`,
on by default since `25ee4f9`, which builds a call graph and computes
transitive reachability to depth 32. The inventory measures the per-file
layer; `verify_against_full_scan.py` then re-checks every hand-labelled
AGENT_REACHABLE case against the **full** scanner, repository layer
included. Result: **0 of 22 caught**. The inventory therefore stands as a
description of the shipped scanner, not merely of one layer.

| | |
|---|---|
| Files scanned | 15,364 (of 21,308; the remainder excluded by the engine's own rules) |
| Parse/detector errors | 6 |
| Sinks matched | 3,258 |
| **Unreachable** | **3,109 (95.4%)** |
| Reachable | 149 (4.6%) |

## Sample

`sample.py` → `sample.json`. Seed **20260920**, target 160, drawn
**before** any case was inspected.

Strata are (repository × consequence category); cells are visited
round-robin so neither a large repository (openhands 590, llamaindex 584,
agno 447 — 52% of the inventory) nor a generic rule (DATA-DELETE-SQL, 25%)
dominates. Result: 160 rows over 131 strata, max repo share 11.2%, max rule
share 13.8%, 12 categories, 24 repositories.

Round-robin over-samples small strata, so every row carries
`weight = stratum_N / stratum_n`. Unweighted figures describe the sample;
weighted figures estimate the inventory. Both are reported.

---

## Ground truth

| Label | n | share |
|---|---:|---:|
| AGENT_REACHABLE | 22 | 13.8% |
| NOT_AGENT_REACHABLE | 110 | 68.8% |
| AMBIGUOUS | 28 | 17.5% |

**Decision rule, stated because it moves the numbers.** AGENT_REACHABLE
requires a path from an *agent/tool/model-controlled* boundary. A
FastAPI/Flask route handler is a **resource** boundary driven by an HTTP
client, not by a model, so web-route-only paths are NOT_AGENT_REACHABLE and
carry `web_route: true`. **20 of the 110** are web-route-only. The scanner
itself treats resource boundaries as reachable — a defensible product
choice, but a different question from the one asked here.

AMBIGUOUS is never counted as safe and never enters a recall denominator.

---

## Real-world recall

**The sample cannot yield a conventional recall directly.** It was drawn
from the sinks the scanner scores `none`, so "detected among
AGENT_REACHABLE" is **0 by construction**. Reporting 0% would be
meaningless. The honest construction uses the weighted sample to estimate
the missed population and compares it against the detected population.

```
currently reachable (detected) sinks     149
estimated agent-reachable but missed    ~138   (4.5% weighted x 3,109)
estimated AMBIGUOUS                     ~803
```

| | |
|---|---|
| Recall if every AMBIGUOUS case is NOT reachable | **51.8%** |
| Recall if every AMBIGUOUS case IS reachable | **13.7%** |
| **Honest bracket** | **14% – 52%** |

Share of the unreachable inventory that is agent-reachable: 22/160 = 13.8%
unweighted, **95% Wilson CI 9.3%–19.9%**; 4.5% weighted.

### Statistical limitations

- The CI covers sampling error only. It does **not** cover classification
  error, and every label is a human judgement.
- 32 of 160 cases were verified by reading the **full** boundary→sink path
  hop by hop; the other 128 were classified from the sink site, its
  enclosing definition, its caller set and the absence of any boundary.
  Infrastructure and build-script cases are decisive at that depth; the
  AMBIGUOUS bucket is where residual doubt was parked.
- 149 "detected" is a count of reachable **sinks**, not of triaged true
  positives. The repository's own corpus triage reports 21 TP / 22 emitted
  findings, so the detected side is close to but not identically true.
- Generalises to *this* corpus at *these* SHAs. 25 repos is not the
  ecosystem.

### Keep these four numbers apart

| Metric | Value |
|---|---|
| Synthetic adversarial recall | 9/10 |
| Corpus-demonstrated architecture recall | 3/10 |
| **Real-world labelled sink recall** | **14%–52%** |
| Precision benchmark | 16/16 |

Never collapse them into one number.

---

## False-negative mechanisms

Ranked by observed count in the labelled AGENT_REACHABLE set. This table was
produced **after** classification.

| Mechanism | n | est. pop | repos | statically resolvable? | precision risk |
|---|---:|---:|---|---|---|
| `CALLBACK_REGISTRATION` | 6 | ~45 | agno, browser-use | Yes for `tools=[self.m]`; no for `getattr` | Low |
| `LOCAL_HELPER_CALL` | 5 | ~37 | crewai, langchain, superagi | Yes — same class/file | Low |
| `CROSS_MODULE_CALL` | 4 | ~18 | autogen, mcp-atlassian, superagi | Mostly — needs an import-resolved call graph | Medium |
| `MULTI_HOP_LOCAL_CALL` | 3 | ~6 | browser-use, mcp-python-sdk | Yes at depth ≤3 | Medium |
| `DYNAMIC_DISPATCH` | 2 | ~16 | agno, aider | Partly — `getattr`/polymorphism | High |
| `SCHEMA_DISPATCH` | 1 | ~2 | mcp-servers | Yes | Low |
| `LLM_OUTPUT_TO_SINK` | 1 | ~15 | superagi | No — needs taint tracking | Very high (r05 was rejected at 10/10 FP) |

Unresolved cases should become explicit **UNKNOWN**, never silently
reachable or silently safe.

---

## P01 — transitive local/interprocedural reachability

**P01 is real, not merely theoretical: 14 of 22 AGENT_REACHABLE cases (64%),
across 9 of 24 repositories, ~70 sinks estimated in the inventory.**

| Property | Result |
|---|---|
| Call depth | 1 hop: 8 · 2 hops: 5 · 3 hops: 1 |
| Same-file vs cross-file | 9 same-file · 5 cross-file |
| Function vs method | 12 method · 2 function |
| Sync vs async | 7 sync · 7 async |

Nothing deeper than 3 hops was needed. Two thirds are same-file and depth 1
— the cheapest possible interprocedural analysis captures most of it.

The canonical instance, `langchain` (case 89):

```python
@tool                                   # boundary — DETECTED
def grep_search(pattern, path, include):
    results = self._ripgrep_search(pattern, path, include)   # 1 hop

def _ripgrep_search(self, ...):
    subprocess.run(cmd, ...)            # sink — MISSED
```

### The most severe individual finding

`superagi/agent/output_handler.py:180` —

```python
def handle(self, session, assistant_reply):
    assistant_reply = JsonCleaner.extract_json_array_section(assistant_reply)
    tasks = eval(assistant_reply)       # eval() on raw model output
```

`eval()` applied directly to the LLM's reply, reached from
`ToolOutputHandler.handle_tool_response(session, assistant_reply)`. Arbitrary
code execution driven by model output, currently scored unreachable.

---

## Precision: the Agno investigation

**The `step.execute()` false positive is fixed but its defect class was only
narrowed.** `DATA-DELETE-SQL` fires on `<receiver>.execute(<non-literal>)`,
so the receiver test is the only thing separating destructive SQL from every
other `.execute()` in Python. The fix added for `step.execute()` matched
receiver names by **unanchored substring**:

```
"sandbox" contains "db"   ->   san(db)ox
```

so `sandbox.execute(cmd)` — a shell executor — was reported as destructive
SQL at **HIGH** severity. Demonstrated live on a minimal agent-reachable
case before the fix, 0 findings after.

Fixed in a separate commit: `_name_looks_db` now matches **word tokens**
(snake_case, camelCase, SCREAMING_CASE). Measured over 2,761
`.execute`-family call sites in the corpus: 1,471 receivers accepted before,
1,418 after. The 53-site delta is three receivers — `sandbox_backend` (40),
`curr` (7), `sandbox` (6). The first two are shell executors and are the
defect; `curr = conn.cursor()` keeps being accepted through `_origin_is_db`,
which resolves origin before any name heuristic.

Pinned by `tests/test_db_receiver_anchoring.py` (12 adversarial cases, both
directions) and `tests/benchmark/precision/p16_sandbox_execute.py`.

### Recorded, not fixed — each needs its own decision

- **`kernel_client.execute(code)`** (a Jupyter kernel) still matches
  DATA-DELETE-SQL, because `client` is a genuine DB token and llamaindex's
  nebula graph store legitimately uses `client.execute`.
- **974 `sess.execute(...)` call sites** in agno migrations are missed:
  `sess` is not in the receiver vocabulary. A recall question needing its
  own triage.
- **`@patch` from `unittest.mock` is treated as a web route.**
  `resource_boundary_decorators` contains bare `"patch"`, `"get"`,
  `"delete"`, and `_has_resource_boundary_decorator` matches on the last
  segment, so a mock-patched function containing a sink is scored HIGH.
  Demonstrated live. **Not fixed**: the bare-verb entries exist for real
  custom routers (`org_router.get`, `api_router.post`, `billing_router.get`
  all appear in the corpus), so removing them would drop genuine boundaries.
  No corpus manifestation today, because `@patch` lives in test files, which
  `_collect_files` excludes.

---

## A precision regression this study surfaced incidentally

Re-running `scripts/corpus_scan.py` against the pinned SHAs at `main` @
`25ee4f9` yields **135 findings**, not the 21 in the committed
`corpus-results.json` — including **18 in fastapi and 1 in flask, both
control repos**, where any finding is a precision failure by the corpus's
own definition. `corpus_scan.py` exits `PRECISION FAILURE`.
`check_corpus_triage.py` still passes, because it validates the committed
JSON rather than a fresh scan.

Confirmed pre-existing: reverting `detectors/sinks.py` to `25ee4f9` and
re-scanning gives the identical fastapi 18 / flask 1. Not fixed here —
triaging 135 findings is its own work order. Recorded in `FINDINGS.md`.

## PCCB / authority boundary

Preserved exactly as `docs/COVERAGE.md` states. This study establishes
*reachability* — entry point → call path → consequential sink. It says
nothing about whether an authority check on that path is **bound** to the
runtime principal, action, resource, parameters, tenant and constraints.

That binding is cryptographic and lives inside the proof object; it is not
visible at any call site. Where scan cannot establish the relationship, the
correct state is **UNKNOWN / RUNTIME VERIFICATION REQUIRED**, never
AUTHORISED. No heuristic in this phase pretends otherwise, and none was
added.

One observation reinforcing this: fixing reachability will **surface latent
sink-rule false positives**. Case 111 (`mcp-servers git_show`) is genuinely
agent-reachable, but its sink `repo.commit(revision)` *reads* a revision —
GitPython's `commit()` resolves, it does not create. The GIT-MUTATE match is
wrong. Today reachability hides it. Any transitive-reachability work must
budget for the sink-rule triage it exposes.

---

## Recommendation — the one next capability

> **Fix callee resolution in the repository layer that already exists.
> Do not build a second one.**

The most important thing this study found is that the capability the
evidence calls for is **already implemented and already enabled**.
`actenon_scan/repository/` contains `call_graph.py`, `symbol_index.py`,
`effect_summary.py` and `taint.py`; `engine_augment.analyze_repository`
runs by default on directory scans at `max_depth=32`. It is not missing.
**It is not resolving.**

Measured across the ten repositories holding the 22 confirmed cases:

```
transitive call edges followed      2
transitive call edges unfollowed  3,297      (0.06% resolved)
AGENT_REACHABLE cases caught       0 / 22
```

Per repository: mcp-atlassian 0 followed / 1,279 unfollowed · crewai
0/887 · mcp-python-sdk 2/408 · superagi 0/387 · agno 0/281 · langchain
0/41 · autogen 0/14 · aider, browser-use, mcp-servers 0/0.

So the engineering question is not "should we add transitive reachability"
— that was already answered and shipped. It is "why does the shipped call
graph resolve 2 edges out of 3,299, and what is the cheapest fix that moves
that number?" The corpus gives an exact regression instrument:
`transitive_unfollowed_count` is already recorded on every `ScanResult`.

The evidence says where to aim that fix:

- **Depth is not the problem.** No confirmed case needed more than 3 hops;
  8 of 14 P01 cases are a single hop. The layer allows 32.
- **Aim at same-file, same-class method calls first.** 9 of 14 P01 cases
  are same-file and 12 of 14 are methods — `self._helper(...)` inside a
  class whose sibling method is already a recognised boundary. That is the
  cheapest possible resolution task and it covers the majority.
- **Then one level of cross-module import resolution** (5 of 14), which is
  where `symbol_index` has to do real work.
- **Then the registration gap**, which is upstream of the call graph: if a
  boundary is never discovered, no amount of call-graph quality helps.
  `_is_in_tool_list` accepts `tools=[run_cmd]` but not `tools=[self.run_cmd]`
  nor `tools = [...]; tools=tools`. agno uses **both** missed forms, so
  every agno Toolkit tool is invisible — 4,255 Python files of the corpus,
  and 6 of the 22 confirmed cases. This is small and testable.
- **Also check `emit_heuristic_new_findings=False`.** Even a followed path
  currently emits no new finding unless certainty is high. Whatever the
  resolution fix achieves, this flag decides whether users see it.

**Do not start with** `LLM_OUTPUT_TO_SINK` (1 case, needs taint tracking,
already measured at 10/10 false positives in the previous work order) or
`DYNAMIC_DISPATCH` (2 cases, `getattr`-based registration and polymorphic
overrides — high precision risk). Unresolved cases should surface as
explicit **UNKNOWN**; the `transitive_unfollowed_count` disclosure already
does this honestly and should stay.

A caution the evidence also supplies: fixing reachability **will surface
latent sink-rule false positives**. Case 111 is genuinely agent-reachable
but its sink `repo.commit(revision)` is a GitPython *read* mislabelled
GIT-MUTATE. Budget for the sink-rule triage this exposes.

## Reproducing

```bash
python research/reachability-ground-truth/fetch_corpus.py  <corpus-dir>
python research/reachability-ground-truth/build_inventory.py --corpus-dir <corpus-dir>
python research/reachability-ground-truth/sample.py
python research/reachability-ground-truth/evidence.py --corpus-dir <corpus-dir>
python research/reachability-ground-truth/chains.py   --corpus-dir <corpus-dir>
python research/reachability-ground-truth/labels.py
python research/reachability-ground-truth/analyse.py
python research/reachability-ground-truth/verify_against_full_scan.py <corpus-dir>
```

Third-party checkouts are **not** committed. Everything else —
inventory, sample, evidence, chains, labels, analysis — is.

## Hostile self-audit

| Question | Answer |
|---|---|
| Classified something reachable merely because it contains LLM-related code? | No. Every AGENT_REACHABLE case cites a concrete call path. The two LLM-flavoured ones cite literal source: `eval(assistant_reply)` and `self.apply_edits(edits)` on LLM-parsed edits. |
| Classified internal message passing as agent authority? | No — and this was the specific trap from the previous work order. `semantic-kernel` SequentialAgentActor, autogen's `wsbridge`, agno's A2A transport were all labelled NOT. |
| Inferred reachability from naming? | Caught one. Case 11 (agno `Workspace`) was initially justified from a docstring. Re-audited and corrected: the real evidence is `sync_tools = [getattr(self, name) for name in registered]` at `:287`, and its mechanism changed from CALLBACK_REGISTRATION to DYNAMIC_DISPATCH — which also removed it from the P01 count (15 → 14). |
| Mistook an example/test/build script for production agent code? | 2 of 22 AGENT_REACHABLE are `tier=example` (mcp-python-sdk `examples/mcpserver/memory.py`, a real MCP server). Flagged, not hidden. 35 cases were labelled NOT precisely because they are build tooling. |
| Treated ambiguity as safety? | No. 28 AMBIGUOUS are excluded from the safe count and drive the **low** end of the recall bracket. |
| Selected a sample favourable to the scanner? | No. Seeded, stratified, drawn before any case was inspected, capped so no repo exceeds 11.2%. |
| Altered a fixture after observing a failure? | No. s02 untouched. `p16` is a **new** fixture for a newly demonstrated defect, added through the sanctioned path (fixture-lock updated, baseline precision 15→16). |
| Improved a metric without improving capability? | No. The one metric that moved (precision 15→16) is backed by a defect demonstrated live before and after. |
| Introduced a detector because it passes synthetic tests? | No detector was added in this phase. |
| Could another reviewer reproduce every number? | Yes for corpus, inventory, sample and analysis — all pinned and seeded. The 160 labels are human judgements; each carries its evidence and its verification depth. |
