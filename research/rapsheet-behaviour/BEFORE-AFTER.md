# BEFORE-AFTER — baseline `ef8487a` vs candidate `5020b44`

| | Commit | Content |
|---|---|---|
| Baseline | `ef8487a` | `origin/main`, v1.6.0 |
| Candidate step 1 | `de06061` | `tool(` / `execute:` text signals require registration syntax |
| Candidate step 2 | `ad07a60` | Node `fs` sinks matched through import bindings |
| Candidate | `5020b44` | Raw tool-schema dispatch (r07) for TS/JS |

Python 3.12.13, tree-sitter 0.26.1, tree-sitter-typescript 0.23.2, Apple
Silicon, 10 cores. Each version was installed editable into its own venv.

## Benchmark and CI acceptance checks

| Check | Baseline | Candidate |
|---|---|---|
| `scripts/benchmark.py --check`: recall (synthetic) | 15/16 | 15/16 |
| recall (corpus-demonstrated, gates CI) | 3/16 | 3/16 |
| precision | 16/16 | 16/16 |
| soundness | 6/6 | 6/6 |
| recall by depth | 0: 11/12, 1: 2/2, 2: 2/2 | identical |
| `check_coverage_contract.py` | OK (16 rows, 3 COVERED) | OK (unchanged) |
| `check_benchmark_integrity.py` | fixture lock in sync | fixture lock in sync; no benchmark files changed |
| `check_version_coherence.py --mode pr` | pass | pass |
| `check_perf_gate.py` on the pinned fixture (langchain `fa7ce76`, 1,954 files) | serial 24,730 ms; default 2,529 ms; ratio 0.102; findings 1/1 | serial 24,370 ms; default 2,529 ms; ratio 0.104; findings 1/1 |
| Zero runtime dependencies (base install) | OK | OK |

No benchmark fixture, baseline value or coverage row was changed. The synthetic
numbers cannot move, and they did not.

## Tests

| Suite | Baseline | `de06061` | `ad07a60` | `5020b44` |
|---|---|---|---|---|
| `pytest tests/` (all extras) | 1349 passed, 12 skipped, 4 xfailed | 1360 passed | 1383 passed | **1404 passed**, 12 skipped, 4 xfailed |
| Base install, no extras (`--ignore=tests/test_protocol_drift.py`) | 1219 passed, 119 skipped | — | — | 1219 passed, 174 skipped (the 55 new TS tests skip cleanly) |

New tests: 11 + 23 + 21 = 55. Run against the baseline, every positive case
fails and every negative case passes (BREAKTHROUGH.md, "Discrimination").

## Third-party corpus: 10 TS-bearing pinned repos, full scan (Python + TS)

| Repo | Files | Findings before → after | Capabilities before → after |
|---|---|---|---|
| modelcontextprotocol/servers | 60 | 2 → 2 | 2 → 2 |
| github/github-mcp-server | 131 | 1 → 1 | 1 → 1 |
| microsoft/autogen | 576 | 0 → 0 | 0 → 0 |
| microsoft/semantic-kernel | 966 | 0 → 0 | 3 → 3 |
| deepset-ai/haystack | 335 | 0 → 0 | 0 → 0 |
| pydantic/pydantic-ai | 406 | 0 → 0 | 0 → 0 |
| openinterpreter/open-interpreter | 748 | 0 → 0 | 0 → 0 |
| All-Hands-AI/OpenHands | 1630 | 0 → 0 | 0 → 0 |
| Aider-AI/aider | 122 | 0 → 0 | 0 → 0 |
| FoundationAgents/MetaGPT | 662 | 8 → 8 | 8 → 8 |
| **Total** | **5,636** | **11 → 11, identical sets** | **identical sets** |

The 15 Python-only corpus repos were not rescanned: the change touches only
`actenon_scan/detectors/typescript.py`, which runs only on TS/JS files. The
Python findings of the 10 repos above are identical, which is consistent with that.

## Ablation: each mechanism measured separately (`--include` TS/JS globs, `--jobs 1`)

The include globs narrow the scan to a TS/JS-focused subset of 2,032 corpus
files; they do not exclude Go files (github-mcp-server's Go finding is in it).
Variants are the candidate with mechanisms switched off in-process
(`tools/variant_scan.py`). With both mechanisms off and before the hardening
existed, the candidate reproduced the frozen baseline **exactly** on every
target, which is the control for this method.

| Target | Frozen | Hardening only (= `de06061`) | + fs (= `ad07a60`) | + dispatch, no fs | **Candidate** | fs without hardening (rejected) |
|---|---|---|---|---|---|---|
| 10 corpus repos (2,032 files) | 3 | 3 | 3 | 3 | **3** | 3 |
| Repo A @ `202bcaf` | 0 | 0 | 0 | 0 | **0** | 2 (FP) |
| Repo A @ `5033ec5` | 1 | 1 | 1 | 2 | **3** | 3 (2 FP) |
| Repo A @ `b8b460b` | 1 | 1 | 1 | 2 | **3** | 4 (3 unjustified) |
| Repo A @ HEAD | 1 | 1 | 1 | 2 | **3** | 6 (5 unjustified) |
| Repo B @ `b0f6951` / HEAD | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | **0 / 0** | 0 / 0 |
| Repo C @ HEAD (holdout) | 6 | 4 | 4 | 10 | **10** | 6 |
| Repos D, E @ HEAD (holdout) | 0 | 0 | 0 | 0 | **0** | 0 |

## Every finding that changed, adjudicated

| Finding | Mechanism | Adjudication | Basis |
|---|---|---|---|
| Repo A `surface.ts` `save_skill` → `writeFileSync` (`:62` @ `5033ec5`, `:70` @ `b8b460b`/HEAD) | fs + dispatch | **New TP** | Row 25 of BEHAVIOUR-EVIDENCE: 31 recorded calls, effect verified across sessions |
| Repo A `surface.ts` `http_get` → `fetch` (`:74` / `:82`) | dispatch | **New TP** | Row 27: 13 recorded calls |
| Repo C `benchmarks/…/terminal.ts:55` MCP `write` → `fs.writeFileSync(p, a.text)` | dispatch | **New TP** (example tier) | A dispatcher on the tool name handles `tools/call`; model supplies path and text (path confined to `out/`, `work/`) |
| Repo C `benchmarks/…/terminal.ts:61` MCP `shell` → writes the container's returned files to the host | dispatch | **New TP** (example tier) | Model-chosen command; its outputs are written back |
| Repo C `packages/protocol/mcp.ts:126` `case "<prefix>_use"` → `fs.writeFileSync(target, out.output)` | dispatch | **New TP** (production, `-UNBOUND`) | Model-chosen `output_path` inside the operator's data roots |
| The same three in Repo C `benchmarks/results/…/source/` | dispatch | Duplicates (example tier) | A frozen evidence copy of the source |
| Repo C `demos/…/run.ts:138` `execSync("<constant command>")` (and its copy) | hardening | **Removed baseline FP** | Constant command in a demo function; reachable only because the function calls a lookup method named `tool`, `registry.tool(id)` |
| Repo A harness file H1, two evidence writes | fs without hardening | Unjustified, **not in candidate** | Harness `main()` driving the server as an MCP client: NOT_AGENT_REACHABLE |
| Repo A benchmark hosts H2, H3, H4, one trace-log write each | fs without hardening | Unjustified rationale, **not in candidate** | Flagged because an `execute:` config key sat within 3 lines. The writes may be reachable by paths Scan does not model (G9, G10); not reported by the baseline either |

**Net, candidate vs baseline:** +5 distinct true positives (2 from recorded
executions, 3 in holdout code), +3 duplicate true positives in an evidence copy,
−1 false positive (plus its copy). **No new false positive, no lost true
positive, no lost finding of any kind on third-party code.**

## Still missed after the change

| Case | Why |
|---|---|
| Repo B edit and run tools (rows 28–29, recorded) | Dispatch into another module (G4) |
| Repo A `run_program` → a sandbox object's `run` (row 26, recorded) | Method on a returned object (G7) |
| Repo A capability-registry dispatch (row 30) | Dynamic dispatch (G6) |
| Reference MCP filesystem server `write_file` → `lib.ts` | `.js` → `.ts` specifier resolution (G5) |
| Module-level `tools/call` loops, callback-assigned sinks | G9, G10 (UNRESOLVED) |

## Performance

| Measurement | Baseline | Candidate |
|---|---|---|
| OpenHands TS/JS, 989 files, `--jobs 1`, three runs | 6.89 / 7.33 / 6.48 s (median 6.89) | 6.73 / 7.06 / 6.88 s (median 6.88) |
| Perf gate, pinned langchain fixture (Python only) | default 2,529 ms | default 2,529 ms |

The schema-dispatch walk runs once per TS file and only when a sink pattern
already matched. No measurable cost.

## Commands

```bash
# Benchmark, tests, CI checks (run in each checkout with its own venv)
python scripts/benchmark.py --check
python -m pytest tests/ -q
python scripts/check_coverage_contract.py
python scripts/check_benchmark_integrity.py
python scripts/check_version_coherence.py --mode pr
python scripts/check_perf_gate.py --fixture <langchain@fa7ce76>

# Corpus: each TS-bearing row of tests/benchmark/pinned_repos.json at its SHA
actenon-scan scan <repo> --format json --output <out>.json --fail-on none --no-cache

# Ablation (TS/JS only); mode is base | g1 | g2 | both
python research/rapsheet-behaviour/tools/variant_scan.py <mode> <out>.json <repo>
python research/rapsheet-behaviour/tools/compare_ablation.py <dir-of-outputs>
```
