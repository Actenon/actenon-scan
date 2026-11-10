# BASELINE — frozen versions and reproduced measurements

Everything in this study is measured against the commits below. Nothing was
re-measured on a moving branch.

## Frozen versions

| Component | Commit | Notes |
|---|---|---|
| Actenon Scan (baseline) | `ef8487a` = `origin/main` on 2026-11-10 | v1.6.0 (unreleased RC). Local `main` was one commit behind (`ee971b4`); the local checkout was on an unrelated branch (`fix/review-corrections`, clean, 5 commits ahead of `origin/main`). Neither was used. The clone is shallow (2 commits of history). |
| Actenon Scan (candidate) | `5020b44` on `research/ts-schema-dispatch` | Three commits on top of `ef8487a`: `de06061`, `ad07a60`, `5020b44`. |
| Rapsheet | `0993ea9` on `fix/credibility-gaps` | Clean working tree. Used read-only, in-process; its report writer was never invoked. Another session added `1225575` and `d98ec25` during the study; the evidence was re-checked against both (BEHAVIOUR-EVIDENCE.md). |
| Python | 3.12.13 (uv venv) | CI's supported window is 3.10–3.12. |
| Optional extras | tree-sitter 0.26.1, tree-sitter-typescript 0.23.2, tree-sitter-go 0.25.0 | From `pip install -e ".[dev]"`. |

The baseline was installed from a detached worktree of `ef8487a`, the
candidate from the branch, each into its own virtual environment.

## Reproduced quality measurements (baseline `ef8487a`)

| Check | Command | Result |
|---|---|---|
| Benchmark | `python scripts/benchmark.py --check` | recall (synthetic) **15/16**, recall (corpus-demonstrated) **3/16** (gates CI), precision **16/16**, soundness **6/6**; by depth 0: 11/12 (r05 missed), 1: 2/2, 2: 2/2. Matches `tests/benchmark/baseline.json` exactly. |
| Coverage contract | `python scripts/check_coverage_contract.py` | OK: 16 rows, 3 COVERED, each backed by a triaged corpus TP |
| Corpus triage (committed data) | `python scripts/check_corpus_triage.py --no-remeasure` | OK: 94 findings, 93 TP, 1 recorded unfixed FP, 0 untriaged, 0 control-repo findings |
| Benchmark integrity | `python scripts/check_benchmark_integrity.py` | fixture lock in sync |
| Version coherence | `python scripts/check_version_coherence.py --mode pr` | all assertions passed (pyproject 1.6.0 ≥ PyPI 1.5.0) |
| Full test suite | `python -m pytest tests/` | **1349 passed**, 12 skipped, 4 xfailed, 89 subtests (21 s) |
| Base install, no extras | CI `base-install-test` steps | zero third-party runtime deps; 1219 passed, 119 skipped, 1 xfailed |

## Re-measurement of the TypeScript-bearing corpus

The ten pinned corpus repositories that contain TS/JS files were fetched at
their pinned SHAs (`tests/benchmark/pinned_repos.json`) and scanned with the
frozen baseline. They were never executed.

| Repo | SHA | Files scanned | Findings |
|---|---|---|---|
| modelcontextprotocol/servers | `d31124c` | 60 | 2 |
| github/github-mcp-server | `eb088df` | 131 | 1 |
| microsoft/autogen | `027ecf0` | 576 | 0 |
| microsoft/semantic-kernel | `61a6b0c` | 966 | 0 |
| deepset-ai/haystack | `757b3e2` | 335 | 0 |
| pydantic/pydantic-ai | `ed0f40c` | 406 | 0 |
| openinterpreter/open-interpreter | `a4da0fc` | 748 | 0 |
| All-Hands-AI/OpenHands | `6525030` | 1630 | 0 |
| Aider-AI/aider | `5dc9490` | 122 | 0 |
| FoundationAgents/MetaGPT | `11cdf46` | 662 | 8 |
| **Total** | | **5636** | **11** |

## Discrepancies found and reported, not corrected

1. **Committed corpus data is slightly stale against the frozen code.** A fresh
   scan of `modelcontextprotocol/servers@d31124c` with `ef8487a` produces a
   finding absent from `corpus-triage.json` and `corpus-results.json`:
   `src/everything/tools/gzip-file-as-resource.ts:195 NET-EGRESS` (reached
   transitively from a registered handler). The `--no-remeasure` check passes
   because it reads the committed JSON. The full re-measuring gate (which clones
   all 25 repos) was not run here; this finding would be untriaged in it.
2. **`docs/COVERAGE.md` quotes stale benchmark figures** ("Precision (11/11)",
   "Recall (synthetic) (4/7)", "6/7", "3/7") while the benchmark reports 16/16,
   15/16 and 3/16. The table and the contract check are current; the prose is not.
3. **The repository-analysis summary line counts call edges, not sinks.** On a
   two-file probe the baseline prints "Repository analysis: 1
   transitively-reachable sink caught" while reporting 0 findings and 0
   capabilities; the number printed is `transitive_followed_count`.
4. **Rapsheet's own test run writes into its repository.** `python3
   tests/test_rapsheet.py` rewrote the tracked `docs/test-results.json`. It was
   restored to HEAD immediately; Rapsheet's tree is clean.

## Reproduce

```bash
git -C <scan> worktree add --detach /tmp/scan-baseline ef8487a
uv venv -p 3.12 /tmp/venv-base && VIRTUAL_ENV=/tmp/venv-base uv pip install -e "/tmp/scan-baseline[dev]"
cd /tmp/scan-baseline
/tmp/venv-base/bin/python scripts/benchmark.py --check
/tmp/venv-base/bin/python -m pytest tests/ -q
```

Corpus repos: `git init && git fetch --depth 1 origin <sha> && git checkout FETCH_HEAD`
for each TS-bearing row of `pinned_repos.json`, then
`actenon-scan scan <dir> --format json --fail-on none --no-cache`.
