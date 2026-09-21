# Branch Report (Phase 7.3)

Classification of all remote branches as of `main` @ `ad2b7c6`.

## Deleted (fully merged, 10 branches)

| Branch | Action |
|--------|--------|
| `feat/repository-consequence-analysis` | Deleted (merged via `54c759c`) |
| `fix/v0.2.2-declarative-guard-crash` | Deleted (merged) |
| `fix/verify-claims-packaging` | Deleted (merged via `798b8c6`) |
| `release/v1.3.1` | Deleted (merged) |
| `research/real-world-reachability-ground-truth` | Deleted (merged via `0277f38`) |
| `work-order-1.10/gate-and-release-fixes` | Deleted (merged) |
| `work-order-1.11/close-out` | Deleted (merged) |
| `work-order-1.5/guard-state-correctness` | Deleted (merged) |
| `work-order-2.1/capability-completeness` | Deleted (merged via `53326b8`) |
| `work-order-2/capability-model` | Deleted (merged via `dbf9007`) |

## Active PR branches (not deletable)

| Branch | PR | Status |
|--------|-----|--------|
| `fix/public-corrections` | PR #90 | Open (docs-only corrections) |
| `fix/correctness-and-integrity` | PR #91 | Open (Phases 2-7) |
| `fix/disclose-analysis-gaps` | PR #89 (closed) | Closed — work being ported via PR #91 |

## Classification of 57 remaining non-merged branches

### SUPERSEDED (content merged via squash-merge or superseded by later work) — 50 branches

These branches have 1-7 commits ahead of main but 52-141 commits behind. Their
content was merged via squash-merge PRs (the individual commits are not on main,
but the changes they introduced are, via later commits). They are safe to delete
after human review.

| Branch | Commits ahead | Last activity |
|--------|--------------|---------------|
| `ci/benchmark-integrity` | 1 | 2026-07-25 |
| `claude/soundness-s02-binding-fix-j80wfc` | 1 | 2026-07-25 |
| `feat/coverage-gaps-w01` | 7 | 2026-07-25 |
| `feat/ecosystem-renderer` | 1 | 2026-07-23 |
| `feat/go-language-support` | 1 | 2026-07-26 |
| `feat/guard-soundness` | 1 | 2026-07-25 |
| `feat/inbound-distribution` | 1 | 2026-07-27 |
| `feat/marketplace-action` | 1 | 2026-07-25 |
| `feat/outreach-artifacts` | 1 | 2026-07-25 |
| `feat/perf-and-corpus` | 2 | 2026-07-25 |
| `feat/soundness-challenge` | 2 | 2026-07-26 |
| `feat/split-recall-and-coverage` | 2 | 2026-07-25 |
| `feat/typescript-support` | 4 | 2026-07-24 |
| `feat/w2-product-ux` | 6 | 2026-07-25 |
| `feat/w2-residual-risks` | 5 | 2026-07-25 |
| `fix/cloudflare-workers-build` | 1 | 2026-07-26 |
| `fix/confidence-label-and-five-refs` | 1 | 2026-07-26 |
| `fix/config-and-guards` | 1 | 2026-07-26 |
| `fix/constant-origin-binding` | 2 | 2026-07-25 |
| `fix/deploy-k8s-fp` | 2 | 2026-07-24 |
| `fix/go-guard-recognition` | 2 | 2026-07-26 |
| `fix/go-sink-parity` | 1 | 2026-07-26 |
| `fix/guard-local-resolution` | 1 | 2026-07-25 |
| `fix/guard-vocabulary-and-config-ux` | 1 | 2026-07-24 |
| `fix/limitations-and-release` | 4 | 2026-07-27 |
| `fix/lychee-green` | 1 | 2026-07-23 |
| `fix/metadata-truth` | 2 | 2026-07-23 |
| `fix/per-function-ts-reachability` | 1 | 2026-07-25 |
| `fix/reachability-precision` | 1 | 2026-07-24 |
| `fix/recognise-validation-guards` | 1 | 2026-07-26 |
| `fix/report-unsupported-files` | 1 | 2026-07-24 |
| `fix/restore-strict-assertions-and-split-recall` | 3 | 2026-07-25 |
| `fix/revert-reachability-label` | 2 | 2026-07-26 |
| `fix/s02-literal-only-binding` | 1 | 2026-07-25 |
| `fix/scan-ecosystem-drift` | 3 | 2026-07-26 |
| `fix/self-scan-clean` | 2 | 2026-07-25 |
| `fix/sql-receiver-constraint` | 2 | 2026-07-25 |
| `fix/sql-sink-detection` | 3 | 2026-07-24 |
| `fix/ts-reachability-precision` | 1 | 2026-07-24 |
| `fix/ts-test-exclusion-and-version` | 2 | 2026-07-24 |
| `fix/unsupported-language-safety` | 1 | 2026-07-26 |
| `fix/v1-audit-fixes` | 4 | 2026-07-26 |
| `fix/v1-tag-audit-and-ecosystem` | 4 | 2026-07-26 |
| `fix/v1-three-persona-audit` | 1 | 2026-07-26 |
| `fix/v1.1.0-regressions` | 1 | 2026-07-26 |
| `fix/v1.1.3-ranking-and-docs` | 1 | 2026-07-26 |
| `integrate/actenon-protocol-v1.0.0` | 2 | 2026-07-21 |
| `north-star/verify-claims` | 1 | 2026-07-24 |
| `north-star/wo-19-changelog-and-version-gate` | 1 | 2026-07-24 |
| `release/v0.6.0` | 1 | 2026-07-25 |
| `release/v1.0.0` | 1 | 2026-07-25 |
| `release/v1.1.0` | 1 | 2026-07-26 |

### STALE (dependabot/automated, can be recreated) — 2 branches

| Branch | Reason |
|--------|--------|
| `dependabot/github_actions/actions/setup-python-7` | Dependabot PR — can be recreated by re-running dependabot |
| `update_worker_name_to_plain-frog-a577` | Automated worker name update — stale |

### CONTAINS-UNIQUE-WORK (not merged, has unique commits) — 5 branches

These branches have work not on main. A human should review before deleting.

| Branch | Commits ahead | Last activity | Notes |
|--------|--------------|---------------|-------|
| `research/industry-consequential-scan` | 3 | 2026-07-25 | Research branch — may have unique analysis |
| `test/benchmark-suite` | 2 | 2026-07-25 | Test infrastructure — may have unique tests |
| `work-order-3/semantic-identity-rebuild` | 4 | 2026-08-11 | Most recent branch — active work |

## Human decision required

The 50 SUPERSEDED branches are safe to delete after review. The 2 STALE branches
can be deleted. The 3 CONTAINS-UNIQUE-WORK branches require human review.
