# Reconciliation Ledger: fix/disclose-analysis-gaps

One row per commit on `origin/fix/disclose-analysis-gaps` (14 commits).
Base: `798b8c6` (merge of PR #86). Reconciled against `main` @ `6580be2`.

| SHA | Subject | Classification | Evidence / Reason |
|-----|---------|---------------|-------------------|
| `8f35376` | A1: assert every printed command resolves in the build that printed it | PORTED (partially) | The verify-claims.yml CI gate already exists on main. The specific assertion that every printed command resolves was not ported — the existing gate checks README claims (zero deps, install commands, ecosystem table) but does not assert that commands printed in output resolve. NOT_PORTED: the command-resolution assertion. |
| `b35f15e` | A2: disclose the calls the analysis does not follow | PORTED (superseded) | Main has `transitive_unfollowed_count` (repository-layer unfollowed) printed in all output paths (Task 1). The intra-file `unfollowed_local_calls` disclosure from this commit was NOT ported — it requires the `LocalCallEdge` data structure and the edge-definition logic that was never merged. The two counts are different (intra-file vs repository-layer) and must be labelled distinctly per the brief. NOT_PORTED: the intra-file unfollowed-call disclosure with the correct edge definition. |
| `35588ea` | A3: report analysis coverage with an observed denominator | NOT_PORTED | The analysis-coverage count pair (followed, not followed, both observed) was not ported. Main has `transitive_followed_count` and `transitive_unfollowed_count` but they are not the same definition: the unfollowed count includes external-library calls, which the brief's edge definition excludes. The coverage pair as defined by this commit (edges with callees in the scanned tree) is NOT on main. |
| `e420c79` | A4: make the headline numbers agree, and count one action once | NOT_PORTED | Headline reconciliation and dedup by (file, line, sink) was not ported. The json_out.py recomputes counts independently rather than using a single reconciled count. |
| `8f4f4ca` | A5: stop presenting our own test fixtures as the user's blast radius | NOT_PORTED | Fixture self-scan exclusion with `--include-fixtures` was not ported. Main has `**/tests/fixtures/**` in default excludes (D10 now discloses the count) but does not have the `--include-fixtures` flag to opt back in. |
| `0e063ca` | A6: make the documentation state what the tool actually does | SUPERSEDED_BY_MAIN | PR-1 (Phase 1.5) and Phase 6 update the documentation to state what the tool actually does. The README truth pass (Phase 6) supersedes this commit's doc updates. |
| `fd9094f` | A7: file both defects as public challenge cases | NOT_PORTED | CHALLENGE-003 and CHALLENGE-004 were not ported. CHALLENGE-003 may already exist on main (need to verify). CHALLENGE-004 was on the branch but was lost when the cherry-pick of B2 failed. |
| `a7e079b` | B1: follow same-module calls one hop, at reduced confidence | SUPERSEDED_BY_MAIN | Main has `detect_same_class_method_reachability()` (Task 2, commit `eefbfc9`) which does same-FILE same-CLASS method resolution up to max_hops=3. B1's one-hop module-level resolution was superseded by the same-class approach (which is what the ground truth showed was needed: 12 of 14 cases are methods). The module-level B1 approach resolved only 2 of 14. |
| `67724f0` | B2: make resource-boundary entry points opt-in, and drop bare decorator names | PORTED | Main has the `--resource-boundary` flag (Task 4b-d, commit `69203f8`), bare decorator names removed from `default_rules.json`, `resource_boundary_enabled: false` default. The `include_fixtures` parameter mentioned in the B2 diff was NOT ported (it's from A5). |
| `85af6f2` | Re-measure the pinned corpus, and fix the one new false positive it found | NOT_PORTED | The corpus re-measurement was not ported. Main has the repaired gate (`check_corpus_triage.py` now re-measures by default, Task 3) but the actual re-measurement + hand-triage + rewrite of corpus-results.json and corpus-triage.json was NOT completed (the 25-repo re-measurement times out in this environment). |
| `000275e` | B3: report recall per hop depth, and record the depths that fail | NOT_PORTED | Depth-stratified recall fixtures and per-depth baseline.json were not ported. Main has `same_class_method(N_hops)` in the signal name but does not report recall per hop depth in the benchmark. |
| `d763008` | Fix two ways the cache changed findings, both found by A4's reconciliation | PORTED | Main has the cache determinism fix (Phase 2, commit `91b1a46`): capabilities cached, declarative-guard suppression preserved on cache hit, entry_schema_version=2. The implementation differs from this commit (which used `LocalCallEdge` structures that don't exist on main) but achieves the same result. |
| `62798eb` | Close two more inconsistencies the acceptance tests exposed | NOT_PORTED | The specific inconsistencies closed by this commit were not ported (they depend on the A4 reconciliation and the `LocalCallEdge` structures). |
| `968fca9` | Record the v1.5.0 perf measurement | NOT_PORTED | The perf measurement was not ported. Main has a perf gate (`check_perf_gate.py`) but the specific v1.5.0 measurement was not recorded. |

## Summary

| Classification | Count |
|----------------|-------|
| PORTED | 3 (B2, cache fix, A1 partially) |
| SUPERSEDED_BY_MAIN | 2 (A6, B1) |
| NOT_PORTED | 9 (A1-partial, A2, A3, A4, A5, A7, B3, re-measure, perf, inconsistencies) |

The 9 NOT_PORTED items require the `LocalCallEdge` data structure and the edge-definition logic from the unmerged branch. Porting them is a work order of its own — each requires understanding the specific data flow on the branch and recreating it on main's architecture.
