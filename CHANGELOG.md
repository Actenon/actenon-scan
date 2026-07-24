# Changelog

All notable changes to `actenon-scan` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3] — 2026-07-24

### Fixed (release-blocking)

- **Crash in `_find_declarative_guarded_classes`** on any plain constructor
  call like `Tool(dependencies=[auth])` when `constructor_params` was
  configured. `ast.Name` exposes `.id`, not `.name` — only `ClassDef`/
  `FunctionDef` have `.name`. This zeroed out 7 of 14 repos in the v0.2.2
  validation run: any file containing a plain-Name constructor call with
  a `constructor_params` kwarg (`dependencies`, `permissions`, `auth`,
  `authorizer`, `permission_classes`, etc.) raised `AttributeError` and
  aborted the scan. Fix: use `.id` for `ast.Name`, `.name` for
  `ast.Attribute`.

### Added

- **`verify-claims` Makefile target and CI gate** — machine-enforces every
  claim the README makes about the package itself (zero runtime deps, badge
  sync, install instructions, ecosystem table). For a trust product, one
  falsified claim costs more than ten missing features.

### Changed

- Link-check CI is green (162 internal links across five repos, zero broken).
- Ecosystem table rendered from `ecosystem.yaml` (WO-2).
- License and version metadata aligned with reality (WO-11).

## [0.2.2] — 2026-07-23

### Added

- Precision recovery for guard detection.
- Declarative guard support (constructor-based guards).
- Tiered example corpus.
- Corpus gate for CI.

### Known issues (fixed in 0.2.3)

- Crashes on plain constructor calls with `constructor_params` configured
  (`AttributeError: 'Name' object has no attribute 'name'`).

## [0.2.1] — 2026-07-23

### Fixed

- Precision regression — `qualified_call` matching and safe corpus
  selection to eliminate false positives seen in OpenHands evaluation.

## [0.2.0] — 2026-07-23

### Added

- Agent-native sink rules.
- Framework reachability analysis.
- Validation corpus for regression testing.

## [0.1.8] — 2026-07-23

### Fixed

- crewAI false positives — precise matching + reachability gate.

## [0.1.7] — 2026-07-23

### Added

- Auto-detect venvs by `pyvenv.cfg` marker file.

## [0.1.6] — 2026-07-23

### Changed

- Ignore venv/build dirs; exclude tests from wheel.

## [0.1.5] — 2026-07-23

### Fixed

- `__version__` string to match `pyproject.toml`.
- Drift gate test: accept PyPI version constraint (not just git URL).
- PyPI publish: replace git URL dep with PyPI version constraint.

## [0.1.4] — 2026-07-22

### Fixed

- Root-level file scanning.
- Added agent-tool-boundary docs and tests.

### Changed

- README badge accuracy tightened.
- README expanded: full ecosystem surface, framework adapters, incident
  library, signed receipts, dual placement, badges.

## [0.1.1] — 2026-07-22

### Added

- `--version` flag.

## [0.1.0] — 2026-07-22

### Added

- Initial `actenon-scan` v1 — execution gap scanner.
- Static-analysis engine for consequential action detection.
- Guard pattern matching.
- SARIF output for GitHub Security tab.
- Baseline files for incremental scanning.

---

*Note: versions prior to 0.1.0 were pre-release development. The changelog
was backfilled from git log; entries before 0.1.0 are not reconstructed
because the commit history does not contain structured release notes for
that period.*
