# Changelog

All notable changes to `actenon-scan` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-07-24

### Fixed — the adoption blocker

- **Guard vocabulary expanded from ~50 to 145 patterns.** The original
  ~12 generic guard names (`authorize`, `check_permission`, etc.) caused
  100% false positives on security-mature teams using their own naming
  conventions (`assert_can`, `policy_gate`, `audit_and_allow`, `can_user`,
  `enforce_policy`, `guard_action`). This was the single highest-churn
  defect: the most security-mature teams — the best prospects — got the
  worst experience and uninstalled. The expanded vocabulary covers:
  - Assertion-style: `assert_can`, `assert_allowed`, `assert_authorized`, etc.
  - Policy gates: `policy_gate`, `guard_action`, `audit_and_allow`, etc.
  - MCP-native approval: `ctx.elicit`, `elicitation`, `request_elicitation`
  - LangChain.js: `HumanApprovalCallbackHandler`, `HumanInTheLoopMiddleware`
  - Vercel AI SDK: `requireConfirmation`, `confirm_action`
  - Framework-specific: `Depends`, `current_user`, `require_admin`, etc.

- **Config errors never crash.** Three plausible config attempts that
  previously crashed with raw tracebacks now produce clean messages with
  the accepted schema:
  - `{"guards": {"patterns": [...]}}` — now parsed correctly (was crash)
  - `{"guard_patterns": [...]}` — works (was already correct)
  - TOML files — rejected with "use JSON or YAML" (was crash)
  - Invalid JSON — prints schema hint, not traceback

### Changed

- The remediation hint in findings now says "register it with
  `scan --config`" with the accepted schema available on any config error.
- `ConfigError` is a new exception class that carries the schema example.
  The CLI catches it and exits with code 2 (not 0 or 1).

## [0.3.1] — 2026-07-24

### Fixed

- **TypeScript test-file exclusion** — `.test.ts`, `.spec.ts`, `.test.js`,
  `.spec.js`, and files in `__tests__/` / `__mocks__/` directories are now
  excluded from scanning, matching the Python analyser's `test_*.py` /
  `*_test.py` exclusion. The three TypeScript false positives in the
  official MCP servers repo were all in `structured-content.test.ts`
  (beforeEach/afterEach cleanup using `fs.writeFile` and `fs.rm`).
  With this fix, the triaged rate on the MCP servers repo goes from
  2 TP / 3 FP to **2 TP / 0 FP**.
- **`__version__` hardcoded to 0.2.3** — `actenon-scan --version` reported
  0.2.3 while `pip show` and `importlib.metadata` said 0.3.0. Now derived
  from `importlib.metadata.version("actenon-scan")`. Added to the
  `verify-claims` gate so this class of drift cannot recur.

## [0.3.0] — 2026-07-24

### Added

- **TypeScript and JavaScript analysis** behind the `[typescript]` extra.
  Install with `pip install "actenon-scan[typescript]"`. Uses tree-sitter
  with prebuilt wheels (~1 MB, no compiler, no Node). The base install
  remains zero-runtime-dependency. Covers .ts, .tsx, .mts, .cts, .js,
  .jsx, .mjs, .cjs. Same rule IDs and categories as Python — output is
  language-agnostic. Sink detection, reachability (MCP/LangChain.js),
  and guard detection ported from Python.
- **Unsupported-file reporting** (safety fix). Scanning a directory of
  .ts files without the extra now reports "N file(s) NOT scanned —
  install with pip install actenon-scan[typescript]" instead of the
  dangerous "No findings. Scanned 0 file(s)." New `--fail-on-unsupported`
  flag (default off). JSON output gains `scanned`, `unsupported`, and
  `errored` top-level keys.
- **Base-install CI job** that verifies the zero-runtime-dependency
  guarantee on every PR.

### Fixed

- **DEPLOY-K8S false positive** — was matching `client.X.create` on ANY
  object named `client`. Now constrained to genuine Kubernetes surfaces
  (kubernetes client API methods, kubectl CLI). Real-world false positives
  in crewai and langchain fixed.
- **DATABASE-ORM-MUTATE false positive** — was matching generic `session.create`,
  `db.create`. Now uses qualified_call with specific ORM method signatures.
- **COMMUNICATION-SEND false positive** — was matching `message.create` with
  generic `create` func pattern. Now uses specific communication SDK methods.
- **DATA-DELETE-SQL risk-model inversion** — was matching the SQL literal
  text and missing variable SQL (the strictly more dangerous case). Now
  matches the SINK (.execute/.executemany/.executescript) regardless of
  whether the SQL is literal or variable. Literal SELECT-only not reported.
- **s3.delete_objects** and other boto3 destructive calls now detected.
  Added: delete_objects, delete_db_instance, delete_table, delete_stack,
  delete_topic, delete_queue, and more.

### Changed

- Rule audit completed: every attr_call rule checked for the same
  loose-pattern defect as DEPLOY-K8S. Results documented in
  `tests/test_rule_audit.py`.

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
