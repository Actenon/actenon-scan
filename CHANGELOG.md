# Changelog

All notable changes to `actenon-scan` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Deprecation policy

- **Public API** = anything in `actenon_scan.api` (re-exported in
  `actenon_scan.__init__`). Includes `scan_path`, `scan_path_parallel`,
  `Finding`, `ScanResult`, `Ruleset`, `SinkRule`, `load_rules`,
  `load_default_rules`, `FileCache`, `get_default_cache_dir`.
- **CLI surface** = subcommand names, positional args, `--flags` documented
  in `actenon-scan --help` and README.
- **Output schemas** = JSON output structure, SARIF rule/result field names,
  Finding dataclass field names.
- **Breaking changes** to any of the above require a major version bump
  (e.g. v1.x → v2.0) and a 2-release deprecation cycle: the old API
  stays working with a `DeprecationWarning` for one minor release, then
  is removed in the next minor release, then the major version bumps.
- **Bug fixes** that change finding output (e.g. fixing a false positive
  that was previously reported) are NOT breaking changes — they are
  noted in the release notes but don't require a deprecation cycle.
- **New rules** added to `default_rules.json` may produce new findings on
  existing repos; this is NOT a breaking change (the ruleset version in
  `default_rules.json` is bumped instead).

## [Unreleased]

_No changes yet._

## [1.1.3] — 2026-07-27

### Ranking + documentation fixes

### ITEM 1 (BLOCKER): "Most exposed" now prefers findings with model-controlled inputs

The ranking previously used severity + confidence + destructiveness. A
finding with no model-controlled input on the path (e.g., a constant-path
delete) could be selected as the headline over a finding the model can
actually influence.

- `_most_exposed_rank` now includes "has model-controlled inputs" as the
  FIRST sort criterion (before severity). Findings WITH identified inputs
  rank higher than those WITHOUT.
- Uses the same call-text parse as the pretty reporter's spotlight
  (`_extract_params`), not a separate analysis — the ranking agrees with
  what the user sees.
- On anthropic-sdk-go: the headline changed from `skills.go:65 RemoveAll()`
  (no model-controlled inputs) to `skills.go:110 RemoveAll()` (has `dest`
  as a model-controlled input) — a sound true positive where the model
  influences the deletion path via the `skillID` parameter.

### ITEM 2: Constant-path deletes — reported, not suppressed (decision documented)

`os.RemoveAll(filepath.Join(e.Workdir, "skills"))` has no model-controlled
component on the analysed path, but the tool cannot verify that no other
call site reaches the same function with a model-controlled `Workdir`.

**Decision: REPORT.** Under-reporting is the worse error for this tool.
The ranking change (ITEM 1) demotes it below findings with identified
model-controlled inputs. Documented in COVERAGE.md.

### ITEM 3: Go guard vocabulary boundary documented

COVERAGE.md now lists:
- Which guard names are recognised (same vocabulary as Python, with
  camelCase matching)
- That method-call form is supported (`s.auth.Authorize(path)`)
- That `Allow` is deliberately excluded (rate.Limiter.Allow is not an
  authorization check)
- That custom guard names can be registered via `--guard` or
  `guard_patterns` in the config file — works for Go exactly as for Python

### ITEM 4: MCP SDK figures corrected with tier split

Both Go SDK repos are 1 production + 3 example, not 4 undifferentiated:

| Repo | Production | Example | Total |
|------|-----------|---------|-------|
| modelcontextprotocol/go-sdk | 1 (FP: hardcoded "myserver") | 3 | 4 |
| mark3labs/mcp-go | 1 (borderline: config-controlled) | 3 | 4 |

- go-sdk production finding is a **false positive** — `exec.Command("myserver")`
  with a hardcoded string. Recorded in FINDINGS.md.
- mcp-go production finding is **borderline** — `exec.CommandContext(ctx,
  c.command, c.args...)` in the stdio transport, config-controlled by design.
  Reported honestly; the scanner's conservative stance is documented.

### ITEM 5: Re-baselined

| Repo | v1.1.2 | v1.1.3 | Change |
|---|---|---|---|
| anthropic-sdk-go | 6 | 6 | no change (ranking only) |
| go-sdk | 4 | 4 (1 prod, 3 example) | tier split |
| mcp-go | 4 | 4 (1 prod, 3 example) | tier split |
| github-mcp-server | 2 | 2 | no change |

No finding counts changed. The ranking change (ITEM 1) affects which
finding is displayed as "Most exposed" but not the total count.

## [1.1.2] — 2026-07-27

### Go support upgrade — guard recognition, temp-file suppression, explain IR

This release closes three correctness gaps in Go support that were
identified by testing v1.1.1 against real Go agent codebases.

### ITEM 1 (BLOCKER): Go detector now recognises guards

The Go detector previously had zero guard analysis — every Go finding
printed "Guard evidence: none found on the analysed path" without any
search being performed. This was false for every Go finding the tool
had ever emitted.

- Reuses the guard vocabulary from `guards.py` (no parallel Go list).
  Handles Go's camelCase convention: `checkPermission` matches
  `check_permission`, `verifyToken` matches `verify_token`, etc.
- Matches Python semantics: dominance (guard on every path to sink),
  binding (shared identifiers), result use (error/bool checked).
- Defeated guards: `_ = authorize(path)` (error discarded) → WEAK.
  `if false { guard() }` → does not dominate. Nested func literal →
  does not dominate.
- Assert-style guards (`authorize`, `verify`, etc.) don't require
  binding — they conventionally panic regardless.
- False negatives are worse than false positives: if unsure, does NOT
  suppress.
- 8 soundness tests in `tests/test_go_guard_soundness.py`.

### ITEM 2: Temp-file false positives suppressed

Three of eight findings on anthropic-sdk-go were false positives from
deferred cleanup of self-created temp files. The variable passed to
`os.Remove` was assigned from `os.CreateTemp` or `.Name()` on its
result — not model-controlled.

- Suppresses `os.Remove`/`os.RemoveAll` when the argument is assigned
  from `os.CreateTemp`/`os.MkdirTemp`/`.Name()` within the same function.
- Anchored to the assignment source, NOT to the `defer` keyword or the
  string "tmp". A model-supplied path deleted in a defer is still a finding.
- `os.RemoveAll(filepath.Join(e.Workdir, "skills"))` (hardcoded subdirectory)
  is NOT suppressed — it's a known limitation, not a false positive.

### ITEM 3: explain IR works for Go

`explain` previously showed `<module-level>` (Python terminology) for
Go findings and `(none identified)` for model-controlled inputs,
contradicting the scan summary.

- `build_brief` now detects `.go` files and uses tree-sitter to extract
  the enclosing function name, caller-controlled parameters, and guard
  evidence.
- Go findings now show the real function name (e.g., `NewBashSession`)
  instead of `<module-level>`.
- The scan/explain contradiction on model-controlled inputs is resolved.

### ITEM 4: Re-baselined numbers

| Repo | Before (v1.1.1) | After (v1.1.2) | Change |
|---|---|---|---|
| anthropic-sdk-go | 8 | 6 | -2 (temp-file FPs suppressed) |
| modelcontextprotocol/go-sdk | 4 | 4 | no change (no guards found) |
| mark3labs/mcp-go | 4 | 4 | no change (no guards found) |
| github/github-mcp-server | 2 | 2 | no change (no guards found) |

No repo had a count increase from guard recognition (none of these
codebases use recognised guard names in agent-reachable functions).
The count decrease on anthropic-sdk-go is entirely from temp-file
suppression (ITEM 2).

The "Most exposed" finding on anthropic-sdk-go is now `bash.go:94
EXEC-SHELL-GO` — `exec.Command("/bin/bash", ...)` — a true positive
by design and the honest illustration of what the tool sees.

### Added — COVERAGE.md Go guard recognition section

Documents what Go guard recognition covers (assert-style, checked-error,
defeated-guard, dead-branch, nested-func-literal) and does not cover
(cross-file resolution, middleware-style, interface method). States the
false-negative boundary: if unsure, does NOT suppress.

### Tests

- `tests/test_go_guard_soundness.py`: 8 tests covering basic harness,
  defeated guards, dead branches, nested func literals, checked errors,
  unbound guards, temp-file suppression, and model-controlled-delete
  not-suppressed.
- Full suite: 356 passed, 10 skipped, 0 failed (was 348).

## [1.1.1] — 2026-07-27

### Regression fix release

v1.1.0 changed the CLI `--fail-on` default from `medium` to `none`,
which meant a scan that found 8 unguarded consequential actions exited
0 — passing CI silently. This is the false-assurance failure the tool
exists to close. v1.1.1 reverts the CLI default to `medium`.

### Fixed — CLI `--fail-on` default reverted to `medium`

- v1.1.0 changed the default to `none` to match `action.yml`. That was
  the wrong direction: the CLI has no other machine-readable signal, so
  its exit code IS the status. A scanner that finds findings and exits 0
  passes CI silently.
- The CLI default is now `medium` again (matching v1.0.0 and the
  near-universal SAST/linter convention: semgrep, bandit, eslint,
  shellcheck all fail on findings by default).
- `action.yml` stays at `none` — the Action has a sticky PR comment +
  SARIF upload, so findings stay visible even when the check is green.
  The two intentionally differ. Added comments in both `cli.py` and
  `action.yml` explaining why, so this doesn't get "fixed" back into
  alignment.
- README now documents the full exit code contract including the
  deliberate CLI/Action difference.

### Fixed — docs/COVERAGE.md stale Go claims

Every scan prints "See docs/COVERAGE.md for supported architectures and
analysis limits." v1.1.0 added Go support, but COVERAGE.md still said
"The scanner supports Python and TypeScript but not Go." A successful
Go scan directed the user to a document telling them Go was unsupported.

- Line 270: "Python and TypeScript/JavaScript" → "Python,
  TypeScript/JavaScript, and Go".
- Line 546: benchmark table `github-mcp-server | 0 (Go unsupported)` →
  `2 (Go)` — re-scanned the pinned SHA (eb088dfe) with 1.1.0, got 2
  findings across 131 Go files.
- Lines 565-570: "Limitation: Go-based MCP servers" section rewritten
  to "Go-based MCP servers (now supported)" with the actual findings
  listed.
- Line 589: coverage verdicts table "Go-based MCP mutation tools | NOT
  SUPPORTED" → "COVERED — NET-EGRESS-GO + FILE-WRITE-GO".
- docs/CORPUS_RESULTS.md: "Python and TypeScript" → "Python, TypeScript,
  and Go" (two locations).

### Fixed — Go findings no longer show Python decorator syntax

`report/pretty.py` `_decorator_or_function` previously guessed
`@mcp.tool() or @tool` based on the file PATH containing "tool" or
"/mcp" — with no language check. A Go finding in `tools/agenttoolset/
fs.go` rendered as "Reachable by: @mcp.tool() or @tool", displaying
Python decorator syntax while reporting on Go.

- `GoFinding` dataclass now carries a `reachability_reason` field
  populated by the detector (`agent_framework_import`,
  `tool_registration`, or both).
- `Finding` dataclass now carries the same field, threaded through from
  the Go detector via the engine.
- `_decorator_or_function` now renders the real reachability reason for
  Go findings ("tool registration (AddTool/RegisterTool)" or "agent
  framework import"). The path-based guess is now ONLY applied to `.py`
  files. TypeScript and other languages get a generic "agent entry
  point" rather than Python syntax.

### Added — regression test pinning the `--fail-on` default

- `test_fail_on_default_is_medium` — asserts the CLI source has
  `default="medium"`.
- `test_scan_with_findings_exits_nonzero_by_default` — end-to-end: a
  scan with medium-or-above findings exits 1 by default.
- `test_scan_with_findings_exits_zero_with_fail_on_none` — explicit
  `--fail-on none` still exits 0 (for triaged repos with baselines).

## [1.1.0] — 2026-07-27

### First-touch readiness release

This release captures three rounds of audit fixes (code-level,
end-to-end user-story, and three-persona first-touch) that close the
gap between "works on the happy path" and "works flawlessly end-to-end
when external users try it." 44 fixes total, 61 new regression tests,
347 tests passing (was 286).

### Added — public Python API

- New `actenon_scan.api` module re-exports the stable public surface:
  `scan_path`, `scan_path_parallel`, `auto_jobs`, `ScanResult`, `Finding`,
  `Ruleset`, `SinkRule`, `load_rules`, `load_default_rules`, `ConfigError`,
  `FileCache`, `get_default_cache_dir`. `from actenon_scan import scan_path`
  now works for integrators embedding actenon-scan as a library.
- `py.typed` marker added — integrators using mypy/pyright get type
  information from the public API. New `Typing :: Typed` classifier.
- `actenon_scan/__init__.py` now re-exports the most commonly used
  symbols (`scan_path`, `Finding`, `ScanResult`, `Ruleset`, `SinkRule`,
  `load_rules`, `load_default_rules`) with an explicit `__all__`.

### Added — cache relocation

- `ACTENON_SCAN_CACHE_DIR` env var overrides the cache directory.
- `--cache-dir` flag on `actenon-scan scan` overrides per-invocation.
- Default cache location moved from `.actenon-scan-cache/` inside the
  scanned directory (which polluted the workspace) to
  `${XDG_CACHE_HOME:-~/.cache}/actenon-scan/<target-hash>/` — keeps
  per-target caches separate without writing into the workspace.
  **Migration:** if you have a `.actenon-scan-cache/` directory in your
  repo, you can delete it; the cache will be recreated at the new
  location on the next scan. Add `ACTENON_SCAN_CACHE_DIR` to your CI
  env if you want the cache on a persistent volume.

### Added — community files

- `.github/ISSUE_TEMPLATE/{bug_report,feature_request,security_report}.yml`
- `.github/PULL_REQUEST_TEMPLATE.md` with the fixture-change-justification
  prompt built in.
- `.github/CODEOWNERS` — maintainer team owns security-critical paths.
- `.github/dependabot.yml` — weekly bumps for dev deps and GitHub Actions.
- `.github/FUNDING.yml` — placeholder for future sponsorship.

### Added — `--all` flag for explain / brief

- `actenon-scan explain --all --path .` explains every finding in one
  invocation. Previously a user with 50 findings ran 50 commands.
- `actenon-scan brief --all --path . --format markdown --output briefs.md`
  produces a single document with all findings.

### Added — `baseline` subcommand

- `actenon-scan baseline <path> --output baseline.json` generates a
  baseline from the current scan. Previously users had to hand-craft
  the JSON. `_cmd_adopt` referenced this subcommand but it didn't exist.

### Added — config-based custom sinks and reachability signals

- The config file's `sinks` and `reachability` keys are now documented
  in README. Users can add support for unrecognised agent frameworks
  (Haystack `@component`, DSPy `dspy.Module`, ControlFlow `@task`) via
  config alone — no code changes, no fork required. The loader already
  supported this; only the docs were missing.

### Added — SARIF rule metadata

- Each SARIF rule now has `helpUri` (per-rule link to
  `docs/COVERAGE.md#<rule-id-lowercased>`).
- Each SARIF rule now has `properties.tags` (`security`, `ai-agent`,
  `cwe-<n>`, `owasp-<id>`).
- Each SARIF rule now includes `properties.cwe` and `properties.owasp`
  from the SinkRule fields. GitHub Security tab "Learn more" links and
  CWE/OWASP filtering now work.

### Added — pre-commit hook for TypeScript and Go

- `.pre-commit-hooks.yaml` now declares separate `actenon-scan-typescript`
  and `actenon-scan-go` hooks with `additional_dependencies` so they
  actually install `tree-sitter-typescript` / `tree-sitter-go` in
  pre-commit's isolated venv. Previously the hooks ran but silently did
  nothing (every file was "unsupported").

### Added — `[project.urls]` in pyproject.toml

- PyPI sidebar now shows Homepage, Documentation, Source, Issues,
  Changelog, Security links.

### Added — Cloudflare Worker

- `wrangler.toml` + `workers/docs.js` — minimal Worker that 301-redirects
  to the GitHub repo. Makes the Cloudflare Workers and Pages GitHub App
  build succeed on every push (was failing on every commit since the
  app was installed).

### Changed — `--fail-on` default is now `none`

- Previously `actenon-scan scan .` defaulted to `--fail-on medium`,
  which meant a new user with 5 medium findings saw exit 1 and assumed
  the tool crashed. The CLI now defaults to `--fail-on none` (matching
  `action.yml`'s default). CI users who want fail-on should pass
  `--fail-on medium` or `--fail-on high` explicitly.

### Changed — `init` merges instead of overwrites

- `actenon-scan init` now reads the existing `.actenon-scan.json` and
  MERGES suggested `guard_patterns` into it (deduped). The `exclude`,
  `sinks`, and `reachability` keys are preserved. Previously `init`
  silently overwrote the config, destroying these keys. Use `--force`
  to restore the old overwrite behaviour.

### Changed — `fix` indentation for nested-block sinks

- `actenon-scan fix` now inserts the guard at the SINK's own indentation
  when the sink is inside a `with`/`for`/`try`/`if` block, not at the
  enclosing function's body indent. The previous behaviour placed guard
  comments in the middle of the nested block, and when uncommented the
  guard would run BEFORE the block was entered (e.g. before
  `browser = p.chromium.launch()`), so the guard could not actually
  guard the sink.

### Changed — `fix --mode actenon` uses the real actenon-kernel API

- Previously the actenon mode inserted `from actenon import verify_proof`
  — but no `actenon` package exists on PyPI. Applying `fix --mode actenon
  --apply` broke user code with `ModuleNotFoundError`. Now uses
  `from actenon_kernel import verify_pccb` (the real package + function).

### Changed — `fix --mode guard` and `--mode approval` emit calls

- Previously both modes emitted pure TODO comments. Now they emit actual
  calls (commented out): `# authorize(action="...")` for guard,
  `# approved = await request_approval(action="...")` for approval.
  The user uncomments when wiring up the function; the structure is
  already in place.

### Changed — `fix` refuses non-Python files safely

- `actenon-scan fix app.ts:7` previously inserted Python syntax (`#`
  comments, `raise PermissionError`) into the `.ts` file. Now refuses
  with a helpful note pointing to the issue tracker.

### Changed — `--changed-only` covers TypeScript and Go files

- Previously `--changed-only` only picked up `.py` files. The GitHub
  Action uses `--changed-only`, so changed `.ts`/`.go` files in a PR
  were silently skipped — contradicting the README's "Parses Python,
  TypeScript, and Go" promise. Now `.ts`/`.tsx`/`.js`/`.jsx`/`.mjs`/
  `.cjs`/`.go` files are all included.

### Changed — `--changed-only` no longer silently degrades to a full scan

- Previously, an empty git diff (the common CI case on a clean working
  tree) caused `--changed-only` to silently run a full scan. Now it
  prints a warning and exits 0 with an empty result.

### Changed — action.yml sticky PR comment actually posts

- The sticky-PR-comment step's env block now sets `FINDINGS_COUNT`
  (was missing — the heredoc always exited at "No findings — skipping").
- `PR_NUMBER` is now passed explicitly from `github.event.pull_request.number`
  (was parsed from `GITHUB_REF` as `"merge"` instead of the actual number).

### Changed — action.yml installs `[typescript,go]` extras

- Previously the action installed only `[typescript]`, so Go files in PRs
  were silently treated as unsupported. Now installs `[typescript,go]`,
  matching the README's "Parses Python, TypeScript, and Go" headline.

### Changed — cache no longer bypasses baseline suppression

- Previously, when the content-hash cache hit, findings were appended
  to the result WITHOUT applying baseline or inline-suppression checks.
  A user who ran `scan .`, then `baseline .`, then `scan . --baseline
  baseline.json` would see all findings still. The cache-hit path now
  re-applies baseline + suppression from the CURRENT sets on every hit.

### Changed — `__version__` reads pyproject.toml as fallback

- When running from a source checkout without install, `__version__`
  previously returned `"0.0.0+unknown"` despite the comment claiming
  it read `pyproject.toml`. Now it actually reads `pyproject.toml`.
  `--version` and the SARIF `tool.driver.version` field no longer lie
  when running from source.

### Changed — `_parse_location` rejects negative line numbers

- `actenon-scan explain app.py:-1` previously ran a full scan and
  returned "No finding at app.py:-1." — wasteful and misleading. Now
  exits 2 with a clear error.

### Changed — parallel scan honours cache and `on_finding`

- `scan_path_parallel` now accepts `cache` and `on_finding` parameters.
  Previously the CLI took the parallel branch and silently dropped both.
  The cache is now passed through to workers (each gets its own
  `FileCache` pointing at the same directory); `on_finding` fires in
  the parent after the merge.

### Changed — README suppression example syntax

- The README documented `# actenon-scan: suppress RULE-ID` but the code
  only matched `# actenon-scan: ignore[RULE-ID]`. Both syntaxes are now
  accepted.

### Changed — README pre-commit `rev` updated to `v1.1.0`

- Was pinned to `v0.8.0` — users copying the snippet pinned to a
  version that didn't ship the v1.0 features advertised in the same
  README.

### Changed — pyproject.toml classifier to `Production/Stable`

- Was `Development Status :: 4 - Beta` on a 1.0.0 package.

### Changed — README "8 categories" → "16 categories"

- The "What's in this repo" table said "Default rules (8 categories)"
  but the actual `default_rules.json` has 16. Now correct. Added
  `BROWSER` and `PROVIDER` rows to the consequence table.

### Fixed — BOM-prefixed Python files

- A file starting with a UTF-8 BOM (Windows convention) was
  misclassified as `SyntaxError` and silently missed. The engine now
  reads with `encoding="utf-8-sig"` which strips the BOM.

### Fixed — Windows backslash path matching

- `_glob_match` now normalizes `rel_path.replace("\\", "/")` so glob
  patterns like `tests/fixtures/**` match `tests\fixtures\x.py` on
  Windows. Previously Windows users scanning repos with test fixtures
  got all the false positives the excludes were designed to suppress.

### Fixed — SARIF tool driver version

- Was hardcoded to `"0.1.0"`. Now uses `__version__`.

### Fixed — README broken fragment links

- `#github-action`, `#output-formats`, `#what-scan-does-not-do` all
  pointed at non-existent anchors. Now point at the real section IDs.


## [1.0.0] — 2026-07-25

### Marketplace release

- GitHub Action marketplace-ready: sticky PR comments, SARIF upload, changed-files scope, pinned version, fail-on: none default.
- Blast-radius summary as the default CLI output.
- `actenon-scan explain <file:line>` — execution-path analysis.
- `actenon-scan fix <file:line>` — neutral remediation diffs (guard → approval → Actenon).
- `actenon-scan brief <file:line> --format markdown` — one-page outreach report.
- Self-contained HTML and Markdown reports.
- Content-hash cache for fast re-runs.
- Receiver-origin resolution for chained calls (psycopg2.connect().cursor().execute()).
- PyGithub repository-mutation coverage (REPOSITORY-MUTATION, GITHUB-REST-MUTATION).
- External email coverage (SMTP_SSL, SES send_raw_email, SendGrid, Resend, Postmark).
- `.actenon-scan.json` auto-detection for repos with test fixtures.
- Self-scan reports clean on own repository (verify-claims enforced).
- CORPUS_STUDY.md: 25 repos, 23K files, 30 hand-triaged findings, 51/63 initial FP rate documented.
- 276 tests, 14 CI gates, machine-verified README claims.

## [0.8.0] — 2026-07-25

### What changed for you

- **Scans are roughly twice as fast** on machines with 8 or more cores, and
  ~30% faster everywhere else. A 1,954-file repository (langchain) goes from
  2.8s to 0.96s on a 10-core machine, and from ~7.4s to ~5.7s on a 4-core CI
  runner.
- **Three classes of false positive are gone.** If scan previously flagged
  documentation scripts, cookbook setup code, or agent-to-agent messaging, it
  no longer does.
- **A guard that returns a decision you ignore is now caught.** Previously
  some of these were reported clean.
- **`--changed-only` is fast enough for a pre-commit hook**: ~150ms for a
  1-3 file diff, down from ~720ms.

### Fixed — false positives

Measured across 25 pinned real repositories (21,308 Python files, 2,168
TypeScript). As shipped, v0.7.0 produced 63 findings on that corpus, 12 of
them in non-agent control libraries. It now produces 30, all hand-triaged
true positives, and **zero** in the controls.

- **Documentation and tooling scripts.** `playwright` and `selenium` were
  treated as agent frameworks, so every screenshot script that imported them
  and started a dev server was flagged. Driving a browser is not agent
  reachability. (12 findings, all in FastAPI.)
- **Module-level setup code.** A sink at module scope in a file that imports
  an agent framework was reported. Module-level code runs at import time and
  cannot be selected by an LLM, so it is not agent-reachable — the same
  reasoning already applied to `if __name__ == "__main__":` blocks. This
  signal produced 19 findings on the corpus and **none** of them were real.
  Recoverable with `reachability.module_level_reachability`. (19 findings.)
- **Agent-to-agent messaging.** `send_message` on an A2A client or an internal
  event bus is inter-agent transport, not a consequential side effect.
  Genuine Slack and email sends still fire. (2 findings.)

### Fixed — false negatives

- **Guard style is resolved by definition, not by name.** A guard whose result
  you discard is safe only if it raises. The same function name is written
  both ways in real code — `check_permission` that returns a bool and
  `check_permission` that raises — so classifying by name reported the
  returning-and-ignored form as clean. Scan now reads the guard's body. When
  the guard is imported and cannot be read, it resolves to WEAK rather than
  being assumed safe.

### Performance

- Roughly 2x faster on the serial path: a detector pass was running on every
  file and having its result discarded on two thirds of them, and an identical
  parent-map was being built twice per file.
- `--jobs N` for parallel scanning, defaulting to automatic. **It parallelises
  only where that was measured to help** — 8+ cores and 250+ files — because
  parallel-by-default was ~10% *slower* on 2-4 core CI runners. `--jobs N`
  always overrides. Findings are identical in either mode.
- `--changed-only` no longer walks the whole repository before filtering to
  the diff.

### Added — verification

- A 25-repository precision corpus pinned by commit SHA, with every finding
  hand-triaged and a CI gate that fails on any false positive, any untriaged
  finding, or any finding in a control library.
- `docs/COVERAGE.md` is now a contract CI enforces: an architecture may be
  marked COVERED only when a hand-triaged true positive exists on real code.
  A synthetic fixture is not sufficient.
- A perf gate that fails if the default scan mode is ever slower than serial.
- A monthly corpus-freshness job that diffs the pinned SHAs against upstream
  HEAD and files a tracking issue. It never edits a pin or a verdict.

### Known limitations

- Corpus-demonstrated recall is **3 of 7** architectures. The other four fire
  on synthetic fixtures but have not yet been shown to fire on real code, and
  are documented as PARTIAL or NOT COVERED rather than counted.
- Scan cannot verify that a guard is *bound* to the action it precedes. That
  binding is cryptographic and can only be checked at execution time. See
  `docs/COVERAGE.md`.

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
