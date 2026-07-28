# Release Checklist — actenon-scan

Lessons from WO1.9 (v1.3.0 release) and WO1.10-1.11.

## Pre-release

1. **Full test suite passes** — all extras installed, all suites green.
2. **Corpus study check passes** — `python scripts/generate_corpus_study.py --check`.
3. **Corpus verification** — `python scripts/verify_corpus_scan.py --scan-dir <corpus-scan-dir>`.
4. **Self-scan clean** — 0 findings on own repository.
5. **Wheel builds and verifies** — Provides-Extra includes typescript and go; version metadata correct.
6. **Built-artifact fixture run** — install built wheel in fresh venv; run Go/TS fixtures.
7. **Scratch repo negative test** — run the release gate against v1.1.0 (known-bad, no Go guard recognition). Must FAIL.
   - Scratch repo: https://github.com/rossbuckley1990-hash/actenon-scan-v1-verification

## Release sequence

8. **Push branch, open PR, merge to main.** All CI must be green.
9. **Push the tag** (e.g. `v1.4.0`). This triggers `publish.yml` (PyPI via trusted publishing/OIDC). **First irreversible step.**
10. **STOP.** Verify from fresh PyPI venv:
    - `pip install 'actenon-scan[typescript,go]==<version>'` — no warnings
    - `actenon-scan --version` — reports the new version
    - Go fixture: guarded case suppresses
    - TS fixture with guard-word comment: still flags
    - regex.exec fixture: does not flag
    - handler.fetch fixture: does not flag
    - Three Go reference repos: counts match previous measurement
11. **Create the GitHub Release.** This triggers `release-v1-tag.yml`:
    - Release gate runs: checkout at tag, `uses: ./`, verifies findings + Go guards + SARIF + version
    - If gate passes, advance-v1 moves the v1 tag
    - Post-advancement verification: `uses: Actenon/actenon-scan@v1` delivers the new version
    **Second irreversible step.**
12. **Verify v1 advancement:**
    ```
    git fetch origin --tags --force
    git rev-parse v1^{commit}     # must equal the new tag's commit
    git cat-file -p v1            # tag field must read "v1"
    ```

## Post-release

13. **External verification** — push to the scratch repo, trigger the workflow, verify from logs: install line, findings, SARIF upload, sticky comment.
14. **Check Marketplace listing** — description may cache stale text.
15. **Check actenon.com landing page** — update precision figure if changed.

## Known issues from WO1.9 (fixed, recorded for reference)

These were discovered during the v1.3.0 release and are now fixed:

- **Reusable workflows require `workflow_call` trigger** with `type: string` on inputs.
- **The `uses:` field cannot contain expressions** from `steps`, `needs`, or `github.event`. Use `actions/checkout` with `ref: <tag>` then `uses: ./` instead.
- **`--scan-scope` is an Action input, not a CLI flag.** The CLI uses `--changed-only`.
- **Annotated tags require git identity** configured on the runner: `git config user.name/email`.
- **`verify-claims` pyproject-vs-PyPI check** shows four states at each release stage:
  - `pyproject == pypi` → PASS (steady state)
  - `pyproject > pypi`, no tag → PASS (bump merged, not yet released)
  - `pyproject > pypi`, tag exists → FAIL (tag pushed but publish didn't land)
  - `pypi > pyproject` → FAIL (rollback, yank, or drift)

## Known issues from WO1.11 (fixed, recorded for reference)

- **`--changed-only origin/main` fails silently** if the base branch isn't fetched. `actions/checkout@v4` with default `fetch-depth` does NOT fetch the base branch. The Action now runs `git fetch origin <base_ref> --depth=1` before scanning. The README documents `fetch-depth: 0` as belt-and-braces.
