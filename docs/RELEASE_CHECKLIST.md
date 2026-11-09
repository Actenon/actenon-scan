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

## Release controls (owner applies once)

`scripts/release_gate.py gate` reads the three GitHub settings below (environment, tag rulesets,
`main` protection) through the public API on every release, and fails closed if any is missing.
PyPI's trusted publisher cannot be read from GitHub. Without it, upload fails, because there is
no other credential:

- **PyPI trusted publisher** for `actenon-scan`: owner `Actenon`, repository `actenon-scan`,
  workflow `publish.yml`, environment `pypi`. Then delete the `PYPI_API_TOKEN` repository secret
  and revoke that token on PyPI. `publish.yml` has no token route, and its `verify-registry` job
  fails unless each uploaded file carries a trusted-publishing attestation from this workflow.
- **`pypi` environment**: required reviewer = the release owner, deployments from tags matching
  `v*.*.*` only, and "Allow administrators to bypass configured protection rules" **off**.
  `python scripts/release_gate.py print-environment --reviewer-id "$(gh api users/<login> --jq .id)"`
  prints the settings.
- **Release-tag rulesets**: `python scripts/release_gate.py print-tag-rulesets` prints them. Only
  repository admins can create `refs/tags/v*.*.*`, and nobody can update or delete one. The
  pattern deliberately does not match the moving Action tag `v1`, which `release-v1-tag.yml`
  advances.
- **`main` branch protection**: `python scripts/release_gate.py print-protection | gh api -X PUT
  repos/Actenon/actenon-scan/branches/main/protection --input -`. This requires every
  `pull_request` check from GitHub Actions (app 15368) and applies to admins.
- **Merge method**: merge release PRs with a merge commit (not squash or rebase), so the commit
  whose checks passed is the commit that lands on `main` and gets tagged.

## Release sequence

8. **Open the release PR and merge it to `main` with a merge commit.** Every check in
   `.github/required-checks.json` must be green on the PR head. The head must contain no
   `.github/candidate-constraints.txt` and no `PIP_CONSTRAINT`, because the gate refuses any
   candidate source pin.
9. **Tag the PR head commit**, which is now on `main`: `git tag -a v<version> <sha> -m "v<version>"`
   and `git push origin v<version>`. This triggers `publish.yml`:
   - `release-gate` checks the tag, `main` ancestry, the required checks on that exact commit, and
     the release controls.
   - `build` builds once, reproducibly (`SOURCE_DATE_EPOCH` = commit time), smoke-tests the wheel,
     and records `SHA256SUMS`.
   - `publish` **waits for the owner to approve the `pypi` deployment**. Approve only after reading
     the gate log and the recorded hashes. **This approval is the first irreversible step.**
   - `verify-registry` checks that PyPI serves exactly the approved, attested files, installs them
     with `--require-hashes` into a clean venv, compares the installed files to the approved wheel
     byte for byte, runs a real scan, and runs `check_version_coherence.py --mode release`.

   There is no manual dispatch. If a job fails, re-run it on the same tag, or fix forward with a
   new version.
10. **STOP.** Check `verify-registry`'s `registry-verification` artifact. Then verify from a fresh
    PyPI venv:
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
    - PyPI probes must read the complete response and validate its version. Under `pipefail`, an early-closing pipeline such as `curl ... | head` can report curl exit 23 despite a successful HTTP response.
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
