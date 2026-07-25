# Contributing to actenon-scan

## Benchmark fixture changes

**Rule 3: Never move a benchmark number by changing a fixture.**

If a fixture is wrong, deleting or replacing it is legitimate, but the
score must be reported both ways (against the old fixture and the new
one) in the PR description.

A benchmark fixture change requires a section headed exactly:

```
## Fixture change justification
Fixture changed: <path>
Reason: <why the old fixture was wrong>
Score against OLD fixture: <n>/<m>
Score against NEW fixture: <n>/<m>
```

This is enforced by CI (`.github/workflows/benchmark-integrity.yml`).
The check fails the build if benchmark files are modified without the
justification section.

### Why this rule exists

A benchmark fixture was silently rewritten to move a soundness score
from 5/6 to 6/6 without fixing the detector. The rewrite replaced a
fixture that was separable in principle with one that was not, making
the score meaningless. The change was only caught by an outside reviewer
reading a diff.

Vigilance is not a mechanism. The CI check is the mechanism.

### Fixture lock

Every benchmark fixture has a SHA-256 digest stored in
`tests/benchmark/fixture-lock.json`. When you change a fixture, update
the lock:

```bash
python scripts/check_benchmark_integrity.py --update-lock
```

Commit the updated lock file alongside your fixture change. CI will
fail if the lock is out of sync.

## Running the benchmark

```bash
python scripts/benchmark.py              # print scoreboard
python scripts/benchmark.py --baseline   # write baseline file
python scripts/benchmark.py --check      # fail if scores decreased
```

Precision must be 100% — a drop fails the build. Recall and soundness
use a ratcheting baseline: they fail only if they decrease from the
committed baseline.

## Re-pinning the corpus

`tests/benchmark/pinned_repos.json` fixes each corpus repository at a commit
SHA. That pin is what makes the precision number reproducible: "30 findings,
30 true positives" is a statement about *those exact trees*.

The pins therefore go stale. The monthly **Corpus freshness** workflow diffs
them against upstream HEAD and files a single tracking issue listing what
changed. It never edits a pin or a verdict — it only reports, because acting
on it costs triage work that a person has to agree to.

**Re-pinning without re-triage is the same defect class as swapping a
benchmark fixture to move a score.** A new SHA means new code, which means the
30/30 no longer describes what was measured.

The procedure:

1. **Re-pin.** Update the `sha` (and `py_files`/`ts_files`) for the repos you
   are moving. Move as few as possible in one PR — a 25-repo re-pin is not
   reviewable.
2. **Re-scan.** `python scripts/corpus_scan.py --corpus-dir DIR` to regenerate
   `corpus-results.json`.
3. **Re-triage every changed finding.** Read the source at the exact line.
   New findings need a verdict and a rationale; findings that disappeared need
   their triage entry removed. Carrying a verdict across a SHA change without
   re-reading the code is triage in name only.
4. **Update `corpus-triage.json`** so every finding in the results has an
   entry, and no entry is orphaned. `scripts/check_corpus_triage.py` enforces
   both directions and will fail otherwise.
5. **Fix any new false positive** by tightening the rule and adding a
   regression fixture — never by editing the verdict. If a rule cannot be
   tightened without losing a true positive, downgrade it below HIGH.
6. **State old and new counts in the PR body**, per repo: findings before,
   findings after, true positives, false positives. A re-pin that changes the
   headline number without showing the delta is not reviewable.

If a re-pin drops the corpus-demonstrated recall, that is a real result and it
goes in the PR — `baseline.json` ratchets, so it needs an explicit decision,
not a quiet edit.
