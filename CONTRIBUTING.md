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
