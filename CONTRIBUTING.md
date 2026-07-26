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

## How to add a new sink rule

A sink rule is a JSON object in `actenon_scan/rules/default_rules.json` under
the `sinks` array. The schema:

```json
{
  "id": "UNIQUE-RULE-ID",
  "category": "payments",
  "severity": "high",
  "cwe": "CWE-862",
  "owasp": "LLM06",
  "description": "One-line description shown in CLI output and SARIF.",
  "match": { ... },
  "priority": 20
}
```

### Fields

| Field | Required | Notes |
|---|---|---|
| `id` | yes | `CATEGORY-SHORT-NAME`. Must be unique. |
| `category` | yes | One of: `payments`, `data_destruction`, `database_mutation`, `code_execution`, `shell_execution`, `network_egress`, `communication`, `identity_change`, `access_control`, `credential_access`, `file_mutation`, `browser_action`, `deployment`, `provider_sdk`, `repository_mutation`, `vcs_mutation`. |
| `severity` | yes | `low` / `medium` / `high`. |
| `cwe` | no | CWE ID for SARIF. |
| `owasp` | no | OWASP LLM Top-10 reference. |
| `description` | yes | One line; appears in `actenon-scan rules`, SARIF, and `--format list`. |
| `match` | yes | See match types below. |
| `priority` | yes | Higher wins when multiple rules fire on the same call. Use 20 for qualified matches, 10 for unqualified. |

### Match types

**`attr_call`** — matches `module.attr(...)` where `module` matches a
`module_pattern` and `attr` matches a `func_pattern`:
```json
"match": {
  "type": "attr_call",
  "module_patterns": ["stripe", "stripe.Refund"],
  "func_patterns": ["refund", "create"]
}
```

**`qualified_call`** — matches `module.func(...)` where the full dotted name
matches a `qualified_name`:
```json
"match": {
  "type": "qualified_call",
  "qualified_names": ["os.system", "subprocess.run"]
}
```

**`name_call`** — matches any call to a function whose name matches a
`func_pattern`, regardless of module. Use sparingly — produces false positives
on unrelated code with same-named helpers. Always pair with `priority: 10`:
```json
"match": {
  "type": "name_call",
  "func_patterns": ["refund", "charge", "transfer"]
}
```

**`sql_execute_pattern`** — matches `cursor.execute(...)` where the cursor
came from a recognised DB-API module (psycopg2, sqlite3, etc.):
```json
"match": {
  "type": "sql_execute_pattern",
  "receiver_patterns": ["cursor", "conn", "db"]
}
```

**`open_write`** — matches `open(path, mode)` where `mode` includes `w`,
`a`, or `x`:
```json
"match": {
  "type": "open_write",
  "modes": ["w", "wb", "a", "ab", "x", "xb", "w+", "a+", "x+"]
}
```

**`string_pattern`** — matches any call whose source text matches a regex:
```json
"match": {
  "type": "string_pattern",
  "patterns": ["kubectl\\s+apply", "kubectl\\s+delete"]
}
```

### Adding a new rule — checklist

1. Add the JSON object to `actenon_scan/rules/default_rules.json`.
2. Add a corpus fixture pair: one `vulnerable/` file that fires the rule,
   one `safe/` file that does NOT (e.g., the call is in a non-tool function,
   or guarded). See `tests/corpus/` for the directory layout.
3. Run `pytest tests/test_corpus.py` — it asserts every corpus pair fires
   (or doesn't) as documented.
4. Run `pytest tests/test_rule_audit.py` — it audits rule metadata
   consistency.
5. Run `pytest tests/test_coverage_contract_gate.py` — it asserts
   `docs/COVERAGE.md` lists every rule, so update `docs/COVERAGE.md`.
6. If the rule introduces a new category, also update the consequence table
   in `README.md` and `_DISPLAY_ORDER` in `actenon_scan/report/blast_radius.py`.

## How to add a new guard pattern

Guards are recognised by name. To add a new vendor-neutral guard, append the
function name to `guard_patterns` in `actenon_scan/detectors/guards.py`:

```python
GUARD_PATTERNS = {
    # ... existing patterns ...
    "my_internal_authorize",
    "company_check_permission",
}
```

Then:

1. Add a test in `tests/test_guards.py` that constructs a function with a
   sink call preceded by your guard, scans it, and asserts the finding is
   suppressed (or marked `-WEAK` / `-UNBOUND` as appropriate).
2. Add the pattern name to `docs/COVERAGE.md` under the guard list.
3. If the guard is framework-specific (e.g., a Django decorator), add a
   corpus fixture in `tests/corpus/DECLARATIVE-GUARD/` showing the decorator
   form is recognised.

Users can also register custom guards via `actenon-scan init` + config file,
or `--guard my_authorize` on the CLI. Those paths do not require code changes.

## How to add a new reachability signal

Reachability signals tell the scanner "this function is reachable by an
agent." They live in `actenon_scan/detectors/reachability.py`. The built-in
signals recognise:

- Tool decorators (`@mcp.tool()`, `@tool`, `@function_tool`, etc.)
- Tool base classes (`BaseTool`, `StructuredTool`)
- Tool-list parameters (`tools=[foo, bar]`)
- Schema dispatch (`function_schema`)
- Action observation loops

To add a new signal:

1. Add the pattern (e.g., a new decorator name) to the relevant set in
   `reachability.py` — usually `TOOL_DECORATORS` or `TOOL_BASE_CLASSES`.
2. Add a test in `tests/test_reachability.py` that constructs a function
   using the new signal, scans it, and asserts the sink fires (i.e., the
   function is correctly detected as agent-reachable).
3. Add a SAFE fixture in `tests/corpus/` showing that the same sink in a
   non-tool function is NOT reported (proves the signal is necessary AND
   sufficient).
4. Update `docs/COVERAGE.md` to list the new architecture.

## How to add a corpus fixture pair

Each consequence category has a directory under `tests/corpus/`, e.g.,
`tests/corpus/EXEC-SHELL/`. Inside, two subdirectories:

- `vulnerable/` — code that fires the rule. The function must be marked as
  agent-reachable (decorated with `@tool` or similar) and the sink must be
  unguarded.
- `safe/` — code that does NOT fire the rule. Same sink, but either the
  function is not agent-reachable, OR a recognised guard precedes the sink.

Naming convention: `NN_short_description.py` where `NN` is a zero-padded
sequence number (01, 02, 03). The sequence number keeps the directory
listing readable as fixtures accumulate.

After adding a pair:

1. Run `pytest tests/test_corpus.py` — it asserts every vulnerable fixture
   fires exactly one finding, and every safe fixture fires zero.
2. Run `pytest tests/test_corpus_completeness.py` — it asserts every
   category directory has at least one vulnerable and one safe fixture.

## How to run a subset of tests

```bash
# One test file
pytest tests/test_sinks.py

# One test
pytest tests/test_sinks.py::test_stripe_refund_in_tool

# Match a pattern
pytest -k "stripe"

# The full suite (slow — includes corpus + benchmark)
pytest

# Skip the slow corpus + benchmark tests
pytest --ignore=tests/test_corpus.py --ignore=tests/benchmark
```

The CI gates that MUST pass before merge:

- `pytest tests/` (full suite)
- `python scripts/check_benchmark_integrity.py` (fixture lock)
- `python scripts/check_corpus_triage.py` (triage completeness)
- `python scripts/check_coverage_contract.py` (COVERAGE.md in sync)
- `python scripts/check_perf_gate.py` (perf regression)
- `python scripts/check_version_coherence.py` (version + changelog)
- `python scripts/check_readme_installs.py` (README install commands resolve)

