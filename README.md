# Actenon Scan

> Find where agent-controlled intent reaches consequential actions without an enforceable authority check.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
<!-- PYTHON-BADGE:START -->
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
<!-- PYTHON-BADGE:END -->
[![PyPI: actenon-scan](https://img.shields.io/pypi/v/actenon-scan?label=PyPI)](https://pypi.org/project/actenon-scan/)
[![Dependencies: 0](https://img.shields.io/badge/Dependencies-0-success.svg)](pyproject.toml)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-v1-blue.svg)](#github-action)
[![SARIF](https://img.shields.io/badge/Output-SARIF-orange.svg)](#output-formats)
[![CI](https://github.com/Actenon/actenon-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Actenon/actenon-scan/actions/workflows/ci.yml)
[![claims: machine-verified](https://img.shields.io/github/actions/workflow/status/Actenon/actenon-scan/verify-claims.yml?branch=main&label=claims%3A%20machine-verified)](https://github.com/Actenon/actenon-scan/actions/workflows/verify-claims.yml)
[![Code style: ruff](https://img.shields.io/badge/Code%20style-ruff-black.svg)](https://docs.astral.sh/ruff/)
[![Vendor-neutral](https://img.shields.io/badge/Stance-vendor%20neutral-2ea44f.svg)](#what-scan-does-not-do)

## Quick start

```bash
uvx actenon-scan scan .
```

No install, no config, no cloud account. The first run produces a blast-radius
summary:

```
Your agent can reach 12 consequential actions without a dominating authorization check.

  REPOSITORY       4   create_file, merge, delete_ref, publish_release
  MONEY            3   process_refund, issue_credit, charge_card
  DATA LOSS        2   delete_s3_prefix, purge_workspace
  EXECUTION        2   deploy, run_migration
  EGRESS           1   notify_customers

Most exposed: app/tools.py:47  process_refund()
  Reachable by:              @mcp.tool()
  Consequence:               MONEY
  Guard evidence:            none found on the analysed path
  Model-controlled inputs:   payment_intent, amount

12 findings in 340 files (0.42s)
Next:
  actenon-scan explain app/tools.py:47
  actenon-scan fix app/tools.py:47
```

Then dig deeper:

```bash
actenon-scan explain app/tools.py:47    # show the analysed execution path
actenon-scan fix app/tools.py:47        # generate a remediation diff
actenon-scan brief app/tools.py:47      # one-page report for outreach
actenon-scan scan . --format html       # self-contained HTML report
actenon-scan scan . --format markdown   # paste into a GitHub issue
actenon-scan scan . --format sarif      # upload to GitHub code scanning
```

## What Actenon Scan detects

Actenon Scan finds places where a model-controlled or agent-controlled
parameter reaches a consequential action — a payment, a repository mutation,
a file deletion, a shell command, a database write, an email send — without
a dominating authority check in the analysed path.

**Consequence categories detected:**

| Category | Examples |
|----------|----------|
| REPOSITORY | PyGithub create_file/delete_file, raw GitHub REST, GitPython push/commit |
| MONEY | Stripe refunds, Braintree charges, generic payment SDK calls |
| DATA LOSS | SQL DELETE, s3.delete_objects, file deletion |
| EXECUTION | subprocess, os.system, eval/exec, container creation |
| DATABASE | psycopg2/sqlite3 execute with caller-controlled SQL |
| EGRESS | requests/httpx POST/PUT/DELETE to external URLs |
| MESSAGING | SMTP email, Slack, Twilio, SendGrid, Resend, SES |
| IDENTITY | IAM mutations, access-control changes |
| SECRETS | Secrets-manager reads |
| DEPLOYMENT | kubectl, terraform, helm |
| FILE | File writes, chmod, rename |

## What it does not establish

The scanner may establish that:
- an agent or model-controlled parameter reaches a consequential action;
- no dominating authority check was found in the analysed path;
- a recognised sink is present.

The scanner does **not** automatically establish that:
- an attacker can externally reach the agent;
- no guard exists outside the analysed file or supported architecture;
- exploitation is practical;
- the operation is irreversible;
- the finding is a vulnerability.

## How to explain a finding

```bash
actenon-scan explain path/to/file.py:42
```

Shows the analysed execution path: agent entry point → model-controlled
inputs → execution path → guard evidence → consequence. Includes a
mandatory "What this does NOT establish" section.

## How to generate a fix

```bash
actenon-scan fix path/to/file.py:42              # auto-select mode, print diff
actenon-scan fix path/to/file.py:42 --mode guard     # repository-native guard
actenon-scan fix path/to/file.py:42 --mode approval  # framework approval
actenon-scan fix path/to/file.py:42 --mode actenon   # Actenon proof verification
actenon-scan fix path/to/file.py:42 --apply          # write the change
```

Remediation is offered in neutral order: repository-native guard first,
framework-native approval second, Actenon proof verification third.
Actenon is not forced into every recommendation.

## How to add it to a PR

### GitHub Action (sticky comment + SARIF, zero config)

```yaml
# .github/workflows/actenon-scan.yml
name: actenon-scan
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write      # for the sticky comment
      security-events: write    # for SARIF upload to Security tab
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: Actenon/actenon-scan@v1
```

That's it. The action:
- Scans only changed files on PRs (full tree on push/schedule)
- Posts a sticky blast-radius comment on PRs with findings (updated in place)
- Uploads SARIF to the GitHub Security tab
- Does **not** fail the build by default

**Ready to enforce?** Add `fail-on: high` once you've triaged your baseline:

```yaml
      - uses: Actenon/actenon-scan@v1
        with:
          fail-on: high
```

### All inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to scan |
| `fail-on` | `none` | Fail at this severity (none/low/medium/high). Default: none |
| `config` | `""` | Path to config file |
| `baseline` | `""` | Path to baseline.json for known-findings suppression |
| `scan-scope` | `auto` | `changed` (PR only), `full` (entire repo), or `auto` |
| `comment-on-pr` | `true` | Post sticky blast-radius comment on PRs |
| `upload-sarif` | `true` | Upload SARIF to Security tab |
| `version` | `""` | Pin scanner version (default: action's own version) |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total findings |
| `high-count` | HIGH-severity findings |
| `medium-count` | MEDIUM-severity findings |
| `low-count` | LOW-severity findings |
| `sarif-path` | Path to the SARIF file |

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Actenon/actenon-scan
    rev: v0.8.0
    hooks:
      - id: actenon-scan
        args: [--changed-only, HEAD]
```

The default workflow does **not** block merging solely because findings exist
unless you explicitly configure `fail-on: high`.

## How to export reports

```bash
actenon-scan scan . --format html --output report.html     # self-contained HTML
actenon-scan scan . --format markdown --output report.md    # GitHub issue / PR
actenon-scan scan . --format sarif --output report.sarif    # GitHub code scanning
actenon-scan scan . --format list                           # old linter-style list
actenon-scan scan . --format json --output report.json      # machine-readable
```

HTML reports are self-contained (no external scripts, fonts, or assets),
safe to open locally, and include the visible honesty statement:
"What this scan verified / did not verify".

## How to suppress or baseline known findings

```bash
# Suppress a single finding inline:
# actenon-scan: suppress REPOSITORY-MUTATION

# Baseline known findings:
actenon-scan scan . --baseline known-findings.json
```

## Scanning a repo that contains test fixtures

If your repo contains security test fixtures — deliberately unguarded code
used to test the scanner or your own security controls — add an
`.actenon-scan.json` at the repo root to exclude them:

```json
{
  "_comment": "Exclude test fixtures that contain intentionally unguarded code.",
  "exclude": [
    "tests/benchmark/**",
    "tests/corpus/**",
    "tests/fixtures/**"
  ]
}
```

The file is auto-detected by `actenon-scan scan .` — no `--config` flag
needed. This repo ships one itself; see
[`.actenon-scan.json`](.actenon-scan.json).

## How to configure custom guards

```bash
# Register a guard by name without a config file:
actenon-scan scan . --guard my_authorize --guard require_permission

# Or use a config file:
actenon-scan scan . --config actenon-scan.json
actenon-scan init --format json  # write a default config
```

---

### Every claim above is machine-verified

The `claims: machine-verified` badge links to a CI gate
([`verify-claims.yml`](.github/workflows/verify-claims.yml)) that fails on
every PR, push to `main`, and once a day if any factual claim this README
makes about the package stops being true:

- **Zero runtime dependencies** — scan's single most important credibility
  claim (it is what lets a security team deploy scan unilaterally into a
  codebase that has adopted nothing). Read from `pyproject.toml`, not prose.
- **Install commands** — every `pip install` in this README is resolved
  against the live registry; the Python version badge is generated, not
  hand-edited.
- **The ecosystem table** — rendered from the protocol's `ecosystem.yaml`,
  never hand-edited.

If a claim drifts, the badge goes red before a human notices.

---


## Performance

Measured against a pinned real repository, not a synthetic tree:
**langchain-ai/langchain @ `fa7ce76`**, 1,954 Python files scanned. The pin,
every figure below, and the raw crossover table live in
[`tests/benchmark/perf-fixture.json`](tests/benchmark/perf-fixture.json).

**Scan time depends on your core count**, so the range is stated across the
machines actually measured rather than as a single number you might not be
able to reproduce:

| langchain, 1,954 files | serial | default (auto) |
|---|---|---|
| 10-core Apple Silicon | 1.9s | **0.96s** |
| 2–4 core CI container | ~5.2s | **~5.2s** (stays serial) |

Other repositories on the 10-core host: crewai (957 files) 2.4s → 1.1s,
openai-agents (539) 2.1s → 0.67s, mcp-python-sdk (586) 0.6s → 0.29s.

### Why the default is not always parallel

Parallelism is not free, and it does not pay off everywhere. Measured, it is
~2.5x faster on a 10-core machine and **~10% slower** on a 2–4 core CI
runner, where there are no spare cores to absorb the workers.

So `--jobs` auto-tunes: it parallelises only at **8+ cores** and **250+
files**, and stays serial otherwise. The 5–7 core range is unmeasured and
therefore treated as serial — the default is the mode that is never slower,
not the one that is sometimes faster.

`--jobs N` always overrides the auto-tune. `--jobs 1` forces serial.
Findings are identical either way; that equivalence is a test, not a claim.

Pre-commit path: `--changed-only` scans a 1–3 file diff in **~150ms**.

## What Scan recognises as a guard

Scan recognises three classes of guards. A sink is "guarded" if a recognised guard call appears lexically before the sink in the same function body, OR a recognised guard decorator wraps the function containing the sink. (This is a v1 lexical-precedence heuristic — documented limitation.)

### 30+ vendor-neutral guard patterns

Recognised out of the box, no Actenon required:

- `authorize`, `check_permission`, `require_permission`, `has_role`, `require_role`
- `verify_proof`, `verify_token`, `verify_signature`
- `jwt_required`, `require_jwt`, `validate_jwt`
- `opa_eval`, `casbin_enforce`, `cedar_authorize`
- `verify_api_key`, `verify_mtls`, `verify_client_cert`
- `require_auth`, `require_authz`, `auth_required`
- `can`, `may`, `is_allowed`, `check_access`
- `authorize_request`, `authorize_action`
- …and the rest in [`actenon_scan/detectors/guards.py`](actenon_scan/detectors/guards.py)

### Actenon-specific guards

Recognised when you are using the Actenon ecosystem:

- `verify_pccb`, `PCCBVerifier`, `PCCBVerifier.verify`
- `ProtectedExecutor`, `ProtectedExecutor.execute`
- `Actenon`, `Actenon.local`, `Actenon.cloud`
- `Broker`, `Broker.execute`, `Broker.execute_via_adapter`
- `Gateway`, `Gateway.execute`
- `BoundaryMiddleware`, `BoundaryVerifier`, `BoundaryVerifier.verify_boundary`

### Custom guards

Register your own guard function names:

```bash
actenon-scan init
# Edit actenon-scan.json:
# {
#   "guards": ["my_internal_check", "company_authorize", "acme_can"]
# }
actenon-scan scan ./my-agent-code
```

Custom guards are first-class — Scan does not privilege Actenon guards over yours.

## Remediation routes — 7 per finding, 3 are Actenon-free

Each finding ships with seven remediation routes. Scan does not pretend Actenon is the only answer.

1. **Add an existing internal guard.** If your codebase already has a guard function Scan didn't recognise, just add it via `actenon-scan init` and the finding disappears.
2. **Register the guard with Scan.** Same as above — Scan treats your guards as first-class.
3. **Use Actenon Kernel (proof verification).** For when you want proof-bound execution at the resource boundary. The Kernel is the trust anchor; it works without Permit or Cloud.
4. **Use brokered Actenon protection (Permit + adapter).** For when you control the agent framework and want credentials never to reach the agent. The recommended developer on-ramp.
5. **Use resource-owned verification.** For when the resource itself is the protected endpoint (FastAPI route, Express endpoint, Go handler). The Boundary Kit automates this.
6. **Use Cloud-managed Actenon.** For when you want a hosted control plane with 9-layer evidence bundles. Optional.
7. **Redesign the boundary.** Sometimes the right answer is to remove the consequential action from the agent's reachable tool surface entirely.

**Cloud is optional.** Local brokered protection (route 4) works without any Cloud login.

## What's in this repo

| Component | Location |
|---|---|
| CLI entry point | [`actenon_scan/cli.py`](actenon_scan/cli.py) |
| Scan engine (AST walk + sink detection + guard check) | [`actenon_scan/engine.py`](actenon_scan/engine.py) |
| Sink detector (consequential-action rules) | [`actenon_scan/detectors/sinks.py`](actenon_scan/detectors/sinks.py) |
| Guard detector (vendor-neutral + Actenon + custom) | [`actenon_scan/detectors/guards.py`](actenon_scan/detectors/guards.py) |
| Reachability analysis | [`actenon_scan/detectors/reachability.py`](actenon_scan/detectors/reachability.py) |
| Default rules (8 categories) | [`actenon_scan/rules/default_rules.json`](actenon_scan/rules/default_rules.json) |
| Rule loader | [`actenon_scan/rules/loader.py`](actenon_scan/rules/loader.py) |
| Baseline (known-findings suppression) | [`actenon_scan/baseline.py`](actenon_scan/baseline.py) |
| Suppression directives | [`actenon_scan/suppress.py`](actenon_scan/suppress.py) |
| Pretty reporter | [`actenon_scan/report/pretty.py`](actenon_scan/report/pretty.py) |
| JSON reporter | [`actenon_scan/report/json_out.py`](actenon_scan/report/json_out.py) |
| SARIF reporter | [`actenon_scan/report/sarif.py`](actenon_scan/report/sarif.py) |
| GitHub Action | [`action.yml`](action.yml) |
| Security policy | [`SECURITY.md`](SECURITY.md) |
| Contributing guide | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

## Independence

Scan depends on **nothing** at runtime. No Permit, no Kernel, no Cloud, no Protocol. `actenon-protocol` is a **dev-only** dependency, used solely by the drift-gate test (`tests/test_protocol_drift.py`) to verify that Scan's guard vocabulary and refusal-code references stay in sync with the Protocol's catalogue — it is not installed when you `pip install actenon-scan`. See [`pyproject.toml`](pyproject.toml).

Scan is a standalone security tool. You can adopt it without adopting anything else from Actenon, and you can stop using it without affecting any other Actenon component.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
