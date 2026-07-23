# Actenon Scan

> The independent static-analysis scanner for the AI-agent execution gap. **Zero runtime dependencies.** Detects consequential actions reachable from agent tool boundaries and checks whether they're guarded. Runs without Cloud, Permit, Kernel, or Protocol.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
<!-- PYTHON-BADGE:START -->
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
<!-- PYTHON-BADGE:END -->
[![PyPI: actenon-scan](https://img.shields.io/pypi/v/actenon-scan?label=PyPI)](https://pypi.org/project/actenon-scan/)
[![Dependencies: 0](https://img.shields.io/badge/Dependencies-0-success.svg)](pyproject.toml)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-v1-blue.svg)](#github-action)
[![SARIF](https://img.shields.io/badge/Output-SARIF-orange.svg)](#output-formats)
[![CI](https://github.com/Actenon/actenon-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Actenon/actenon-scan/actions/workflows/ci.yml)
[![Code style: ruff](https://img.shields.io/badge/Code%20style-ruff-black.svg)](https://docs.astral.sh/ruff/)
[![Vendor-neutral](https://img.shields.io/badge/Stance-vendor%20neutral-2ea44f.svg)](#what-scan-does-not-do)

---

## The Actenon ecosystem

Scan is one of five independent repositories that together close the **execution gap** — the gap between *upstream authorization* and the *execution edge* that actually performs a consequential side effect.

<!-- ECOSYSTEM-TABLE:START -->
| Repository | Role | Depends on | Packages |
|---|---|---|---|
| **`actenon-protocol`** | The neutral wire contract — what every artefact looks like on the wire | — | `actenon-protocol` (PyPI) · `@actenon/protocol-types` (npm) |
| **`actenon-kernel`** | The open verifier — defines what a valid proof is | `actenon-protocol` | `actenon-kernel` (PyPI) |
| **`actenon-permit`** | The developer on-ramp and authority broker | `actenon-kernel`, `actenon-protocol` | `actenon-permit` (PyPI) · `@actenon/sdk` (npm) |
| **`actenon-scan`** ← you are here | The independent static-analysis scanner | — | `actenon-scan` (PyPI) |

**Optional:** [`actenon-cloud`](https://github.com/Actenon/actenon-cloud) — a managed control plane (source-available; see its LICENSE). Not required by any component above; every capability in this ecosystem works without it.
<!-- ECOSYSTEM-TABLE:END -->

Scan is the **only** Actenon tool that should run in your CI on day one. It has zero dependencies, takes seconds to run, and tells you exactly where your agent code is reaching consequential side effects without proof-bound guards — whether or not you ever adopt the rest of the ecosystem.

---

## What this is

Scan is a defensive static-analysis scanner that detects **consequential actions** reachable from AI-agent tool boundaries — and checks whether they're guarded. It is:

- **Independent** — zero runtime dependencies (`dependencies = []` in [`pyproject.toml`](pyproject.toml)). Installable without pulling in any other Actenon package.
- **Neutral** — recognises Actenon guards AND non-Actenon guards (`authorize`, `check_permission`, `verify_proof`, `has_role`, `jwt_required`, `opa_eval`, `casbin_enforce`, `verify_api_key`, `verify_mtls`, etc.). Using Actenon is **not** the only remedy.
- **Honest** — importing Actenon alone does NOT make a repo "safe". A `import actenon` line in an unrelated module is not a guard. Scan refuses to green-light a codebase on the basis of imports.
- **Adoption-aware** — shows 7 remediation routes per finding, only 2 of which mention Actenon. The other 5 are framework-native or redesign routes.
- **CI-native** — ships as a Python package, a CLI, and a GitHub Action with SARIF output that integrates directly with the GitHub Security tab.

## Why it exists

Most agent code today reaches consequential side effects — `stripe.Refund.create()`, `os.remove()`, `subprocess.run()`, `put_user_policy()`, `db.execute("DROP TABLE...")` — through tool wrappers that the model can call directly. Very few of those tool wrappers verify proof bound to the exact action before the side effect happens. That is the **execution gap** in code form.

Scan exists to make that gap **visible** before it ships. It does not require you to adopt Actenon to be useful — it requires you to *see* where your agent code can reach money movement, data destruction, deployment, access-control change, communication, provider mutation, database mutation, or identity change without an enforceable guard.

The canonical problem statement lives in [`actenon-kernel/docs/THE_EXECUTION_GAP.md`](https://github.com/Actenon/actenon-kernel/blob/main/docs/THE_EXECUTION_GAP.md). Scan is the local adoption tool for detecting it; conformance (in the Kernel) is the public compatibility target.

## Install

```bash
pip install actenon-scan
```

Or use the GitHub Action (no install required) — see [below](#github-action).

## Use

```bash
# Scan a codebase
actenon-scan scan ./my-agent-code

# See adoption guidance for each finding
actenon-scan adopt ./my-agent-code

# Register custom guard function names
actenon-scan init
# Edit actenon-scan.json, add your guard function names

# Suppress known findings with a baseline
actenon-scan scan ./my-agent-code --baseline baseline.json
```

## Example: detecting the execution gap

Save this as `refund_tool.py`:

```python
from langchain.tools import tool
import stripe

@tool
def refund(pid: str, amt: int) -> str:
    """Refund a payment."""
    return stripe.Refund.create(payment_intent=pid, amount=amt)
```

Run the scanner:

```bash
$ actenon-scan scan .

actenon-scan: 1 finding(s) in 1 file(s) (scanned 1 file(s))

  refund_tool.py
    6:11  [HIGH] PAY-STRIPE-REFUND (payments)
            stripe.Refund.create(payment_intent=pid, amount=amt)
            confidence: high
            Guard this payment call before execution. Options:
              (1) add an existing internal authorization check,
              (2) register it with scan --config,
              (3) use Actenon Kernel proof verification,
              (4) use brokered Actenon protection (Permit + adapter),
              (5) redesign the boundary if this action should not be agent-reachable.
```

Notice the `@tool` decorator on line 4 — that is what makes the `stripe.Refund.create()` call on line 6 agent-reachable, and therefore in-scope for the scanner. The same call inside a plain function with no agent-tool boundary would be silently ignored to avoid false positives.

## What Scan detects — 8 consequence categories

Scan walks the AST and finds calls to consequential / irreversible operations across eight categories. Rules are configurable in [`actenon_scan/rules/default_rules.json`](actenon_scan/rules/default_rules.json); you can add your own.

| Category | Example sinks |
|---|---|
| **Payments** | `stripe.Refund.create()`, `braintree.Transaction.sale()`, `paypal.Payment.create()` |
| **Data destruction** | `os.remove()`, `shutil.rmtree()`, `DROP TABLE`, `DELETE FROM`, `TRUNCATE` |
| **Deployment** | `subprocess.run()`, `kubectl apply`, `terraform apply`, `helm install` |
| **Access control** | `put_user_policy()`, `attach_role_policy()`, `create_role()`, `assign_role()` |
| **Communication** | `sendmail()`, `slack.postMessage()`, `twilio.messages.create()` |
| **Provider SDK** | `github.create_issue()`, `boto3.delete_object()`, `azure.storage.delete_blob()` |
| **Database mutation** | `INSERT INTO`, `UPDATE`, `db.save()`, `cursor.execute("DELETE...")` |
| **Identity change** | `create_user()`, `assign_role()`, `rotate_keys()`, `update_permissions()` |

Each finding includes: rule ID, category, severity, description, file:line:column, and the matched call text.

> **Detection requires an agent-tool boundary.** A finding is only raised when the risky call is reachable from a recognised agent-tool boundary — a `@tool`-decorated function (LangChain, LlamaIndex), an MCP `@server.tool` handler, a method on a tool-base subclass, or a module that imports a supported agent framework. Standalone calls with no agent context are intentionally ignored to avoid drowning you in false positives on code that isn't agent-reachable. See the [example below](#example-detecting-the-execution-gap) for what this looks like in practice.

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

## What Scan does NOT do

This is the part that makes Scan trustworthy in a vendor-neutral CI:

- **Does NOT report a repo as safe merely because Actenon is imported.** An `import actenon` line in an unrelated module is not a guard. Scan refuses to green-light a codebase on the basis of imports.
- **Does NOT report a repo as unsafe merely because a non-Actenon guard is used.** `@jwt_required` on a refund endpoint is a real guard. Scan recognises it.
- **Does NOT make Actenon the only remedy.** Each finding ships with 7 remediation routes — only 2 mention Actenon.
- **Does NOT inspect prompts, model output, or in-band response content.** It is a static-analysis tool, not a runtime filter.
- **Does NOT replace conformance.** Scan is the local adoption tool; conformance (in the Kernel) is the public compatibility target. See [`actenon-kernel/docs/EXECUTION_GAP_SCANNER.md`](https://github.com/Actenon/actenon-kernel/blob/main/docs/EXECUTION_GAP_SCANNER.md).
- **Does NOT make a runtime-safety claim.** A guarded sink is "lexically guarded", not "provably safe at runtime". The v1 lexical-precedence heuristic is documented in [`actenon_scan/detectors/guards.py`](actenon_scan/detectors/guards.py).

## GitHub Action

Drop this into `.github/workflows/actenon-scan.yml` — no install step, no API key, no Cloud account:

```yaml
name: Actenon Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actenon/scan@v1
        with:
          path: ./src
          fail-on: medium
```

The Action:

1. Installs `actenon-scan` from PyPI.
2. Runs the scan, emitting SARIF.
3. Uploads the SARIF to the GitHub Security tab via `github/codeql-action/upload-sarif@v3`.
4. Fails the build if any findings meet the `fail-on` severity threshold.

Inputs:

| Input | Default | Purpose |
|---|---|---|
| `path` | `.` | Path to scan (file or directory) |
| `fail-on` | `medium` | Fail the check when findings meet this severity |
| `config` | `""` | Path to a custom `actenon-scan.json` config |
| `baseline` | `""` | Path to a `baseline.json` for known-findings suppression |

## Output formats

| Format | Flag | Use case |
|---|---|---|
| `pretty` (default) | `--format pretty` | Human-readable terminal output |
| `json` | `--format json --output results.json` | Machine-readable, for piping into other tools |
| `sarif` | `--format sarif --output results.sarif` | GitHub Security tab integration |

## Remediation routes — 7 per finding, only 2 mention Actenon

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
