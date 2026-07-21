# actenon-scan

**Stop AI agents from taking consequential actions they were never authorised to take.**

`actenon-scan` is a defensive static-analysis scanner that finds the **execution gap**: places where a consequential, irreversible action (payment, deletion, deployment, access grant) is reachable from an AI-agent tool boundary **without** a preceding authority or proof check on that code path.

Think of it as Bandit or Semgrep — but scoped to one problem: **the Replit incident, where an agent took a destructive action it should not have.**

> Works on **any** Python repo. Does not require the repo to have adopted Actenon.

## Quick start

```bash
pip install actenon-scan
actenon-scan scan .
```

Sample output:

```
actenon-scan: 3 finding(s) in 3 file(s) (scanned 47 file(s))

  refund_tool.py
    8:4     [HIGH] PAY-STRIPE-REFUND (payments)
            stripe.Refund.create(payment_intent=payment_id, amount=amount)
            confidence: high
            Guard this payment call with actenon proof verification. See: https://github.com/Actenon/actenon-permit

  delete_tool.py
    14:4    [HIGH] DATA-DELETE-SQL (data_destruction)
            'DELETE FROM {table_name}'
            confidence: high
            Guard this destructive call with actenon proof verification. See: https://github.com/Actenon/actenon-permit
```

## GitHub Action (SARIF + inline PR annotations)

```yaml
name: actenon-scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Actenon/actenon-scan@main
        with:
          path: .
          fail-on: medium
      # SARIF is automatically uploaded to GitHub code scanning
      # — inline PR annotations appear automatically
```

## How it decides

A **finding** is raised when a **SINK** is (a) **AGENT-REACHABLE** and (b) **UNGUARDED**.

| Signal | What it means | Detection |
|---|---|---|
| **SINK** | A call to a consequential/irreversible operation (payment refund, DELETE FROM, kubectl apply, IAM grant) | AST pattern matching on call names + SQL string literals |
| **AGENT-REACHABLE** | The sink lives inside a registered agent tool (`@tool`, `@mcp.tool`, `@server.tool`, tool wrapper, or a class subclassing `BaseTool`) | AST decorator/wrapper/class detection |
| **UNGUARDED** | No preceding authority/proof check on the path to the sink within the same function | Lexical precedence check for guard calls (`verify_proof`, `authorize`, `check_permission`) or guard decorators |

If the sink is not agent-reachable (e.g., it's in a plain script with no agent framework imports), no finding is raised. This keeps false positives low.

If the sink is guarded (an `authorize()` or `verify_proof()` call appears before it in the same function, or the function has a guard decorator), no finding is raised.

## Fix it

When `actenon-scan` flags a finding, the fix is to add a **proof-bound authority check** before the consequential call:

```python
# BEFORE (flagged)
@tool
def process_refund(payment_id: str, amount: int):
    stripe.Refund.create(payment_intent=payment_id, amount=amount)

# AFTER (clean)
@tool
def process_refund(payment_id: str, amount: int):
    from actenon import verify_proof
    verify_proof(action="refund", target=payment_id, amount=amount)
    stripe.Refund.create(payment_intent=payment_id, amount=amount)
```

The scanner recognises both **Actenon guards** (`verify_proof`, `require_proof`, `actenon.*`) and **generic guards** (`authorize`, `check_permission`, `require_approval`). So even if you don't adopt Actenon, adding a guard silences the finding — the tool is honestly useful to non-adopters.

- **[actenon-kernel](https://github.com/Actenon/actenon-kernel)** — the open proof gate
- **[actenon-permit](https://github.com/Actenon/actenon-permit)** — the developer-first issuer + PDP + broker

## Suppression

If a finding is a false positive, suppress it inline:

```python
# actenon-scan: ignore[PAY-STRIPE-REFUND]
stripe.Refund.create(...)
```

Or use a baseline to suppress already-known findings:

```bash
actenon-scan scan . --format json > baseline.json
# Future runs suppress these:
actenon-scan scan . --baseline baseline.json
```

## CLI

```
actenon-scan scan <path> [--format pretty|json|sarif] [--fail-on none|low|medium|high]
                          [--config config.json] [--baseline baseline.json]
                          [--include GLOB]... [--exclude GLOB]...
actenon-scan rules   # list active rules
actenon-scan init    # write a default config
```

## Exit codes

- `0` — no findings at or above the `--fail-on` threshold (default: `medium`)
- `1` — findings present at or above the threshold

This makes the tool CI-gating.

## License

Apache-2.0. See [LICENSE](LICENSE).
