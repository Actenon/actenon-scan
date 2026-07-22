# Actenon Scan

> The independent static-analysis scanner for the AI-agent execution gap. Zero dependencies. Runs without Cloud, Permit, or Kernel.

## What this is

Scan detects **consequential actions** reachable from AI-agent tool boundaries — and checks whether they're guarded.

It is:

- **Independent** — zero runtime dependencies (`dependencies = []`)
- **Neutral** — recognises Actenon guards AND non-Actenon guards (authorize, casbin_enforce, OPA, JWT, etc.)
- **Honest** — importing Actenon alone does NOT make a repo "safe"
- **Adoption-aware** — shows remediation routes (not Actenon-only)

## Install

```bash
pip install actenon-scan
```

## Use

```bash
# Scan a codebase
actenon-scan scan ./my-agent-code

# See adoption guidance
actenon-scan adopt ./my-agent-code

# Register custom guards
actenon-scan init
# Edit actenon-scan.json, add your guard function names
```

## What Scan detects

| Category | Examples |
|---|---|
| **Payments** | `stripe.Refund.create()`, `braintree.Transaction.sale()` |
| **Data destruction** | `os.remove()`, `DROP TABLE`, `shutil.rmtree()` |
| **Deployment** | `subprocess.run()`, `kubectl apply`, `terraform apply` |
| **Access control** | `put_user_policy()`, `attach_role_policy()` |
| **Communication** | `sendmail()`, `slack.postMessage()` |
| **Provider SDK** | `github.create()`, `boto3.delete_object()` |
| **Database mutation** | `INSERT INTO`, `UPDATE`, `db.save()` |
| **Identity change** | `create_user()`, `assign_role()` |

## What Scan recognises as guards

**30+ generic patterns** (vendor-neutral): `authorize`, `check_permission`, `verify_proof`, `has_role`, `jwt_required`, `opa_eval`, `casbin_enforce`, `verify_api_key`, `verify_mtls`, etc.

**Actenon-specific**: `verify_pccb`, `PCCBVerifier`, `ProtectedExecutor`, `Actenon`, `Broker`, `Gateway`, `BoundaryMiddleware`, etc.

**Custom**: Register your own via `actenon-scan init` + config file.

## What Scan does NOT do

- Report a repo as safe merely because Actenon is imported
- Report a repo as unsafe merely because a non-Actenon guard is used
- Make Actenon the only remedy (7 remediation routes, only 2 mention Actenon)

## GitHub Action

```yaml
- uses: actenon/scan@v1
  with:
    path: ./src
    fail-on: medium
```

## Output formats

- `pretty` (default, human-readable)
- `json` (machine-readable)
- `sarif` (GitHub Security tab integration)

## Remediation routes (per finding)

1. Add an existing internal guard
2. Register the guard with Scan
3. Use Actenon Kernel (proof verification)
4. Use brokered Actenon protection (Permit + adapter)
5. Use resource-owned verification
6. Use Cloud-managed Actenon
7. Redesign the boundary

**Cloud is optional.** Local brokered protection (route 4) works without any Cloud login.

## Independence

Scan depends on **nothing**. No Permit, no Kernel, no Cloud, no Protocol. It's a standalone security tool.

## License

Apache-2.0
