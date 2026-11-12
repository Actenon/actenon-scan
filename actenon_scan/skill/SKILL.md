---
name: actenon-scan
description: Audit AI agents, MCP servers, agent skills, tool handlers, and agentic repositories (Python, TypeScript/JS, Go) for consequential actions reachable by model-controlled input without a dominating authorization guard, multi-step compound exfiltration/poisoning chains, MCP/skill configuration risks, and ABOM/lockfile capability drift. Use when asked what an agent can do without permission, to audit `.mcp.json` or `SKILL.md` files, to trace compound attack chains, to generate an Agent Bill of Materials (`ABOM`) or `actenon.lock.json`, or to remediate unguarded tool side effects.
---
<!-- actenon-scan-managed-skill -->

# Actenon Scan — Agent Blast-Radius & Execution-Gap Skill

`actenon-scan` is a local, zero-cloud, vendor-neutral static analyzer that finds **where model-controlled input reaches consequential actions** (payments, shell execution, code execution, file deletion/writes, database mutations, outbound messaging, secret reads, repository mutations, deployments, browser actions) **without a dominating authorization check**.

## 1. Check Environment Readiness First

Before scanning an unfamiliar or polyglot repository, run:

```bash
actenon-scan doctor --json
```

If the repository contains `.ts`/`.tsx`/`.js` or `.go` files and `doctor` reports `typescript` or `go` parser support is missing, install full language support so those files are analysed rather than merely flagged as unsupported:

```bash
pip install "actenon-scan[all]"
# or with uv:
uv tool install "actenon-scan[all]"
```

## 2. Command Map (What the User Asks -> What to Run)

| User intent | Command |
|---|---|
| "What can my agent do without permission?" / "Scan this repo" | `actenon-scan .` |
| Structured machine-readable triage for agent reasoning | `actenon-scan scan . --format json --fail-on none` |
| Audit MCP configs (`.mcp.json`, Cursor/Claude) & `SKILL.md` files | `actenon-scan audit .` (add `--machine` for host IDE configs) |
| Detect multi-step exfiltration, skill-poisoning & lethal-trifecta chains | `actenon-scan chains .` |
| Generate Agent Bill of Materials (`actenon-abom/v1`) | `actenon-scan abom . --format markdown` |
| Pin approved agent capabilities & guard states (`actenon.lock.json`) | `actenon-scan lock .` |
| Verify PR/CI against `actenon.lock.json` (fail on new powers / guard drift) | `actenon-scan lock --check .` |
| Scan only files changed on the current branch / PR | `actenon-scan scan . --changed-only main` |
| Also audit FastAPI / Flask HTTP routes as entrypoints | `actenon-scan scan . --resource-boundary` |
| "Why is `app/tools.py:47` flagged?" (trace full call chain) | `actenon-scan explain app/tools.py:47` |
| Generate a stakeholder / PR security brief | `actenon-scan brief app/tools.py:47 --format markdown` |
| Preview a remediation patch | `actenon-scan fix app/tools.py:47` |
| Inventory every external capability & resource provenance | `actenon-scan authority . --format json` |
| Recognise custom repo guard helpers without editing code | `actenon-scan scan . --guard my_authorize` |
| Lock in legacy findings so CI only flags new regressions | `actenon-scan baseline . --output baseline.json` |
| Wire native read-only `actenon-scan` MCP server into `.mcp.json` | `actenon-scan install mcp` (or `actenon-scan setup --mcp`) |
| Add non-blocking GitHub Actions PR comment + SARIF | `actenon-scan install github` |
| Add local pre-commit hook | `actenon-scan install pre-commit` |

## 3. Non-Negotiable Soundness & Honesty Rules

1. **Never claim a clean scan proves a codebase is safe.**
   - Always inspect and report `unsupported_files`, `analysis_errors`, and `transitive_unfollowed_count` (the `Repository analysis:` disclosure). Dynamic dispatch, reflection, external queues, and unsupported languages remain outside static proof.
2. **Authentication and validation are NOT action authorization.**
   - `authenticate(user)`, `@login_required`, API-key checks, Pydantic/Zod schema validation, `isinstance(...)`, sanitization, and rate limiters establish **who is calling** or **input shape** — they NEVER authorize a specific consequential action (`refund`, `delete_file`, `subprocess.run`, `send_email`).
   - A valid guard must **dominate** every control-flow path to the sink, **bind** to the action and sink parameters (not a discarded return value `-WEAK` or unrelated parameter/action `-UNBOUND`), and refuse execution on denial.
3. **Remediation order is strictly vendor-neutral.**
   - Offer and prefer fixes in this order:
     1. **Repository-native guard** (`authorize(...)`, `check_permission(...)`, OPA/Casbin/Cedar, or registering the repo's existing guard via `.actenon-scan.json` / `--guard`).
     2. **Framework-native human approval** (MCP elicitation `ctx.elicit`, LangGraph/LangChain human interrupt, confirmation gate).
     3. **Cryptographic proof verification** (`actenon-kernel` `verify_pccb`) only when proof-bound execution at the resource boundary is desired.
4. **Do not stop at commented scaffolds.**
   - `actenon-scan fix <file:line>` in `guard` or `approval` mode inserts a commented scaffold (`# authorize(...)`) so it never breaks runtime imports with invented symbols. After applying or editing, wire the real dominating guard, uncomment it, and re-run `actenon-scan .` to confirm the capability moves to `Guard found on path`.
