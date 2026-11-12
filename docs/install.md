# Install Actenon Scan (For AI Agents & Developers)

> **One-sentence prompt for your coding agent (Claude Code, Cursor, Codex, Antigravity, Gemini CLI, Windsurf, OpenClaw):**
>
> `Install actenon-scan and wire its agent skill by following https://raw.githubusercontent.com/Actenon/actenon-scan/main/docs/install.md`

---

## Agent Instructions (Execute Directly)

Follow these steps in order to install `actenon-scan` with full Python + TypeScript/JavaScript + Go + YAML support, register its embedded `SKILL.md` into your harness, and verify readiness.

### Step 1 — Install `actenon-scan`

Prefer `uv tool install` when `uv` is available; otherwise use `pipx` or `pip`:

```bash
if command -v uv >/dev/null 2>&1; then
  uv tool install "actenon-scan[all]"
elif command -v pipx >/dev/null 2>&1; then
  pipx install "actenon-scan[all]"
else
  python3 -m pip install --user "actenon-scan[all]"
fi
```

Need a zero-install, zero-dependency Python-only check right now?

```bash
uvx actenon-scan .
# or base install (0 runtime dependencies):
pip install actenon-scan
```

### Step 2 — Install the Agent Skill & Run Readiness Checks

```bash
actenon-scan setup
```

`actenon-scan setup` performs three safe, local-only actions (no network requests, no cloud account, foreign files are never overwritten):

1. Writes the canonical skill to `~/.agents/skills/actenon-scan/SKILL.md` (`0700` dir / `0600` file).
2. Auto-links the skill into every detected agent harness on the machine (`~/.claude/skills`, `~/.cursor/skills`, `~/.codex/skills`, `~/.gemini/skills`, `~/.gemini/antigravity/skills`, `~/.copilot/skills`, `~/.codeium/windsurf/skills`, `~/.openclaw/skills`, `~/.hermes/skills`).
3. Runs `actenon-scan doctor` to verify Python/TypeScript/Go parser availability, Git `--changed-only` readiness, config files, and CI/pre-commit hooks.

### Step 3 — Verify on the Current Workspace

```bash
actenon-scan doctor --json
actenon-scan . --fail-on none
actenon-scan audit . --fail-on none
actenon-scan chains . --fail-on none
```

### Step 4 — Optional: Wire Native MCP Server, Consequence Lockfile, or CI Guardrails

Only run these when requested by the user:

```bash
actenon-scan install mcp          # registers zero-dep stdio `actenon-scan mcp-server` in .mcp.json
actenon-scan lock .               # pins approved capabilities & guard states in actenon.lock.json
actenon-scan install github       # writes .github/workflows/actenon-scan.yml (non-blocking sticky PR comment + SARIF)
actenon-scan install pre-commit   # writes/appends .pre-commit-config.yaml
```

---

## Managing or Removing the Skill

```bash
actenon-scan skill status         # check canonical SKILL.md and harness links
actenon-scan skill print          # print the embedded SKILL.md to stdout
actenon-scan skill link --link-dir .agents/skills   # link into a repo-local skill folder
actenon-scan skill uninstall      # cleanly remove managed skill & links (never touches foreign files)
```
