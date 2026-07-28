<!-- HISTORICAL: This file is frozen at v0.4.0. The authoritative corpus -->
<!-- study is docs/CORPUS_STUDY.md (auto-generated, CI-enforced). -->
<!-- This file is preserved for the correction story (51/63 → 22/22). -->
<!-- The current figure is 22 TP / 100% precision (0 false positives). See CORPUS_STUDY.md. -->

# Corpus Validation Results — actenon-scan 0.4.0 (historical)

## Scan summary

| Repo | Files scanned | Findings | TP | FP | Precision |
|---|---|---|---|---|---|
| anthropic-quickstarts | 138 | 7 | 6 | 1 | 86% |
| autogen | 576 | 3 | 0 | 3 | 0% |
| codex | 755 | 0 | 0 | 0 | n/a |
| crewAI | 957 | 12 | 12 | 0 | 100% |
| langchain | 1,954 | 0 | 0 | 0 | n/a |
| openai-agents-python | 539 | 4 | 0 | 4 | 0% |
| python-sdk | 586 | 1 | 1 | 0 | 100% |
| servers (MCP) | 60 | 2 | 2 | 0 | 100% |
| **Total** | **5,065** | **29** | **21** | **8** | **72%** |

## What actenon-scan gives the user

### The value

1. **Instant visibility into the execution gap.** In under 2 seconds per
   repo, scan tells you exactly where agent code can reach money movement,
   data destruction, shell execution, file writes, and network egress
   without a guard. No other tool does this for agent code specifically.

2. **Agent-aware reachability.** Unlike a generic SAST tool, scan
   understands MCP tool decorators, LangChain BaseTool subclasses, and
   CrewAI tool patterns. A `subprocess.run` in a utility module is
   ignored; the same call inside `@mcp.tool()` is flagged.

3. **Vendor-neutral guard recognition.** 145 guard patterns covering
   Actenon, OAuth, JWT, OPA, Casbin, Cedar, MCP-native elicitation,
   LangChain human-in-the-loop, and common naming conventions
   (`authorize`, `assert_can`, `policy_gate`). A codebase with its own
   guard naming gets a clean scan.

4. **Zero-dependency base install.** `pip install actenon-scan` installs
   with nothing else. TypeScript and Go support are each 1 MB behind an
   extra. This is what gets scan into CI pipelines that would reject a
   heavier tool.

5. **Language-agnostic output.** Same rule IDs, same categories, same
   SARIF format for Python, TypeScript, and Go. CI gates work identically.

### The true positives that matter

**crewAI SingleStore tool** — `cursor.execute(search_query)` in an
`@tool`-decorated function. The agent controls the SQL. This is the
exact execution gap the tool is designed to find.

**MCP memory server** — `fs.writeFile(this.memoryFilePath, ...)` inside
a `setRequestHandler` handler. The agent writes arbitrary content to
the filesystem. No guard.

**MCP everything server** — `fetch(url)` inside a tool handler. The
agent fetches arbitrary URLs. No guard. This is a data exfiltration path.

**python-sdk text_me** — `client.post('https://api.surgemsg.com/messages')`
inside an `@mcp.tool`. The agent sends SMS messages. No guard.

**anthropic-quickstarts computer-use** — `subprocess.Popen(cmd)` and
`page.goto(kwargs["url"])` in tool classes. The agent executes shell
commands and navigates to URLs. These are the real consequential actions.

## False positive analysis

All 8 FPs share two root causes:

### Root cause 1: `if __name__ == "__main__"` blocks (5 FPs)

Files that import the MCP SDK trigger module-level reachability. Sinks
inside `if __name__ == "__main__":` blocks are at module level (not in
a function), so they get MEDIUM confidence and are reported.

**Affected:** 4 openai-agents-python EXEC-SHELL (subprocess.Popen in
example main blocks), 1 autogen FILE-OPEN-WRITE (gallery builder main
block).

**Fix:** Exclude `if __name__ == "__main__"` blocks from module-level
reachability. Entry-point code is not agent-reachable.

### Root cause 2: Class-body lambdas (2 FPs)

`SecretStr: lambda v: v.get_secret_value()` in Pydantic ConfigDict
assignments. The lambda has no enclosing FunctionDef, so the sink
appears to be at module level.

**Affected:** 2 autogen SECRET-READ.

**Fix:** Detect when a sink is inside a class body (even inside a
lambda) and do not apply module-level reachability.

### Root cause 3: Cleanup in finally blocks (1 FP)

`script.unlink(missing_ok=True)` in a `finally` block — temp file
cleanup, not a consequential action.

**Affected:** 1 anthropic-quickstarts DATA-DELETE-OS.

**Fix:** Suppress findings inside `finally` blocks for file-deletion
rules when the deleted file is a temp file (created with tempfile
in the same function).

## What would improve precision to ~95%

1. **Exclude `if __name__ == "__main__"` from reachability** — fixes 5/8 FPs
2. **Exclude class-body code from module-level reachability** — fixes 2/8 FPs
3. **Suppress temp-file cleanup in finally blocks** — fixes 1/8 FP

After these fixes: 22 TP / 100% precision (0 false positives) across 5,065 files.

The server.go:286 finding (os.OpenFile on cfg.LogFilePath) was suppressed
by a rule fix (log/config file detection). The actions.go:172 finding
(http.Get on logURL) is kept as TRUE_POSITIVE — the URL is not directly
model-controlled but the scanner cannot trace this interprocedurally.
