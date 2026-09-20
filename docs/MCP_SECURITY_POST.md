# MCP Security Discussions — Draft Post

> Draft text for posting to MCP security discussions (Anthropic's MCP
> Discord, the MCP spec GitHub Discussions, the #mcp-security channel
> on relevant servers). Paste the body below into the composer. Same
> tone as the OWASP post — engineer to engineer, no hype.

**Suggested title:** Soundness challenge for an MCP static analyzer (actenon-scan)

---

If you're building MCP servers, the `@mcp.tool` decorator marks an entrypoint where the LLM can call your code. Scan catches sinks inside `@mcp.tool` bodies. It does NOT catch sinks in helpers only reachable transitively from `@mcp.tool` — that's a known limitation we're disclosing.

**The instrument.** Actenon Scan is a per-file static analyzer for Python, TypeScript, and Go. It finds places where model-controlled input reaches a consequential action — a payment, a file deletion, a shell command, a database write, an email send, a deployment — without a dominating authority guard on the analysed path. It matches against ~145 guard patterns and recognises the MCP `@mcp.tool` decorator and the TypeScript `setRequestHandler` boundary as agent tool entrypoints. A clean scan means "no supported consequential-action paths were identified" — never "the codebase is safe." The full boundary of what it does and does not verify is at https://github.com/Actenon/actenon-scan/blob/main/docs/COVERAGE.md, pinned by CI.

Three honest limitations matter for an MCP server author:

- **Per-file analysis by default.** A sink in a helper only reachable from `@mcp.tool` via intermediate calls is NOT flagged unless `--repository-analysis` is enabled — and only when every call-chain edge resolves to `RESOLVED`. Heuristic edges record evidence but produce no finding. If your `@mcp.tool` body calls a helper that calls `subprocess.run`, the helper's sink may go unreported. This is the central limitation for MCP server code.
- **No detection of custom agent loops.** If your server passes the LLM's output through a hand-rolled dispatch loop, scan does not flag it. Recorded as NOT COVERED.
- **Unsupported languages are reported as unsupported, never as clean.** MCP servers in Rust are out of scope; that is the contract, not a miss.

**The specific MCP ask.** Submit MCP-specific soundness challenges — patterns where scan misses an agent-reachable consequential action in an MCP server, or flags a sink that is actually guarded. The most useful cases are sinks in transitive helpers reachable from `@mcp.tool` bodies that the per-file scan reports clean on. Template: https://github.com/Actenon/actenon-scan/blob/main/community-scans/CHALLENGE_TEMPLATE.md. Submissions get a public scoreboard entry and a permanent regression test when fixed.

**The honest incentive.** External submissions are worth more than another sprint of my own tests because I wrote the detector — I can't see my own blind spots. The two open cases today are limitations I knew about and seeded myself. The cases I am missing are the ones I do not know about.

Repo: https://github.com/Actenon/actenon-scan
