# OWASP Agent Control Standard Working Group — Draft Post

> Draft text for posting to the OWASP Agent Control Standard working
> group. Paste the body below into the forum post composer. Matter-of-
> fact, no marketing. Honest about scan's limitations.

**Suggested title:** Request for adversarial review — actenon-scan soundness challenge

---

I built a static analyzer for AI-agent execution gaps. It refuses to claim "clean". I'm asking for adversarial help.

**The instrument.** Actenon Scan is a per-file static analyzer for Python, TypeScript, and Go. It finds places where model-controlled input reaches a consequential action — a payment, a file deletion, a shell command, a database write, an email send, a deployment — without a dominating authority guard on the analysed path. It matches against ~145 guard patterns (vendor-neutral: OAuth, JWT, OPA, Casbin, Cedar, plus Actenon-specific) and recognises agent tool boundaries including the MCP `@mcp.tool` decorator, LangChain `@tool` and `BaseTool` subclasses, OpenAI `@function_tool`, and CrewAI tools. A clean scan means "no supported consequential-action paths were identified" — never "the codebase is safe." The full boundary of what it does and does not verify is published at https://github.com/Actenon/actenon-scan/blob/main/docs/COVERAGE.md and pinned by CI.

Three honest limitations matter for an adversarial reviewer:

- **Per-file analysis by default.** A guard in a caller does not protect a sink in a callee unless `--repository-analysis` is enabled. Codebases that centralise authorization at a dispatch layer produce false positives on the per-file scan.
- **No detection of custom agent loops or action/observation dispatchers.** Both are recorded as NOT COVERED in the coverage contract. The candidate strategy for custom agent loops was measured and rejected — 10/10 false positives on a 9-repo hand-triage.
- **Unsupported languages are reported as unsupported, never as clean.** Rust, Java, C#, Ruby, PHP are out of scope. That is the contract.

**The ask.** I have 2 open soundness challenges, both self-submitted, zero fixed. I'd like 10 external ones. The template is at https://github.com/Actenon/actenon-scan/blob/main/community-scans/CHALLENGE_TEMPLATE.md. Submissions get a public scoreboard entry and a permanent regression test when fixed. The scoreboard lives at https://github.com/Actenon/actenon-scan/blob/main/docs/SOUNDNESS_CHALLENGE.md.

**The honest incentive.** External submissions are worth more than another sprint of my own tests because I wrote the detector — I can't see my own blind spots. The two open cases today (a constant-path delete flagged as a finding; a missing `os.Chmod` sink) are limitations I knew about and seeded myself. The cases I am missing are the ones I do not know about.

Repo: https://github.com/Actenon/actenon-scan
