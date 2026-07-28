# Actenon Scan Corpus Study

> This document is generated from `tests/benchmark/corpus-triage.json`
> by `scripts/generate_corpus_study.py`. Do not edit by hand.
> Run `python scripts/generate_corpus_study.py --check` in CI to
> verify it is current.

## What was scanned

- **Repos:** 25 pinned by immutable commit SHA
- **Files:** 23,476 (21,308 Python, 2,168 TypeScript)
- **Categories:** 4 9 framework, 7 application, 5 control, 4 mcp_server

## Methodology

**What "consequential action reachable without an authorization check" means:**

The scanner parses each source file, identifies calls to recognised
consequential sinks (payments, repository mutations, shell execution,
data destruction, email, deployment, etc.), and checks whether the
call is:

1. **Agent-reachable** — inside a function decorated with `@mcp.tool`,
   `@tool`, `@function_tool`, or a recognised agent framework entry point.
2. **Unguarded** — no dominating authority check (guard call, proof
   verification, or declarative guard) is found on the analysed path
   between the entry point and the sink.
3. **Model-controlled** — at least one parameter of the sink call
   derives from the tool function's signature (the model controls it).

A finding means: *a model-controlled parameter reaches a recognised
consequential action, and no dominating authority check was identified
in the analysed path.* It does **not** mean the finding is a vulnerability.

## Findings

- **Total findings:** 22
- **True positives (hand-triaged):** 21
- **False positives:** 1

### By consequence category

| Category | Count |
|---|---|
| unknown | 22 |

### By rule

| Rule | Count |
|---|---|
| NET-EGRESS | 9 |
| FILE-OPEN-WRITE | 6 |
| COMMUNICATION-SEND | 2 |
| DATA-DELETE-OS | 2 |
| FILE-WRITE | 1 |
| EXEC-SHELL | 1 |
| NET-EGRESS-GO | 1 |

### By repository

| Repository | Findings |
|---|---|
| crewAIInc/crewAI | 8 |
| TransformerOptimus/SuperAGI | 6 |
| FoundationAgents/MetaGPT | 5 |
| modelcontextprotocol/servers | 1 |
| modelcontextprotocol/python-sdk | 1 |
| github/github-mcp-server | 1 |

## The false-positive rate

This is the most valuable section. A tool that publishes its own initial
false-positive rate and names the failure classes is trusted by security
engineers in a way that a tool claiming 100% never is.

### Full count lineage

The corpus figure has changed five times. Each transition is recorded
with the reason, so a reader can see the trajectory rather than a bare
number that changed again.

| Step | Count | Reason |
|---|---|---|
| Initial scan (18 repos) | 63 raw → 51 true positive | 12 false positives across 3 failure classes (DEPLOY-K8S pattern too loose, DATA-DELETE-SQL missed variable SQL, s3.delete_objects not in vocabulary). All 3 fixed. |
| Corpus grew to 25 repos | 30 true positive | 7 new repos added; new findings hand-triaged before merge. |
| agno correction (2026-07-26) | 30 → 28 | 2 agno findings reclassified: `@tool(external_execution=True)` is agno's human-in-the-loop primitive, a framework-level guard. Scanner now recognises the flag. |
| crewai/semantic-kernel correction (2026-07-26) | 28 → 21 | 7 findings reclassified: guarded by validation methods (`_validate_query`, `validate_url`, etc.) that dominate the sink and are bound to the model-controlled parameter. Scanner now recognises validation-method names as guards. |
| TS guard rewrite + github-mcp-server Go triage (2026-07-27) | 21→22 TP, precision 100% (transient) | WO1.5 rewrote the TS guard detector. server.go:286 suppressed by rule fix. actions.go:172 reclassified to TRUE_POSITIVE under gate pressure (later corrected). |
| Gate fix + actions.go reclassification (2026-07-29) | 22→21 TP, precision 100% → 95.5% | WO1.10 fixed the gate to allow recording unfixed FPs. actions.go:172 reclassified back to FALSE_POSITIVE (recorded, issue #81) on the merits: function is not a tool handler, URL is not directly model-controlled. The WO1.9 reclassification was made under gate pressure, not on the merits. |

### Initial measurement: 51/63 (81% precision)

The initial corpus scan across the first 18 pinned repositories produced
63 raw findings. Hand triage identified 12 false positives (51 true
positives, 63 total = 81% precision). Three distinct failure classes
were identified and fixed:

1. **DEPLOY-K8S false positive on `client.search.create`** — the pattern
   `client.*.create` was too loose and matched Elasticsearch search clients.
   Fixed by constraining the pattern to genuine Kubernetes surfaces
   (kubectl, kubernetes client, `create_namespaced_*`).

2. **DATA-DELETE-SQL matched literal but missed variable SQL** — the rule
   only matched literal `execute("DROP TABLE")` strings, missing the more
   dangerous caller-controlled `execute(query)` form. Fixed by matching
   the sink method rather than the literal text.

3. **s3.delete_objects not detected** — the boto3 `delete_objects` method
   was not in the sink vocabulary. Fixed by adding it to the DATA-DELETE-OBJ
   rule's qualified patterns.

### Current measurement: 21/22 (95% precision)

After fixes, the current corpus has 21 findings,
all hand-triaged as TRUE_POSITIVE. Zero false positives. This is the number
that gates CI — `check_corpus_triage.py` fails if any FALSE_POSITIVE is
present or any finding is untriaged.

The corpus grew from 18 to 25 repos (7 more added). The false-positive
count stayed at zero because each new finding was hand-triaged before merge.

### Self-correction: 2 agno findings reclassified (30 → 28)

During outreach preparation, 2 findings in `agno-agi/agno` were found to
be false positives. The findings were on `@tool(external_execution=True)`
decorated functions — agno's human-in-the-loop primitive that hands the
tool call back to a human rather than auto-executing it. The scanner
originally treated these as unguarded; after recognising the
`external_execution=True` flag as a framework-level guard, the findings
no longer fire. The correction was made by the project itself, before
any maintainer was contacted. A study that publishes a corrected number
with the reason stated is more credible than one that never moved.

## What the scanner cannot see

### The r05 negative result: custom agent loops

The custom agent loop strategy (a function that runs whatever the LLM
returns, without a framework decorator) was rejected after detection-only
pre-triage on a 9-repo corpus. It produced 10/10 false positives across
autogen wsbridge, agno A2A, semantic-kernel process routing, and OpenHands
integrations. The dominant category was framework message-passing
plumbing — `send_message` on internal event buses — which the heuristic
matched because the signal decomposes into "module talks to an LLM" and
"function runs what it was passed", which describes most of an agent
framework. This is recorded as a useful negative result: the pattern is
too broad without interprocedural dataflow analysis.

### Architectures at NOT COVERED

The following architectures are NOT COVERED by the scanner:
- Custom agent loops without framework decorators (r05)
- Action/observation dispatchers without recognised entry points (r06)
- Raw tool-schema dispatch (r07 — active but produces zero candidates)

### The PCCB limitation

Actenon's own guard pattern (PCCB proof verification) does not exhibit
syntactic parameter binding — the binding is cryptographic, inside the
PCCB object. The scanner's guard-dominance analysis cannot verify this
binding statically. This is an argument FOR the runtime kernel: the
scanner can identify where a proof check is missing, but only the kernel
can enforce that the proof actually binds the right parameters at runtime.

## Control repositories

Five non-agent libraries are pinned as controls. Any finding in a control
repo is a precision failure by definition. All five remain at zero:

| Control repo | Files | Findings |
|---|---|---|
| requests | 37 | 0 |
| flask | 83 | 0 |
| fastapi | 1130 | 0 |
| click | 78 | 0 |
| rich | 213 | 0 |

## Reproduction

```bash
# Clone actenon-scan
git clone https://github.com/Actenon/actenon-scan.git
cd actenon-scan
pip install -e ".[typescript,yaml]"

# Verify the corpus triage is consistent
python scripts/check_corpus_triage.py

# Run the benchmark (precision, soundness, recall)
python scripts/benchmark.py

# Scan a specific pinned repo (download separately)
# actenon-scan scan /path/to/repo --format json --fail-on none
```

The pinned repository list with commit SHAs is in
[`tests/benchmark/pinned_repos.json`](../tests/benchmark/pinned_repos.json).

## Regeneration

This document is generated by:
```bash
python scripts/generate_corpus_study.py
```
CI verifies it is current:
```bash
python scripts/generate_corpus_study.py --check
```

## Scanner version

- **Measured with:** actenon-scan 1.4.0
- **Measurement date:** 2026-07-29

The corpus is a measurement taken with a specific scanner version. When
the scanner's analysis changes materially, the corpus must be re-measured.
CI verifies that the recorded scanner version is not older than the
current package version — if it is, the check fails and prompts a
re-measurement decision rather than allowing silent drift.

## TypeScript guard analysis coverage

Before v1.2.1, TypeScript guard analysis was lexical: any guard-pattern
word appearing on any line in the file suppressed every sink below it,
regardless of function boundary, dominance, binding, or result-use. A
comment mentioning "authorize", a string literal containing
"unauthorized", or a variable named `authorizeButton` suppressed every
sink below it in that file. This was unsound.

v1.2.1 replaced the lexical heuristic with strict dominance, binding,
and result-use analysis (640 lines ported from the Python and Go
detectors). The rewrite was exercised on:

- TS files in corpus: 2311
- TS sink candidates: 140
- TS sinks that reached guard analysis: 1

The corpus has 1 TS sink candidate that reached guard analysis. The
rewrite was validated by fixtures and by real-world TS repos
(modelcontextprotocol/typescript-sdk, langchain-ai/langchainjs,
getzep/zep-js), not by the corpus itself. The 3 appeared findings in
the MCP TypeScript SDK are FALSE_POSITIVE at the rule-matching level
(NET-EGRESS matches `handler.fetch()`, an MCP handler entry point, not
outbound egress), not at the guard level. The guard rewrite correctly
removed the false-negative lexical suppression.

Also worth noting: 2,168 TS files yielding 1 sink candidate suggests
TS reachability may be narrow. This is recorded as a coverage
limitation, not a soundness issue.

