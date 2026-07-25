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

- **Total findings:** 30
- **True positives (hand-triaged):** 30
- **False positives:** 0

### By consequence category

| Category | Count |
|---|---|
| unknown | 30 |

### By rule

| Rule | Count |
|---|---|
| NET-EGRESS | 15 |
| FILE-OPEN-WRITE | 6 |
| EXEC-SHELL | 3 |
| COMMUNICATION-SEND | 2 |
| DATA-DELETE-OS | 2 |
| FILE-WRITE | 1 |
| DATA-DELETE-SQL | 1 |

### By repository

| Repository | Findings |
|---|---|
| crewAIInc/crewAI | 12 |
| TransformerOptimus/SuperAGI | 6 |
| FoundationAgents/MetaGPT | 5 |
| microsoft/semantic-kernel | 3 |
| agno-agi/agno | 2 |
| modelcontextprotocol/servers | 1 |
| modelcontextprotocol/python-sdk | 1 |

## The false-positive rate

This is the most valuable section. A tool that publishes its own initial
false-positive rate and names the failure classes is trusted by security
engineers in a way that a tool claiming 100% never is.

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

### Current measurement: 30/30 (100% precision)

After fixes, the current corpus has 30 findings,
all hand-triaged as TRUE_POSITIVE. Zero false positives. This is the number
that gates CI — `check_corpus_triage.py` fails if any FALSE_POSITIVE is
present or any finding is untriaged.

The corpus grew from 18 to 25 repos (7 more added). The false-positive
count stayed at zero because each new finding was hand-triaged before merge.

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

