# Request a consequential-action review

Actenon Scan finds where model-controlled input reaches consequential actions — payments, file deletions, shell commands, database writes, deployments — without a recognised dominating authority check.

You can request a manually reviewed scan of your repository. Reports are **private first**. Publication is optional and requires your consent.

## What the review covers

- Static analysis of Python, TypeScript, and Go source files
- Detection of agent-reachable consequential actions (sinks)
- Guard recognition (whether a dominating authority check exists on the analysed path)
- Manual adjudication of each candidate finding
- A report with: findings, guard evidence, model-controlled inputs, and what the scanner does NOT establish

## What it does not prove

- It does not prove your codebase is secure
- It does not establish that an attacker can externally reach your agent
- It does not verify guards outside the analysed file or supported architecture
- It does not assess runtime behaviour, network configuration, or access control outside the static-analysis scope

## How it works

1. **You request a scan** (using the template below or the [issue form](https://github.com/Actenon/actenon-scan/issues/new?template=scan-request.yml))
2. **Actenon runs a pinned, reproducible scan** — the scanner version and repository commit are recorded
3. **Findings are manually adjudicated** — each candidate is reviewed for reachability, caller control, and guard dominance
4. **You receive the report privately** — with reproduction evidence and what each finding does and does not establish
5. **You may dispute or correct findings** — identify guards, configuration, or architecture the scanner couldn't see
6. **Publication occurs only with your explicit consent** — choose private, anonymised, or named publication
7. **Actenon may offer a non-blocking GitHub Action PR** — only if you consent to it

## What to provide

Copy this template into a [new issue](https://github.com/Actenon/actenon-scan/issues/new?template=scan-request.yml) or email security@actenon.dev for private handling:

```
Repository:
Branch or commit:
Primary languages:
Agent framework:
Relevant directories:
Known guard or authorisation functions:
Configuration file:
Baseline file, if any:
Contact route:
May Actenon open a remediation PR?:
May Actenon open a non-blocking installation PR?:
Publication preference:
- Private
- Anonymised
- Named publication
Additional context:
```

## Important

- Static analysis has limitations. The scanner cannot see guards in middleware, framework interceptors, or runtime configuration. A finding means the scanner did not find a dominating guard on the analysed path — not that no guard exists.
- No guarantee of zero findings or complete coverage is provided.
- The scanner and repository commit will be pinned for reproducibility.
- Manual adjudication is included where capacity allows.

See [DISCLOSURE_POLICY.md](DISCLOSURE_POLICY.md) for the full policy on candidate versus confirmed findings, disputes, and publication.
