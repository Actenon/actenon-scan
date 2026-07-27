# Disclosure and Review Policy

## Scope

This policy applies to:

- Maintainer-requested scans (via [SCAN_ME.md](SCAN_ME.md))
- Independently identified findings
- Public corpus research (published in [docs/CORPUS_STUDY.md](docs/CORPUS_STUDY.md))
- Published Community-Requested Scans (in [community-scans/](community-scans/))

## Candidate versus confirmed

Scanner output is a **candidate finding**, not a confirmed vulnerability. Every finding carries one of the following statuses:

| Status | Meaning |
|--------|---------|
| `candidate` | Scanner detected a potential issue. Not yet reviewed by a human. |
| `actenon_reviewed` | An Actenon reviewer has manually inspected the code path and confirmed the scanner's detection is structurally correct. This is NOT independent security verification — it means the scanner's analysis is sound, not that the finding is exploitable. |
| `maintainer_confirmed` | The repository maintainer has confirmed the finding represents a real risk in their codebase. |
| `disputed` | The maintainer has disputed the finding. The dispute is recorded with evidence. |
| `false_positive` | The finding was confirmed as incorrect (e.g., a guard exists outside the analysed scope, the sink is not model-controlled, or the detection logic was wrong). |
| `guard_outside_scope` | A dominating guard exists but was not visible to the scanner (e.g., in middleware, a decorator on a parent class, or a framework-level interceptor). The finding is not a false positive, but the scanner's analysis is incomplete. |
| `accepted_risk` | The maintainer has acknowledged the finding and decided not to fix it. The finding remains visible. |
| `fixed` | The finding has been resolved in the codebase. |

"Actenon reviewed" is **not** equivalent to independent confirmation. It means the scanner's analysis is structurally correct — the sink exists, the path is reachable, and no guard was found on the analysed path. It does not establish that an attacker can exploit the finding.

## Private-first process

For requested scans:

1. **Findings are delivered privately first.** The maintainer receives the full report before any publication decision.
2. **Reproduction evidence** is included: the exact commit, scanner version, command, and output.
3. **Right of reply.** The maintainer may identify configuration, guards, or architecture outside the analysed scope that the scanner could not see.
4. **Corrections.** The report is corrected where evidence supports correction. False positives are removed. Guard-outside-scope findings are reclassified.
5. **No automatic publication.** The report is not published without explicit consent.

## Publication consent

For requested scans:

- **Named publication** requires explicit consent from the maintainer.
- Publication is **not required** to receive the review. A maintainer may choose private-only.
- The maintainer may choose: **private** (report delivered, not published), **anonymised** (published without repo name), or **named** (published with full attribution).
- Publication status is recorded in the scan report.
- Findings may be updated with corrections and resolution status after publication.

## Disputes

- A maintainer may dispute any finding by responding to the report or opening an issue.
- Disputes should include: the finding ID, the reason for dispute, and any evidence (guards, architecture, configuration).
- Disputed findings are marked `disputed` in the report and on the scoreboard.
- Corrections are published when evidence supports them.
- Historical changes are recorded: the original finding, the dispute, and the correction are all visible.

## Language rules

In all Actenon Scan documentation, reports, and communications:

- **Do not** use "vulnerability" without supporting evidence. A scanner candidate is a "finding" or "candidate finding."
- **Do not** use CVE language unless a CVE has been assigned.
- **Do not** use "secure" as a binary certification. The absence of findings does not mean the codebase is secure.
- **Do not** use "passed" to mean absence of risk. A clean scan means no supported consequential-action paths were identified — not that the codebase is safe.
- **Do not** use public shaming language. Findings are technical observations, not moral judgments.

## Research

Aggregate corpus research may be published without seeking permission from every repository when based on public code, but:

- Repository-specific claims must be reproducible (exact commit, scanner version, command).
- Uncertainty must be stated.
- Candidate findings must not be presented as confirmed.
- Corrections must be published when errors are found.
- Maintainers must have an accessible response route (issue, email, or discussion).
