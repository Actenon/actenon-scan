# Community-Requested Scans

This directory contains scan reports for repositories whose maintainers
have requested a manually reviewed consequential-action scan and consented
to publication.

Each report is a markdown file generated from the scan results and
manually adjudicated findings. Reports use the template in
[TEMPLATE.md](TEMPLATE.md) and the finding-status vocabulary defined in
[DISCLOSURE_POLICY.md](../DISCLOSURE_POLICY.md).

## Finding statuses

| Status | Meaning |
|--------|---------|
| `candidate` | Scanner detected a potential issue. |
| `actenon_reviewed` | Manually reviewed — scanner analysis is structurally correct. |
| `maintainer_confirmed` | Maintainer confirmed the finding. |
| `disputed` | Maintainer disputes the finding; dispute recorded. |
| `false_positive` | Finding confirmed as incorrect. |
| `guard_outside_scope` | Guard exists but was not visible to the scanner. |
| `accepted_risk` | Maintainer acknowledged and decided not to fix. |
| `fixed` | Finding resolved in the codebase. |

## What this is not

- This is not a ranking of projects.
- This is not a vulnerability database.
- This is not a wall of shame.
- Findings are candidate observations from static analysis, not confirmed vulnerabilities.

## Requesting a scan

See [SCAN_ME.md](../SCAN_ME.md) to request a scan. Reports are private
first; publication requires explicit maintainer consent.
