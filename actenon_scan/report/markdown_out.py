"""Markdown report formatter — shareable blast-radius report.

Work Order 2, Part 6.3: optimised for GitHub issues, PR descriptions,
Slack/Teams pasting, and design-review documents.
"""

from __future__ import annotations

from collections import Counter

from actenon_scan.engine import ScanResult
from actenon_scan.report.blast_radius import (
    CLEAN_SCAN_LIMITATIONS,
    CLEAN_SCAN_STATEMENT,
    consequence_label,
    group_by_consequence,
    select_most_exposed,
)


def format_markdown(result: ScanResult, *, elapsed: float | None = None) -> str:
    """Format scan results as a compact Markdown report."""
    unsuppressed = [f for f in result.findings if not f.suppressed]
    timing = f" ({elapsed:.2f}s)" if elapsed is not None else ""

    lines: list[str] = []
    lines.append("# Actenon Scan Report")
    lines.append("")
    lines.append(f"**Files scanned:** {result.files_scanned}  ")
    lines.append(f"**Findings:** {len(unsuppressed)}{timing}")
    lines.append("")

    if not unsuppressed:
        lines.append(f"> {CLEAN_SCAN_STATEMENT}")
        lines.append("")
        lines.append("## What this scan verified")
        lines.append("")
        lines.append(
            "Supported source files were parsed and analysed for agent-reachable "
            "consequential actions without a dominating authority check."
        )
        lines.append("")
        lines.append("## What this scan did not verify")
        lines.append("")
        lines.append(
            "Unsupported languages, files outside the scan target, guards outside "
            "the analysed path, external reachability, or practical exploitability. "
            "See `docs/COVERAGE.md` for supported architectures and analysis limits."
        )
        return "\n".join(lines) + "\n"

    groups = group_by_consequence(unsuppressed)
    most_exposed = select_most_exposed(unsuppressed)

    # Blast-radius summary
    lines.append("## Blast-radius summary")
    lines.append("")
    has_weak = any(f.confidence in ("low", "medium") for f in unsuppressed)
    if has_weak:
        lines.append(
            f"Your agent can reach **{len(unsuppressed)} consequential actions**. "
            f"No dominating authorization check was identified in the analysed path."
        )
    else:
        lines.append(
            f"Your agent can reach **{len(unsuppressed)} consequential actions** "
            f"without a dominating authorization check."
        )
    lines.append("")
    lines.append("| Consequence | Count | Methods |")
    lines.append("|---|---|---|")
    for label, group in groups.items():
        lines.append(f"| {label} | {group.count} | {group.method_summary} |")
    lines.append("")

    # Most-exposed spotlight
    if most_exposed is not None:
        lines.append("## Most exposed")
        lines.append("")
        lines.append(f"**{most_exposed.file}:{most_exposed.line}** — `{most_exposed.call_text}`")
        lines.append("")
        lines.append(f"- **Consequence:** {consequence_label(most_exposed.category)}")
        lines.append(f"- **Rule:** `{most_exposed.rule_id}`")
        lines.append(f"- **Severity:** {most_exposed.severity} (confidence: {most_exposed.confidence})")
        lines.append(f"- **Guard evidence:** none found on the analysed path")
        loc = f"{most_exposed.file}:{most_exposed.line}"
        lines.append(f"- **Explain:** `actenon-scan explain {loc}`")
        lines.append(f"- **Fix:** `actenon-scan fix {loc}`")
        lines.append("")

    # Findings by consequence
    lines.append("## Findings by consequence")
    lines.append("")
    for label, group in groups.items():
        lines.append(f"### {label} ({group.count})")
        lines.append("")
        for f in group.findings:
            lines.append(f"- **{f.file}:{f.line}** `{f.rule_id}` — `{f.call_text}`")
            lines.append(f"  - severity: {f.severity}, confidence: {f.confidence}")
        lines.append("")

    # Honesty statement
    lines.append("## What this scan verified / did not verify")
    lines.append("")
    lines.append("**Verified:** supported source files were parsed and analysed for agent-reachable consequential actions without a dominating authority check.")
    lines.append("")
    lines.append("**Not verified:** unsupported languages, files outside the scan target, guards outside the analysed path, external reachability, or practical exploitability.")
    lines.append("")
    lines.append("See `docs/COVERAGE.md` for supported architectures and analysis limits.")

    # Unsupported files
    if result.unsupported_files:
        lines.append("")
        lang_counts = Counter(lang for _, lang in result.unsupported_files)
        lines.append(f"**Note:** {len(result.unsupported_files)} file(s) NOT scanned — unsupported: {dict(lang_counts)}")

    return "\n".join(lines) + "\n"
