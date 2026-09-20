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


def _markdown_unfollowed(result) -> list[str]:
    """The unfollowed-call disclosure as Markdown.

    Present in both the clean and the with-findings branch: a partial scan
    misleads as much as a clean one, and the Markdown report is what lands
    in a PR comment where nobody re-runs the tool to check.
    """
    edges = result.unfollowed_local_calls
    followed, unfollowed, pct = result.analysis_coverage
    if not edges and not followed:
        return []
    lines: list[str] = ["", "## Analysis coverage", ""]
    if edges:
        n = len(edges)
        call_word = "call" if n == 1 else "calls"
        was_were = "was" if n == 1 else "were"
        lines.append(
            f"**{n} {call_word}** from agent-reachable code into "
            f"locally-defined functions {was_were} not followed; sinks reached "
            f"only through them are not reported."
        )
        lines.append("")
        lines.append("| Location | Call | Not followed because |")
        lines.append("| --- | --- | --- |")
        for e in edges[:20]:
            lines.append(
                f"| `{e.file}:{e.line}` | `{e.caller}()` -> `{e.callee}()` | "
                f"`{e.reason}` |"
            )
        if n > 20:
            lines.append(f"| ... and {n - 20} more | | |")
        lines.append("")
    if pct is not None:
        lines.append(
            f"**Call edges from agent-reachable code:** {followed} followed, "
            f"{unfollowed} not followed ({pct:.1f}%)."
        )
        lines.append("")
        lines.append(
            "This is *analysis coverage* — how much of the call structure was "
            "examined. It is not a measure of how safe this code is."
        )
    return lines


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
            "See [docs/COVERAGE.md](https://github.com/Actenon/actenon-scan/blob/main/docs/COVERAGE.md) for supported architectures and analysis limits."
        )
        lines.extend(_markdown_unfollowed(result))
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
    lines.append("See [docs/COVERAGE.md](https://github.com/Actenon/actenon-scan/blob/main/docs/COVERAGE.md) for supported architectures and analysis limits.")

    lines.extend(_markdown_unfollowed(result))

    # Unsupported files
    if result.unsupported_files:
        lines.append("")
        lang_counts = Counter(lang for _, lang in result.unsupported_files)
        lines.append(f"**Note:** {len(result.unsupported_files)} file(s) NOT scanned — unsupported: {dict(lang_counts)}")

    return "\n".join(lines) + "\n"
