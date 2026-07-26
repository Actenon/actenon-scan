"""Pretty (human-readable) report formatter — blast-radius summary.

Work Order 2, Part 1: the default output leads with a map of the
consequential actions an agent can reach without a dominating authority
check. The old linter-style list output is available via ``--format list``.
"""

from __future__ import annotations

import os
import sys
from collections import Counter

from actenon_scan.engine import ScanResult, Finding
from actenon_scan.report.blast_radius import (
    CLEAN_SCAN_LIMITATIONS,
    CLEAN_SCAN_STATEMENT,
    consequence_label,
    group_by_consequence,
    select_most_exposed,
)


def format_pretty(result: ScanResult, *, elapsed: float | None = None) -> str:
    """Format scan results as a blast-radius summary.

    The summary leads with the consequence map, then spotlights the
    most-exposed finding, then lists next-step commands. The old
    linter-style output is available via ``--format list``.
    """
    unsuppressed = [f for f in result.findings if not f.suppressed]

    if not unsuppressed:
        return _format_clean(result, elapsed)

    groups = group_by_consequence(unsuppressed)
    most_exposed = select_most_exposed(unsuppressed)

    lines: list[str] = []

    # Header line — confidence-aware wording (Part 1.1 + RULE 7).
    has_weak = any(f.confidence in ("low", "medium") for f in unsuppressed)
    n = len(unsuppressed)
    action_word = "action" if n == 1 else "actions"
    if has_weak:
        header = (
            f"Your agent can reach {n} consequential {action_word}. "
            f"No dominating authorization check was identified in the analysed path "
            f"for each."
        )
    else:
        header = (
            f"Your agent can reach {n} consequential {action_word} "
            f"without a dominating authorization check."
        )
    lines.append(header)
    lines.append("")

    # Consequence map
    for label, group in groups.items():
        lines.append(f"  {label:14s} {group.count:3d}   {group.method_summary}")

    # Most-exposed spotlight
    if most_exposed is not None:
        lines.append("")
        lines.append(
            f"Most exposed: {most_exposed.file}:{most_exposed.line}  "
            f"{_short_call_name(most_exposed.call_text)}"
        )
        lines.append(f"  Reachable by:              {_decorator_or_function(most_exposed)}")
        lines.append(f"  Consequence:               {consequence_label(most_exposed.category)}")
        lines.append(f"  Guard evidence:            none found on the analysed path")
        params = _extract_params(most_exposed)
        if params:
            lines.append(f"  Model-controlled inputs:   {', '.join(params)}")
        lines.append(f"  Rule:                      {most_exposed.rule_id}")
        lines.append(f"  Severity:                  {most_exposed.severity} (sink match: {most_exposed.confidence})")

    # Summary line
    lines.append("")
    timing = f" ({elapsed:.2f}s)" if elapsed is not None else ""
    lines.append(
        f"{len(unsuppressed)} findings in {result.files_scanned} files{timing}"
    )

    # Next steps
    if most_exposed is not None:
        loc = f"{most_exposed.file}:{most_exposed.line}"
        lines.append("Next:")
        lines.append(f"  actenon-scan explain {loc}")
        lines.append(f"  actenon-scan fix {loc}")

    # Unsupported files warning (preserved from old formatter)
    if result.unsupported_files:
        lines.append("")
        lang_counts = Counter(lang for _, lang in result.unsupported_files)
        lines.append(
            f"  {len(result.unsupported_files)} file(s) NOT scanned — "
            f"unsupported language(s): {dict(lang_counts)}."
        )
        extras = set()
        has_unsupported = False
        for _, lang in result.unsupported_files:
            if "TypeScript" in lang or "JavaScript" in lang:
                extras.add("typescript")
            else:
                has_unsupported = True
        if extras:
            install_hint = " or ".join(f'"actenon-scan[{e}]"' for e in sorted(extras))
            lines.append(f"  Install with:  pip install {install_hint}")
        if has_unsupported:
            lines.append("  actenon-scan parses Python and TypeScript. Other languages are not supported.")

    # Analysis errors (preserved)
    if result.analysis_errors:
        lines.append("")
        lines.append(f"analysis errors: {len(result.analysis_errors)} file(s) skipped")
        for rel, err in result.analysis_errors[:10]:
            lines.append(f"  {rel}: {err}")
        if len(result.analysis_errors) > 10:
            lines.append(f"  ... and {len(result.analysis_errors) - 10} more")

    return "\n".join(lines) + "\n"


def _format_clean(result: ScanResult, elapsed: float | None = None) -> str:
    """Format a clean scan with the honesty statement (Part 1.5)."""
    lines: list[str] = []
    timing = f" ({elapsed:.2f}s)" if elapsed is not None else ""
    lines.append(f"actenon-scan: scanned {result.files_scanned} file(s){timing}.")
    lines.append("")
    lines.append(CLEAN_SCAN_STATEMENT)
    lines.append("")
    lines.append(CLEAN_SCAN_LIMITATIONS)
    lines.append("")

    if result.unsupported_files:
        lang_counts = Counter(lang for _, lang in result.unsupported_files)
        lines.append(
            f"  {len(result.unsupported_files)} file(s) NOT scanned — "
            f"unsupported language(s): {dict(lang_counts)}."
        )
        extras = set()
        has_unsupported = False
        for _, lang in result.unsupported_files:
            if "TypeScript" in lang or "JavaScript" in lang:
                extras.add("typescript")
            else:
                has_unsupported = True
        if extras:
            install_hint = " or ".join(f'"actenon-scan[{e}]"' for e in sorted(extras))
            lines.append(f"  Install with:  pip install {install_hint}")
        if has_unsupported:
            lines.append("  actenon-scan parses Python and TypeScript. Other languages are not supported.")
        lines.append("")

    if result.analysis_errors:
        lines.append(f"  {len(result.analysis_errors)} file(s) errored during analysis.")
        for rel, err in result.analysis_errors[:10]:
            lines.append(f"    {rel}: {err}")
        if len(result.analysis_errors) > 10:
            lines.append(f"    ... and {len(result.analysis_errors) - 10} more")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_list(result: ScanResult) -> str:
    """Format scan results as the old linter-style list (Part 1.6).

    This is the previous default output, available via ``--format list``.
    """
    unsuppressed = [f for f in result.findings if not f.suppressed]

    if not unsuppressed:
        return _format_clean(result)

    by_file: dict[str, list[Finding]] = {}
    for f in unsuppressed:
        by_file.setdefault(f.file, []).append(f)

    lines = []
    lines.append(
        f"actenon-scan: {len(unsuppressed)} finding(s) in {len(by_file)} file(s) "
        f"(scanned {result.files_scanned} file(s))"
    )
    lines.append("")

    for filepath in sorted(by_file):
        lines.append(f"  {filepath}")
        for f in sorted(by_file[filepath], key=lambda x: (x.line, x.rule_id)):
            lines.append(f"    {f.line}:{f.col}  [{f.severity.upper()}] {f.rule_id} ({f.category})")
            lines.append(f"            {f.call_text}")
            lines.append(f"            sink match: {f.confidence}")
            lines.append(f"            {f.remediation}")
            lines.append("")

    if result.analysis_errors:
        lines.append(f"analysis errors: {len(result.analysis_errors)} file(s) skipped")
        for rel, err in result.analysis_errors[:20]:
            lines.append(f"  {rel}: {err}")
        if len(result.analysis_errors) > 20:
            lines.append(f"  ... and {len(result.analysis_errors) - 20} more")
        lines.append("")

    if result.unsupported_files:
        lang_counts = Counter(lang for _, lang in result.unsupported_files)
        lines.append(
            f"unsupported: {len(result.unsupported_files)} file(s) NOT scanned — {dict(lang_counts)}"
        )
        extras = set()
        has_unsupported = False
        for _, lang in result.unsupported_files:
            if "TypeScript" in lang or "JavaScript" in lang:
                extras.add("typescript")
            else:
                has_unsupported = True
        if extras:
            install_hint = " or ".join(f'"actenon-scan[{e}]"' for e in sorted(extras))
            lines.append(f"  Install with:  pip install {install_hint}")
        if has_unsupported:
            lines.append("  actenon-scan parses Python and TypeScript. Other languages are not supported.")
        lines.append("")

    return "\n".join(lines) + "\n"


def _short_call_name(call_text: str) -> str:
    """Extract a short readable name from a call text.

    For chained calls, returns the final method actually being invoked.
    e.g., "g.get_repo(repo).create_file(...)" -> "create_file()"
    """
    from actenon_scan.report.blast_radius import _extract_method_name
    method = _extract_method_name(call_text)
    return method + "()" if method else call_text.strip()


def _decorator_or_function(f: Finding) -> str:
    """Best-effort guess at the entry-point decorator.

    The finding itself doesn't carry the decorator; we'd need the brief/
    explain IR for that. For the summary, we use the file name as a
    hint: if it's in a tools/ directory or has 'tool' in the name,
    we guess @mcp.tool() or @tool(). This is purely presentational.
    """
    # Check if the file path suggests a tool context
    fp = f.file.lower()
    if "tool" in fp or "/mcp" in fp or "/agent" in fp:
        return "@mcp.tool() or @tool"
    return "agent entry point"


def _extract_params(f: Finding) -> list[str]:
    """Extract parameter names from the call text.

    This is a best-effort extraction for the summary. The full
    caller-controlled-parameter analysis lives in the brief/explain IR.
    """
    # Extract arguments from the call text
    if "(" not in f.call_text:
        return []
    paren_start = f.call_text.index("(")
    # Find the matching close paren
    depth = 0
    paren_end = len(f.call_text)
    for i in range(paren_start, len(f.call_text)):
        if f.call_text[i] == "(":
            depth += 1
        elif f.call_text[i] == ")":
            depth -= 1
            if depth == 0:
                paren_end = i
                break
    args_text = f.call_text[paren_start + 1 : paren_end]
    # Split by comma, extract names
    params: list[str] = []
    for arg in args_text.split(","):
        arg = arg.strip()
        if not arg:
            continue
        # Handle keyword args: name=value
        if "=" in arg:
            name = arg.split("=")[0].strip()
            params.append(name)
        else:
            # Positional arg — use the variable name if it's a simple Name
            if arg.isidentifier():
                params.append(arg)
    return params[:6]  # cap at 6 for width
