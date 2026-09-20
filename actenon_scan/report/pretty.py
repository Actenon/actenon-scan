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
    render_clean_scan_limitations,
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

    Work Order 2, Phase 6: when capabilities are available, the output
    includes a capability summary showing guard-found vs review-required
    counts. The existing finding-based output is preserved for backward
    compatibility.
    """
    unsuppressed = [f for f in result.findings if not f.suppressed]

    # Work Order 2, Phase 6: capability summary.
    # Displayed when capabilities exist, before the finding-based output.
    if result.capabilities:
        cap_lines = _format_capability_summary(result)
        if not unsuppressed:
            # All capabilities are GUARD_FOUND — no findings to report
            cap_lines.append("")
            timing = f" ({elapsed:.2f}s)" if elapsed is not None else ""
            cap_lines.append(f"{result.files_scanned} files scanned{timing}")
            disclosure = format_unfollowed_calls(result, indent="  ")
            if disclosure:
                cap_lines.append("")
                cap_lines.extend(disclosure)
            excluded = format_excluded_fixtures(result, indent="  ")
            if excluded:
                cap_lines.append("")
                cap_lines.extend(excluded)
            if result.unsupported_files:
                cap_lines.append("")
                cap_lines.extend(_format_unsupported(result))
            return "\n".join(cap_lines) + "\n"
        # Has both capabilities and findings — show capability summary
        # then the existing blast-radius output
        lines = cap_lines
        lines.append("")
    else:
        lines = []

    if not unsuppressed:
        return _format_clean(result, elapsed)

    groups = group_by_consequence(unsuppressed)
    most_exposed = select_most_exposed(unsuppressed)

    # Note: lines may already contain capability summary from above.
    # If not, start fresh.
    if not lines:
        lines = []

    # Header line — confidence-aware wording (Part 1.1 + RULE 7).
    has_weak = any(f.confidence in ("low", "medium") for f in unsuppressed)
    # Deduplicated by call site: a line matched by two rules is one action
    # with two reasons. This is the same number the capability summary above
    # reports as "Review required" and the same one the summary line below
    # reports, which they previously were not.
    n = result.consequential_action_count
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
    # The headline is a floor, not a total, whenever a call was stepped over.
    # It must not stand alone while that is true, so the count is attached to
    # the sentence itself rather than left to a footnote further down.
    n_unfollowed = len(result.unfollowed_local_calls)
    if n_unfollowed:
        call_word = "call" if n_unfollowed == 1 else "calls"
        was_were = "was" if n_unfollowed == 1 else "were"
        header += (
            f" That is a floor, not a total: {n_unfollowed} {call_word} into "
            f"locally-defined functions {was_were} not followed."
        )
    lines.append(header)
    lines.append("")

    # Consequence map. Counts are per consequence type, so one call site
    # matched by rules in two categories appears in both rows. The column
    # then sums to more than the headline, which reads as a discrepancy
    # unless it is named.
    for label, group in groups.items():
        lines.append(f"  {label:14s} {group.count:3d}   {group.method_summary}")
    map_total = sum(group.count for group in groups.values())
    if map_total != n:
        lines.append(
            f"  (rows sum to {map_total}: {map_total - n} action(s) carry more "
            f"than one consequence type)"
        )

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

    # Unfollowed-call disclosure (A2/A3)
    disclosure = format_unfollowed_calls(result, indent="  ")
    if disclosure:
        lines.append("")
        lines.extend(disclosure)

    excluded = format_excluded_fixtures(result, indent="  ")
    if excluded:
        lines.append("")
        lines.extend(excluded)

    # Summary line. The action count leads; the rule-match count is named
    # separately when it differs, never silently substituted for it.
    lines.append("")
    timing = f" ({elapsed:.2f}s)" if elapsed is not None else ""
    matches = result.rule_match_count
    file_word = "file" if result.files_scanned == 1 else "files"
    summary = (
        f"{n} consequential {action_word} in {result.files_scanned} "
        f"{file_word}{timing}"
    )
    if matches != n:
        summary += f" ({matches} rule matches)"
    lines.append(summary)

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
            elif "Go" in lang:
                extras.add("go")
            else:
                has_unsupported = True
        if extras:
            install_hint = " or ".join(f'"actenon-scan[{e}]"' for e in sorted(extras))
            lines.append(f"  Install with:  pip install {install_hint}")
        if has_unsupported:
            lines.append("  actenon-scan parses Python, TypeScript, and Go. Other languages are not supported.")

    # Analysis errors (preserved)
    if result.analysis_errors:
        lines.append("")
        lines.append(f"analysis errors: {len(result.analysis_errors)} file(s) skipped")
        for rel, err in result.analysis_errors[:10]:
            lines.append(f"  {rel}: {err}")
        if len(result.analysis_errors) > 10:
            lines.append(f"  ... and {len(result.analysis_errors) - 10} more")

    return "\n".join(lines) + "\n"


def format_excluded_fixtures(result: ScanResult, *, indent: str = "") -> list[str]:
    """One line stating how many findings were held aside, and how to see them.

    Held aside, not dropped. A scan that quietly removed findings would be
    making exactly the kind of undisclosed decision this tool exists to
    surface — the count and the flag are both printed so the reader can
    check the judgement rather than take it.
    """
    n = len(result.excluded_fixture_findings)
    if not n:
        return []
    return [
        f"{indent}{n} finding(s) in actenon-scan's own test fixtures were "
        f"excluded; --include-fixtures to show"
    ]


def format_unfollowed_calls(
    result: ScanResult, *, indent: str = "", include_summary: bool = True
) -> list[str]:
    """The unfollowed-call disclosure, rendered for every text output path.

    The analysis is per-function. A sink in a helper that an entry point
    calls is not reported, and before this block existed nothing in the
    output said so — a scan of such code printed CLEAN. This is the
    correction: a partial scan has to say it was partial, in every format,
    on clean runs as much as on runs with findings.

    Returns [] when there is nothing to disclose, so a scan that followed
    every edge it found prints no apology it does not owe.
    """
    edges = result.unfollowed_local_calls
    followed, unfollowed, pct = result.analysis_coverage
    if not edges and not followed:
        return []

    lines: list[str] = []
    if edges:
        n = len(edges)
        if include_summary:
            call_word = "call" if n == 1 else "calls"
            was_were = "was" if n == 1 else "were"
            lines.append(
                f"{indent}{n} {call_word} from agent-reachable code into "
                f"locally-defined functions {was_were} not followed; sinks "
                f"reached only through them are not reported."
            )
        for e in edges[:10]:
            lines.append(
                f"{indent}  {e.file}:{e.line}  {e.caller}() -> {e.callee}()  "
                f"[{e.reason}]"
            )
        if n > 10:
            lines.append(f"{indent}  ... and {n - 10} more")
    if pct is not None:
        # Counts first, percentage second. The pair is what is observed; the
        # percentage is a convenience derived from it, and leading with the
        # percentage would invite it to be quoted on its own.
        lines.append(
            f"{indent}Call edges from agent-reachable code: {followed} followed, "
            f"{unfollowed} not followed ({pct:.1f}%). This is analysis coverage — "
            f"how much of the call structure was examined. It is not a measure "
            f"of how safe this code is."
        )
    return lines


def _format_capability_summary(result: ScanResult) -> list[str]:
    """Format the capability summary for the blast-radius output.

    Work Order 2, Phase 6: shows the total capabilities and their
    breakdown by state (GUARD_FOUND, REVIEW_REQUIRED, etc.).
    Uses observational language — never asserts safety.
    """
    summary = result.capability_summary
    lines: list[str] = []
    lines.append("YOUR AGENT'S BLAST RADIUS")
    lines.append("")
    lines.append(f"Consequential capabilities: {summary.total}")
    if summary.guard_found:
        lines.append(f"  Guard found on path:       {summary.guard_found}")
    if summary.review_required:
        lines.append(f"  Review required:           {summary.review_required}")
    if summary.accepted_decision:
        lines.append(f"  Accepted decision:         {summary.accepted_decision}")
    if summary.not_analysed:
        lines.append(f"  Not analysed:              {summary.not_analysed}")
    return lines


def _format_clean(result: ScanResult, elapsed: float | None = None) -> str:
    """Format a clean scan with the honesty statement (Part 1.5)."""
    lines: list[str] = []
    timing = f" ({elapsed:.2f}s)" if elapsed is not None else ""
    lines.append(f"actenon-scan: scanned {result.files_scanned} file(s){timing}.")
    lines.append("")
    lines.append(CLEAN_SCAN_STATEMENT)
    lines.append("")
    lines.append(render_clean_scan_limitations(len(result.unfollowed_local_calls)))
    lines.append("")

    # The count is already in the limitations block above; this adds the
    # per-call detail and the coverage pair without repeating it.
    disclosure = format_unfollowed_calls(result, indent="  ", include_summary=False)
    if disclosure:
        lines.extend(disclosure)
        lines.append("")

    excluded = format_excluded_fixtures(result, indent="  ")
    if excluded:
        lines.extend(excluded)
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
            elif "Go" in lang:
                extras.add("go")
            else:
                has_unsupported = True
        if extras:
            install_hint = " or ".join(f'"actenon-scan[{e}]"' for e in sorted(extras))
            lines.append(f"  Install with:  pip install {install_hint}")
        if has_unsupported:
            lines.append("  actenon-scan parses Python, TypeScript, and Go. Other languages are not supported.")
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
    n_actions = result.consequential_action_count
    matches = result.rule_match_count
    # The list format enumerates findings, so its count is the finding count
    # and stays labelled that way. When a call site is matched by more than
    # one rule the two numbers diverge, and both are then named rather than
    # one standing in for the other.
    if matches == n_actions:
        header = (
            f"actenon-scan: {matches} finding(s) in {len(by_file)} file(s) "
            f"(scanned {result.files_scanned} file(s))"
        )
    else:
        header = (
            f"actenon-scan: {n_actions} consequential action(s), "
            f"{matches} finding(s) in {len(by_file)} file(s) "
            f"(scanned {result.files_scanned} file(s))"
        )
    lines.append(header)
    lines.append("")

    for filepath in sorted(by_file):
        lines.append(f"  {filepath}")
        for f in sorted(by_file[filepath], key=lambda x: (x.line, x.rule_id)):
            lines.append(f"    {f.line}:{f.col}  [{f.severity.upper()}] {f.rule_id} ({f.category})")
            lines.append(f"            {f.call_text}")
            lines.append(f"            sink match: {f.confidence}")
            lines.append(f"            {f.remediation}")
            lines.append("")

    disclosure = format_unfollowed_calls(result)
    if disclosure:
        lines.extend(disclosure)
        lines.append("")

    excluded = format_excluded_fixtures(result)
    if excluded:
        lines.extend(excluded)
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
            elif "Go" in lang:
                extras.add("go")
            else:
                has_unsupported = True
        if extras:
            install_hint = " or ".join(f'"actenon-scan[{e}]"' for e in sorted(extras))
            lines.append(f"  Install with:  pip install {install_hint}")
        if has_unsupported:
            lines.append("  actenon-scan parses Python, TypeScript, and Go. Other languages are not supported.")
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
    """Best-effort guess at the entry-point decorator / reachability reason.

    For Go findings, the detector populates ``f.reachability_reason`` with
    the actual criterion that matched (agent_framework_import,
    tool_registration, or both). We render that directly — no guessing.

    For Python findings, the finding doesn't carry the decorator (we'd
    need the brief/explain IR for that). We fall back to a file-path hint:
    if it's in a tools/ directory or has 'tool' in the name, we guess
    @mcp.tool() or @tool(). This path-guess is ONLY applied to .py files —
    applying it to .go/.ts files would display Python decorator syntax
    while reporting on a different language, which is the precise
    impression the Go/TS support exists to correct.

    For TypeScript findings, reachability_reason is currently empty (the
    TS detector doesn't track it). We return a generic "agent entry point"
    rather than guessing Python syntax.
    """
    # Go findings: use the real reachability reason from the detector.
    if f.reachability_reason:
        reason = f.reachability_reason
        if "tool_registration" in reason:
            return "tool registration (AddTool/RegisterTool)"
        if "agent_framework_import" in reason:
            return "agent framework import"
        return reason

    # Python findings: path-based guess (only for .py files).
    if f.file.endswith(".py"):
        fp = f.file.lower()
        if "tool" in fp or "/mcp" in fp or "/agent" in fp:
            return "@mcp.tool() or @tool"
        return "agent entry point"

    # TypeScript/other: don't guess Python syntax.
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
