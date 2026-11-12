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
from actenon_scan.report.airlock_handoff import AirlockHandoff, format_handoff, target_line
from actenon_scan.report.python_version import python_version_hint
from actenon_scan.report.blast_radius import (
    CLEAN_SCAN_STATEMENT,
    analysis_incomplete_statement,
    clean_scan_limitations,
    consequence_label,
    default_exclude_disclosure_line,
    group_by_consequence,
    is_literal_argument_value,
    select_most_exposed,
    transitive_disclosure_line,
)


def format_pretty(
    result: ScanResult,
    *,
    elapsed: float | None = None,
    command: str = "actenon-scan",
    handoff: AirlockHandoff | None = None,
    scan_target: str | os.PathLike[str] | None = None,
) -> str:
    """Format scan results as a blast-radius summary.

    The summary leads with the consequence map, then spotlights the
    most-exposed finding, then lists next-step commands. The old
    linter-style output is available via ``--format list``.

    Work Order 2, Phase 6: when capabilities are available, the output
    includes a capability summary showing guard-found vs review-required
    counts. The existing finding-based output is preserved for backward
    compatibility.

    ``command`` is how the user should invoke the scanner in the printed
    next steps (``uvx actenon-scan`` when run through uvx). ``handoff`` is
    the Airlock runtime-protection handoff for the most-exposed finding,
    when Scan's authority evidence shows Airlock can act on it. ``scan_target`` is the path the user
    scanned, as typed; with it, analysis errors caused by running on an older Python than the
    project's ``requires-python`` get a rerun line (see :mod:`actenon_scan.report.python_version`).
    """
    unsuppressed = [f for f in result.findings if not f.suppressed]
    python_hint = python_version_hint(result.analysis_errors, scan_target, command=command)

    # Work Order 2, Phase 6: capability summary.
    # Displayed when capabilities exist, before the finding-based output.
    if result.capabilities:
        cap_lines = _format_capability_summary(result)
        if not unsuppressed:
            # All capabilities are GUARD_FOUND — no findings to report
            cap_lines.append("")
            timing = f" ({elapsed:.2f}s)" if elapsed is not None else ""
            cap_lines.append(f"{result.files_scanned} files scanned{timing}")
            # No other part of the all-guarded summary lists files that
            # failed to parse, so list them here, not only the count.
            incomplete = _incomplete_lines(result, list_files=True)
            cap_lines.extend(incomplete)
            # Under the failed files, as on the clean and findings paths.
            if incomplete and python_hint is not None:
                cap_lines.append(f"  {python_hint}")
            if result.unsupported_files:
                cap_lines.append("")
                cap_lines.extend(_format_unsupported(result))
            # Task 5-A1: also surface the transitive-reachability
            # disclosure line on the all-guarded clean scan, so users
            # with capabilities-but-no-findings still see which
            # agent-reachable calls the repo layer proved reachable
            # vs. could not resolve. Omitted when the layer was
            # disabled (--no-repository-analysis).
            disclosure = transitive_disclosure_line(result)
            if disclosure is not None:
                cap_lines.append("")
                cap_lines.append(disclosure)
            return "\n".join(cap_lines) + "\n"
        # Has both capabilities and findings — show capability summary
        # then the existing blast-radius output
        lines = cap_lines
        lines.append("")
    else:
        lines = []

    if not unsuppressed:
        return _format_clean(result, elapsed, python_hint=python_hint)

    groups = group_by_consequence(unsuppressed)
    most_exposed = select_most_exposed(unsuppressed)

    # Note: lines may already contain capability summary from above.
    # If not, start fresh.
    if not lines:
        lines = []

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
        if handoff is not None:
            lines.append(f"  Target:                    {target_line(handoff)}")
        lines.append(f"  Guard evidence:            {_guard_evidence_summary(most_exposed)}")
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
    # The failed files themselves are listed under "analysis errors" below.
    lines.extend(_incomplete_lines(result, list_files=False))

    # Next steps
    if most_exposed is not None:
        loc = f"{most_exposed.file}:{most_exposed.line}"
        lines.append("Next:")
        explain_cmd = f"{command} explain {loc}"
        fix_cmd = f"{command} fix {loc}"
        if handoff is None:
            lines.append(f"  {explain_cmd}")
            lines.append(f"  {fix_cmd}")
        else:
            # Two remediation options: Scan's repository-native guard is the
            # default; Airlock is the optional runtime alternative below.
            width = max(len(explain_cmd), len(fix_cmd))
            lines.append(f"  {explain_cmd.ljust(width)}  # show the analysed path")
            lines.append(f"  {fix_cmd.ljust(width)}  # default remediation: a repository-native guard")
            lines.append("")
            lines.extend(format_handoff(handoff))

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
        if python_hint is not None:
            lines.append(f"  {python_hint}")

    # Task 1b: transitive-reachability disclosure. MUST appear in the
    # findings case too — a directory scan with findings still has
    # unfollowed transitive edges that are NOT in the findings list.
    # The user needs to know how many agent-reachable calls the repo
    # layer could not resolve, so they can audit them manually.
    disclosure = transitive_disclosure_line(result)
    if disclosure is not None:
        lines.append("")
        lines.append(disclosure)

    # Phase 3.3 (D10): default-exclude disclosure. Files excluded by
    # default patterns must be disclosed.
    exclude_disclosure = default_exclude_disclosure_line(result)
    if exclude_disclosure is not None:
        lines.append("")
        lines.append(exclude_disclosure)

    return "\n".join(lines) + "\n"


def _format_unsupported(result: ScanResult) -> list[str]:
    """The NOT-scanned notice for files in languages Scan cannot analyse.

    Used by the all-guarded capability summary, which previously called
    this helper without it existing (a NameError for any repository whose
    capabilities were all guarded and which contained an unsupported file).
    """
    lines: list[str] = []
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


def _format_clean(
    result: ScanResult, elapsed: float | None = None, *, python_hint: str | None = None
) -> str:
    """Format a clean scan with the honesty statement (Part 1.5).

    ``python_hint`` is printed under the analysis errors (see ``format_pretty``).
    """
    lines: list[str] = []
    timing = f" ({elapsed:.2f}s)" if elapsed is not None else ""
    lines.append(f"actenon-scan: scanned {result.files_scanned} file(s){timing}.")
    lines.append("")
    lines.append(CLEAN_SCAN_STATEMENT)
    # Right under the "nothing found" line, so it cannot be read alone.
    lines.extend(_incomplete_lines(result, list_files=False))
    lines.append("")
    lines.append(clean_scan_limitations(result))
    lines.append("")
    # Task 5-A1: transitive-reachability disclosure. Only rendered when
    # the repo layer actually ran (``repository_analysis_enabled=True``).
    # When the user passed ``--no-repository-analysis``, the line is
    # omitted entirely to preserve the pre-5-A1 output shape for
    # backwards compat with output parsers (verification step 5).
    disclosure = transitive_disclosure_line(result)
    if disclosure is not None:
        lines.append(disclosure)
        lines.append("")

    # Phase 3.3 (D10): default-exclude disclosure in clean-scan too.
    exclude_disclosure = default_exclude_disclosure_line(result)
    if exclude_disclosure is not None:
        lines.append(exclude_disclosure)
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
        if python_hint is not None:
            lines.append(f"  {python_hint}")
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
    # Analysis errors are listed at the end; state the gap up front too.
    statement = analysis_incomplete_statement(result)
    if statement is not None:
        lines.append(statement)
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

    # Task 1b: transitive disclosure in list format too.
    disclosure = transitive_disclosure_line(result)
    if disclosure is not None:
        lines.append(disclosure)
        lines.append("")

    return "\n".join(lines) + "\n"


def _incomplete_lines(result: ScanResult, *, list_files: bool) -> list[str]:
    """The ANALYSIS INCOMPLETE statement (and optionally the failed files), or nothing.

    Starts with a blank separator line. ``list_files`` is for report paths
    that do not list analysis errors anywhere else.
    """
    statement = analysis_incomplete_statement(result)
    if statement is None:
        return []
    lines = ["", statement]
    if list_files:
        for rel, err in result.analysis_errors[:10]:
            lines.append(f"  {rel}: {err}")
        if len(result.analysis_errors) > 10:
            lines.append(f"  ... and {len(result.analysis_errors) - 10} more")
    return lines


def _short_call_name(call_text: str) -> str:
    """Extract a short readable name from a call text.

    For chained calls, returns the final method actually being invoked.
    e.g., "g.get_repo(repo).create_file(...)" -> "create_file()"
    """
    from actenon_scan.report.blast_radius import _extract_method_name
    method = _extract_method_name(call_text)
    return method + "()" if method else call_text.strip()


def _guard_evidence_summary(f: Finding) -> str:
    """Summarize guard evidence honestly for the spotlight section."""
    rid = f.rule_id or ""
    reason = f.reachability_reason or ""
    if rid.endswith("-WEAK"):
        return "guard call found, but return value is discarded (-WEAK)"
    if rid.endswith("-UNBOUND"):
        return "guard call found, but not parameter/action-bound to sink (-UNBOUND)"
    if "does NOT authorize" in reason:
        return "non-authorizing check found (authentication/validation does not authorize this action)"
    return "none found on the analysed path"


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
        # Phase 4: distinguish resource_boundary (HTTP route) from
        # model-callable entry points. A resource_boundary signal means
        # the function is an externally-callable HTTP endpoint, NOT a
        # model-callable entry point. Saying "agent entry point" for
        # an HTTP route is false — the model may or may not be the
        # caller.
        if "resource_boundary" in reason:
            return "HTTP route handler (resource boundary)"
        if "same_class_method" in reason or "local_call" in reason:
            return "transitive local call"
        if "dynamic_registration" in reason:
            return "dynamic tool registration"
        if reason.startswith("transitive:"):
            chain = reason[len("transitive:"):].split(" [", 1)[0].strip()
            return f"transitive call ({chain})"
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

    Phase 4: only report identifiers that look like function parameters
    (simple names), NOT string literals or complex expressions. A SQL
    string literal like "UPDATE runs SET status = ?" must NOT appear
    as a "Model-controlled input".
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
        if "=" in arg and not arg.startswith(("'", '"', "[")):
            name, _, value = arg.partition("=")
            name = name.strip()
            # A constant value (branch="main") is not model-controlled.
            if is_literal_argument_value(value):
                continue
            # Only report if the kwarg name looks like it could carry
            # model-controlled data (not 'api_key', 'max_results', etc.)
            # But we don't know which are constants without deeper analysis.
            # Report the kwarg name — it's better than the literal value.
            params.append(name)
        else:
            # Positional arg — only report if it's a simple identifier
            # (a variable name), NOT a string literal or expression.
            # String literals start with quotes; expressions have operators.
            if arg.isidentifier() and not arg.startswith(("'", '"')):
                params.append(arg)
    return params[:6]  # cap at 6 for width
