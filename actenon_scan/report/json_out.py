"""JSON report formatter."""

from __future__ import annotations

import json
from collections import Counter

from actenon_scan.engine import ScanResult


def format_json(result: ScanResult) -> str:
    """Format scan results as JSON."""
    # Work Order 1.5: include the scanner version at the top level so any
    # JSON output is attributable to a specific release. This makes it
    # possible to tell which scanner version produced a given results.json
    # without inspecting the Action logs.
    try:
        from actenon_scan import __version__ as scanner_version
    except ImportError:
        scanner_version = "unknown"

    findings = [
        {
            "file": f.file,
            "line": f.line,
            "col": f.col,
            "rule_id": f.rule_id,
            "category": f.category,
            "severity": f.severity,
            "effective_severity": f.effective_severity,
            "confidence": f.confidence,
            "description": f.description,
            "call_text": f.call_text,
            "remediation": f.remediation,
            "snippet_hash": f.snippet_hash,
            "suppressed": f.suppressed,
            "suppression_reason": f.suppression_reason,
            "tier": f.tier,
        }
        for f in result.findings
        if not f.suppressed
    ]
    # Count by tier
    production_count = sum(1 for f in findings if f["tier"] == "production")
    example_count = sum(1 for f in findings if f["tier"] == "example")

    # Per-language counts for unsupported files
    unsupported_lang_counts = Counter(lang for _, lang in result.unsupported_files)

    output = {
        # Work Order 1.5: top-level scanner version for output attribution.
        "scanner": "actenon-scan",
        "version": scanner_version,
        "findings": findings,
        # Work Order 2, Phase 4: capability surface alongside findings.
        # Every agent-reachable consequential sink, including guarded ones.
        # Findings remain the subset requiring review (REVIEW_REQUIRED).
        "capabilities": [
            {
                "file": c.file,
                "line": c.line,
                "col": c.col,
                "rule_id": c.rule_id,
                "category": c.category,
                "severity": c.severity,
                "call_text": c.call_text,
                "state": c.state,
                "guard_status": c.guard_status,
                "guard_message": c.guard_message,
                "confidence": c.confidence,
                "reachability_reason": c.reachability_reason,
                "reachability_source": c.reachability_source,
                "tier": c.tier,
                "language": c.language,
            }
            for c in result.capabilities
        ],
        # Counts come from capability_summary, which deduplicates by call site
        # and resolves each site's state against the FINAL findings. Counting
        # the raw capability list here instead meant json reported
        # review_required_count 87 beside finding_count 85 — the same
        # inconsistency the text output had, in the format that machines read.
        "capability_count": len(result.capabilities),
        "guard_found_count": result.capability_summary.guard_found,
        "review_required_count": result.capability_summary.review_required,
        "accepted_decision_count": result.capability_summary.accepted_decision,
        # The headline number: distinct call sites, deduplicated by sink.
        # Equal to review_required_count by construction.
        "consequential_action_count": result.consequential_action_count,
        # Unsuppressed Findings, NOT deduplicated — one call site matched by
        # two rules appears twice here and once above. Two reasons to look at
        # one action.
        "rule_match_count": result.rule_match_count,
        "scanned": result.files_scanned,
        "unsupported": {
            "count": len(result.unsupported_files),
            "by_language": dict(unsupported_lang_counts),
            "files": [
                {"file": rel, "language": lang}
                for rel, lang in result.unsupported_files
            ],
        },
        # Analysis coverage. Machine-readable counterpart to the disclosure
        # printed in the text formats. A consumer that reads finding_count
        # without reading this is reading a floor as if it were a total.
        "analysis_coverage": {
            "followed_edges": result.analysis_coverage[0],
            "unfollowed_edges": result.analysis_coverage[1],
            "percent_followed": (
                round(result.analysis_coverage[2], 1)
                if result.analysis_coverage[2] is not None else None
            ),
            "_meaning": (
                "Call edges from agent-reachable code into functions defined "
                "in the same file. This is analysis coverage, not safety "
                "coverage: it says how much of the call structure was "
                "examined, not how much of the code is protected."
            ),
            "unfollowed_calls": [
                {
                    "file": e.file,
                    "line": e.line,
                    "col": e.col,
                    "caller": e.caller,
                    "callee": e.callee,
                    "reason": e.reason,
                }
                for e in result.unfollowed_local_calls
            ],
        },
        # Findings in actenon-scan's own vulnerable test fixtures, held aside
        # rather than reported. Counted here so a machine consumer sees the
        # same decision the text output states rather than an unexplained
        # difference between two runs.
        "excluded_fixtures": {
            "count": len(result.excluded_fixture_findings),
            "reason": "actenon-scan's own test fixtures",
            "show_with": "--include-fixtures",
            "files": sorted({f.file for f in result.excluded_fixture_findings}),
        },
        "errored": {
            "count": len(result.analysis_errors),
            "files": [
                {"file": rel, "error": err}
                for rel, err in result.analysis_errors
            ],
        },
        # Keep legacy keys for backward compatibility
        "files_scanned": result.files_scanned,
        "finding_count": len(findings),
        "production_count": production_count,
        "example_count": example_count,
        # Per-file analysis errors caught by the defensive wrapper.
        # Surface these so users see what got skipped — a non-empty list
        # means part of the repo wasn't actually scanned.
        "analysis_errors": [
            {"file": rel, "error": err}
            for rel, err in result.analysis_errors
        ],
        # Field semantics: the "confidence" field on each finding measures
        # REACHABILITY confidence — how confident the scanner is that the
        # sink is agent-reachable (i.e., inside a @tool or @mcp.tool
        # decorated function). It does NOT measure guard confidence —
        # whether the sink is unguarded. A finding with confidence: "high"
        # means "I'm confident this is an agent-reachable sink", not
        # "I'm confident this is unguarded." Guard analysis is separate
        # and produces WEAK/UNBOUND suffixes on the rule_id when the
        # guard is imperfect.
        "_confidence_meaning": "sink-match (not guard) confidence; see docs",
    }
    return json.dumps(output, indent=2) + "\n"
