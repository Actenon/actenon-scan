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
        "capability_count": len(result.capabilities),
        "guard_found_count": sum(1 for c in result.capabilities if c.state == "GUARD_FOUND"),
        "review_required_count": sum(1 for c in result.capabilities if c.state == "REVIEW_REQUIRED"),
        "scanned": result.files_scanned,
        "unsupported": {
            "count": len(result.unsupported_files),
            "by_language": dict(unsupported_lang_counts),
            "files": [
                {"file": rel, "language": lang}
                for rel, lang in result.unsupported_files
            ],
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
