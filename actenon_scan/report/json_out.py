"""JSON report formatter."""

from __future__ import annotations

import json
from collections import Counter

from actenon_scan.engine import ScanResult


def format_json(result: ScanResult) -> str:
    """Format scan results as JSON."""
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
        "findings": findings,
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
    }
    return json.dumps(output, indent=2) + "\n"
