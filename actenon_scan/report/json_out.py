"""JSON report formatter."""

from __future__ import annotations

import json

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
    output = {
        "findings": findings,
        "files_scanned": result.files_scanned,
        "finding_count": len(findings),
        "production_count": production_count,
        "example_count": example_count,
    }
    return json.dumps(output, indent=2) + "\n"
