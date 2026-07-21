"""JSON report formatter."""

from __future__ import annotations

import json
from dataclasses import asdict

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
        }
        for f in result.findings
        if not f.suppressed
    ]
    output = {
        "findings": findings,
        "files_scanned": result.files_scanned,
        "finding_count": len(findings),
    }
    return json.dumps(output, indent=2) + "\n"
