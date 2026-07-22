"""SARIF 2.1.0 report formatter for GitHub code scanning integration."""

from __future__ import annotations

import json

from actenon_scan.engine import ScanResult


SEVERITY_TO_LEVEL = {
    "low": "note",
    "medium": "warning",
    "high": "error",
}


def format_sarif(result: ScanResult) -> str:
    """Format scan results as SARIF 2.1.0 JSON."""
    # Build rules array (unique by rule_id)
    rules_seen: dict[str, dict] = {}
    for f in result.findings:
        if f.suppressed:
            continue
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.description},
                "fullDescription": {"text": f.remediation},
                "defaultConfiguration": {"level": SEVERITY_TO_LEVEL.get(f.severity, "warning")},
                "properties": {
                    "category": f.category,
                    "severity": f.severity,
                    "precision": "high" if f.confidence == "high" else "medium",
                },
            }

    # Build results array
    results = []
    for f in result.findings:
        if f.suppressed:
            continue
        results.append({
            "ruleId": f.rule_id,
            "level": SEVERITY_TO_LEVEL.get(f.effective_severity, "warning"),
            "message": {"text": f"{f.description}. {f.remediation}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.col + 1,  # SARIF is 1-indexed
                        },
                    }
                }
            ],
            "partialFingerprints": {"primaryLocationLineHash": f.snippet_hash},
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "actenon-scan",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Actenon/actenon-scan",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"
