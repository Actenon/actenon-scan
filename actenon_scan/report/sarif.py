"""SARIF 2.1.0 report formatter for GitHub code scanning integration."""

from __future__ import annotations

import json
from typing import Any

from actenon_scan import __version__
from actenon_scan.engine import ScanResult


SEVERITY_TO_LEVEL = {
    "low": "note",
    "medium": "warning",
    "high": "error",
}

# Canonical base URL for per-rule documentation. SARIF `helpUri` on each
# rule points here with a `#<rule-id-lowercased>` anchor. GitHub's
# Security tab renders this as the "Learn more" link.
DOCS_BASE_URL = "https://github.com/Actenon/actenon-scan/blob/main/docs/COVERAGE.md"


def _rule_help_uri(rule_id: str) -> str:
    """Per-rule documentation URL.

    COVERAGE.md uses lowercased rule IDs as anchors (e.g.
    `#pay-stripe-refund`). GitHub's renderer accepts this form.
    """
    return f"{DOCS_BASE_URL}#{rule_id.lower()}"


def _rule_tags(rule_id: str, cwe: str, owasp: str) -> list[str]:
    """Build a SARIF `properties.tags` array for a rule.

    GitHub's Security tab uses tags for filtering and dashboards. We
    include `security` and `ai-agent` on every rule, plus `cwe-<n>` and
    `owasp-<id>` when the rule declares them in default_rules.json.
    """
    tags = ["security", "ai-agent"]
    if cwe:
        # Normalise "CWE-862" -> "cwe-862".
        tags.append(cwe.lower().replace(" ", "-"))
    if owasp:
        # Normalise "LLM06" -> "owasp-llm06".
        tags.append(f"owasp-{owasp.lower()}")
    return tags


def _build_rule_entry(finding, ruleset) -> dict[str, Any]:
    """Build a SARIF rule entry, enriching the finding with CWE/OWASP
    metadata from the ruleset when available."""
    # Look up the rule in the ruleset to pull cwe/owasp fields.
    cwe = ""
    owasp = ""
    if ruleset is not None:
        for sink in ruleset.sinks:
            if sink.id == finding.rule_id:
                cwe = sink.cwe or ""
                owasp = sink.owasp or ""
                break

    entry: dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.description},
        "fullDescription": {"text": finding.remediation},
        "helpUri": _rule_help_uri(finding.rule_id),
        "defaultConfiguration": {"level": SEVERITY_TO_LEVEL.get(finding.severity, "warning")},
        "properties": {
            "category": finding.category,
            "severity": finding.severity,
            "precision": "high" if finding.confidence == "high" else "medium",
            "tags": _rule_tags(finding.rule_id, cwe, owasp),
        },
    }
    if cwe:
        entry["properties"]["cwe"] = cwe
    if owasp:
        entry["properties"]["owasp"] = owasp
    return entry


def format_sarif(result: ScanResult) -> str:
    """Format scan results as SARIF 2.1.0 JSON."""
    ruleset = result.rules_used
    # Build rules array (unique by rule_id)
    rules_seen: dict[str, dict] = {}
    for f in result.findings:
        if f.suppressed:
            continue
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = _build_rule_entry(f, ruleset)

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
                        "version": __version__,
                        "informationUri": "https://github.com/Actenon/actenon-scan",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"
