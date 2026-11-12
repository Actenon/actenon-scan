"""Baseline — load, compare, and suppress known findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_baseline(findings: list[dict[str, Any]], output_path: str | Path) -> None:
    """Write findings to a baseline JSON file."""
    baseline: dict[str, Any] = {"version": "1", "findings": findings}
    Path(output_path).write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")


def load_baseline(baseline_path: str | Path) -> dict[str, set[str]]:
    """Load a baseline file and return a dict mapping filename -> set of baseline keys.

    The baseline is matched on ``(file, rule_id, snippet_hash)`` — resilient to
    line-number drift while avoiding cross-rule suppression on the same line.
    Legacy baseline entries without ``rule_id`` store ``snippet_hash`` directly.
    """
    data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    result: dict[str, set[str]] = {}
    for finding in data.get("findings", []):
        filename = finding.get("file", "")
        snippet_hash = finding.get("snippet_hash", "")
        rule_id = finding.get("rule_id", "")
        if filename and snippet_hash:
            entry = f"{rule_id}:{snippet_hash}" if rule_id else snippet_hash
            result.setdefault(filename, set()).add(entry)
    return result


def is_in_baseline(
    baseline_findings: dict[str, set[str]] | None,
    filename: str,
    rule_id: str,
    snippet_hash: str,
) -> bool:
    """Return True if ``(filename, rule_id, snippet_hash)`` matches a baseline entry."""
    if not baseline_findings or not snippet_hash:
        return False
    file_baselines = baseline_findings.get(filename)
    if not file_baselines:
        return False
    if f"{rule_id}:{snippet_hash}" in file_baselines:
        return True
    if snippet_hash in file_baselines:
        return True
    return False
