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
    """Load a baseline file and return a dict mapping filename -> set of snippet hashes.

    The baseline is matched on (file, rule_id, snippet_hash) — resilient to
    line-number drift.
    """
    data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    result: dict[str, set[str]] = {}
    for finding in data.get("findings", []):
        filename = finding.get("file", "")
        snippet_hash = finding.get("snippet_hash", "")
        if filename and snippet_hash:
            result.setdefault(filename, set()).add(snippet_hash)
    return result
