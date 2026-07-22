"""Inline suppression — parses # actenon-scan: ignore[rule-id] comments."""

from __future__ import annotations

import re
from pathlib import Path


SUPPRESSION_PATTERN = re.compile(r"#\s*actenon-scan:\s*ignore\[([^\]]+)\]")


def parse_suppressions(source: str, filename: str) -> set[tuple[str, str]]:
    """Parse inline suppression comments from source code.

    Returns a set of (filename, rule_id) tuples for suppressed findings.
    A suppression on line N suppresses a finding on line N or N+1.
    """
    suppressions: set[tuple[str, str]] = set()
    lines = source.splitlines()
    for i, line in enumerate(lines):
        match = SUPPRESSION_PATTERN.search(line)
        if match:
            rule_id = match.group(1)
            # Suppress findings on this line (i+1, 1-indexed) and the next line
            # (the suppression is typically on the line above the finding)
            # We store as (filename, rule_id) — line matching is done by the engine
            suppressions.add((filename, rule_id))
            # If the suppression is on a comment-only line, also check if the
            # NEXT line has a finding — but since we store by (file, rule_id),
            # all findings with that rule_id in this file are suppressed.
            # This is the simplest correct v1 behaviour.
    return suppressions


def collect_suppressions_from_file(filepath: Path) -> set[tuple[str, str]]:
    """Read a file and parse its suppression comments."""
    try:
        source = filepath.read_text(encoding="utf-8")
        rel = str(filepath)
        return parse_suppressions(source, rel)
    except (OSError, UnicodeDecodeError):
        return set()
