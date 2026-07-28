"""Work Order 2, Phase 9 — Tests for version coherence and corpus figure drift.

Tests:
  1. check_version_coherence: all 4 conditions (match, bump-no-tag, tag-no-publish, rollback)
  2. Corpus figure drift: FINDINGS.md and CORPUS_RESULTS.md agree with corpus-triage.json
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from actenon_scan.version_check import check_version_coherence

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH = REPO_ROOT / "tests" / "benchmark"


# ---------------------------------------------------------------------------
# Item 2: verify-claims case 3 (tag exists, PyPI doesn't)
# ---------------------------------------------------------------------------

def test_version_match_passes():
    ok, msg = check_version_coherence("1.3.1", "1.3.1", tag_exists=True)
    assert ok is True
    assert "match" in msg


def test_version_bump_no_tag_passes():
    """pyproject > pypi, no tag — normal between merge and tag push."""
    ok, msg = check_version_coherence("1.4.0", "1.3.1", tag_exists=False)
    assert ok is True
    assert "unpublished" in msg


def test_tag_exists_no_publish_fails():
    """pyproject > pypi, tag exists — publish failed. This is case 3."""
    ok, msg = check_version_coherence("1.4.0", "1.3.1", tag_exists=True)
    assert ok is False
    assert "tag" in msg.lower()
    assert "failed" in msg.lower() or "may have failed" in msg


def test_pypi_newer_than_pyproject_fails():
    """pypi > pyproject — rollback, yank, or drift."""
    ok, msg = check_version_coherence("1.3.0", "1.3.1", tag_exists=False)
    assert ok is False
    assert "rollback" in msg.lower() or "drift" in msg.lower() or "newer" in msg.lower()


# ---------------------------------------------------------------------------
# Phase 9: corpus figure drift check
# ---------------------------------------------------------------------------

def _get_triage_totals() -> dict:
    """Get the canonical precision figure from corpus-triage.json."""
    triage = json.loads((BENCH / "corpus-triage.json").read_text())
    return triage.get("totals", {})


def test_findings_md_matches_triage():
    """FINDINGS.md must not state a precision figure that disagrees with triage."""
    triage = _get_triage_totals()
    tp = triage.get("true_positives", 0)
    fp = triage.get("false_positives", 0)
    total = tp + fp

    findings_text = (REPO_ROOT / "FINDINGS.md").read_text()

    # Check for stale precision strings that should not appear
    # in non-historical context
    stale_strings = [
        "21/21", "22/22", "28/28", "30/30",
        "0 FP = 100%", "21 TP / 0 FP",
        "22 TP / 0 FP", "100% precision",
    ]
    historical_markers = [
        "was", "previously", "originally", "revised", "corrected",
        "historical", "frozen", "v0.4.0", "After these fixes",
        "→", "lineage", "Step", "Initial", "Self-correction",
        "revised downward", "precision figure was", "annotated",
        "transient", "gate pressure",
    ]

    for line_num, line in enumerate(findings_text.split("\n"), 1):
        for stale in stale_strings:
            if stale not in line:
                continue
            is_historical = any(m in line for m in historical_markers)
            if is_historical:
                continue
            pytest.fail(
                f"FINDINGS.md:{line_num} contains stale precision '{stale}': "
                f"{line.strip()[:100]}. "
                f"corpus-triage.json says {tp}/{total}."
            )


def test_corpus_results_md_matches_triage():
    """CORPUS_RESULTS.md must not state a precision figure that disagrees with triage."""
    triage = _get_triage_totals()
    tp = triage.get("true_positives", 0)
    fp = triage.get("false_positives", 0)

    text = (REPO_ROOT / "docs" / "CORPUS_RESULTS.md").read_text()

    # The current figure comment must match
    current_correct = f"{tp} TP / {fp} FP"
    if "current figure" in text.lower():
        # Find the line with "current figure"
        for line in text.split("\n"):
            if "current figure" in line.lower():
                if str(tp) not in line or str(fp) not in line:
                    pytest.fail(
                        f"CORPUS_RESULTS.md 'current figure' line doesn't match triage. "
                        f"Line: {line.strip()}. Expected: {current_correct}"
                    )


# ---------------------------------------------------------------------------
# Item 6: corpus study category rendering regression test
# ---------------------------------------------------------------------------

def test_corpus_study_categories_not_concatenated():
    """The Categories line must not concatenate the count with the list."""
    text = (REPO_ROOT / "docs" / "CORPUS_STUDY.md").read_text()
    for line in text.split("\n"):
        if line.startswith("- **Categories:**"):
            # Must not have a pattern like "4 9 framework" (count immediately
            # followed by another number with only a space)
            import re
            # The old bug: "4 9 framework" — len(cat_counts)=4 followed by
            # the first entry "9 framework" with no separator
            if re.search(r'\*\*\s*\d+\s+\d+\s', line):
                pytest.fail(
                    f"Categories line has concatenated counts: {line}. "
                    f"The category count and the list must be separated."
                )
            return
    pytest.fail("Categories line not found in CORPUS_STUDY.md")
