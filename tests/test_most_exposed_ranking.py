"""Regression test for ITEM 1 (v1.1.3 audit): "Most exposed" must prefer
findings with model-controlled inputs over those without.

This test scans the anthropic-sdk-go repo (if cloned) and asserts that
the selected headline finding has non-empty model-controlled inputs.
It fails loudly if the ranking regresses — not as a golden-output
string match that breaks on unrelated copy edits.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def test_most_exposed_has_model_controlled_inputs():
    """The 'Most exposed' finding on anthropic-sdk-go must have
    identified model-controlled inputs.

    Before v1.1.3, the ranking selected skills.go:65 (a constant-path
    delete with NO model-controlled inputs) as the headline, while
    fs.go:243 (os.Rename with a model-controlled `path`) was buried.

    After v1.1.3, the ranking prefers findings WITH model-controlled
    inputs. The headline should be a finding where the model can
    actually influence the sink — not one where the path is constant.

    This test asserts the PROPERTY (headline has inputs), not a specific
    file:line, so it doesn't break on unrelated copy edits.
    """
    # Check if anthropic-sdk-go is cloned at /tmp/anthropic-sdk-go.
    # If not, skip — this test requires a real repo, not a fixture.
    repo = Path("/tmp/anthropic-sdk-go")
    if not repo.exists():
        pytest.skip("anthropic-sdk-go not cloned at /tmp/anthropic-sdk-go")

    # Run the scan.
    result = subprocess.run(
        [sys.executable, "-m", "actenon_scan", "scan", str(repo),
         "--fail-on", "none", "--format", "json"],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, f"scan failed: {result.stderr[:300]}"

    data = json.loads(result.stdout)
    findings = [f for f in data.get("findings", []) if not f.get("suppressed")]
    assert len(findings) > 0, "no findings — repo may have changed"

    # The "Most exposed" finding is the one the pretty reporter would
    # select. We replicate the ranking logic here to find it.
    # The ranking: (has_model_controlled_inputs, severity_rank,
    # confidence_rank, destructive, file, line) — lower is more exposed.
    from actenon_scan.report.blast_radius import _most_exposed_rank, select_most_exposed
    from actenon_scan.engine import Finding

    finding_objs = []
    for f in findings:
        finding_objs.append(Finding(
            file=f["file"], line=f["line"], col=f["col"],
            rule_id=f["rule_id"], category=f["category"],
            severity=f["severity"], confidence=f["confidence"],
            description=f["description"], call_text=f["call_text"],
            remediation=f.get("remediation", ""),
        ))

    most_exposed = select_most_exposed(finding_objs)
    assert most_exposed is not None, "select_most_exposed returned None"

    # The headline finding MUST have model-controlled inputs.
    # This is the PROPERTY we're testing — not a specific file:line.
    from actenon_scan.report.blast_radius import _has_model_controlled_inputs
    assert _has_model_controlled_inputs(most_exposed), (
        f"BLOCKER: the 'Most exposed' finding ({most_exposed.file}:{most_exposed.line} "
        f"{most_exposed.call_text[:50]}) has NO model-controlled inputs. "
        f"A finding the model cannot influence should not be the headline. "
        f"Check _most_exposed_rank in blast_radius.py — the 'has model-controlled "
        f"inputs' criterion must be the FIRST sort key."
    )
