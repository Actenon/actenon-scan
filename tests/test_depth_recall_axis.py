"""Recall is reported per hop depth, and the misses are recorded.

A single recall number hid the thing that most determines whether a sink is
found: how far it sits from the entry point. The depth axis makes that
visible, and it makes the improvement from same-module one-hop following
measurable rather than asserted.

depth2 and crossfile are EXPECTED FAILURES. They are not deleted and not
softened to make a number green — the recorded miss is the purpose of the
file. Each one also produces a disclosed unfollowed call, so the tool says
out loud where it stopped.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path

REPO = Path(__file__).resolve().parent.parent
DEPTH_DIR = REPO / "tests" / "benchmark" / "recall" / "depth"
BASELINE = REPO / "tests" / "benchmark" / "baseline.json"

FAMILIES = ("net_egress", "exec_shell", "data_delete_sql")


def _findings(target: Path) -> list:
    return [f for f in scan_path(target).findings if not f.suppressed]


@pytest.mark.parametrize("family", FAMILIES)
def test_depth0_is_found(family):
    assert _findings(DEPTH_DIR / f"{family}_depth0.py")


@pytest.mark.parametrize("family", FAMILIES)
def test_depth1_is_found(family):
    """The whole point of same-module one-hop following."""
    assert _findings(DEPTH_DIR / f"{family}_depth1.py")


@pytest.mark.parametrize("family", FAMILIES)
def test_depth2_is_missed_and_the_stop_is_disclosed(family):
    """Following is non-transitive, so this is missed — and says so.

    The disclosure is the assertion that matters. An earlier version of the
    coverage figure reported "1 followed, 0 not followed (100.0%)" on this
    exact fixture: a perfect coverage number over a miss. The second hop is
    now counted as an unfollowed edge.
    """
    result = scan_path(DEPTH_DIR / f"{family}_depth2.py")
    assert [f for f in result.findings if not f.suppressed] == []
    reasons = [e.reason for e in result.unfollowed_local_calls]
    assert "depth_limit" in reasons, reasons
    followed, unfollowed, pct = result.analysis_coverage
    assert unfollowed >= 1
    assert pct < 100.0, "a missed second hop must not read as full coverage"


@pytest.mark.parametrize("family", FAMILIES)
def test_crossfile_is_missed_and_the_stop_is_disclosed(family):
    result = scan_path(DEPTH_DIR / f"{family}_crossfile")
    assert [f for f in result.findings if not f.suppressed] == []
    assert [e.reason for e in result.unfollowed_local_calls] == ["cross_file"]


def test_baseline_records_recall_per_depth_not_as_a_scalar():
    baseline = json.loads(BASELINE.read_text())
    by_depth = baseline["recall_by_depth"]
    assert set(by_depth) == {"depth0", "depth1", "depth2", "crossfile"}
    assert by_depth["depth0"] == {"pass": 3, "total": 3, "expected_fail": False}
    assert by_depth["depth1"] == {"pass": 3, "total": 3, "expected_fail": False}
    assert by_depth["depth2"] == {"pass": 0, "total": 3, "expected_fail": True}
    assert by_depth["crossfile"] == {"pass": 0, "total": 3, "expected_fail": True}


def test_recorded_depths_match_what_the_scanner_actually_does():
    """The baseline is a record of behaviour, not an aspiration."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "benchmark", REPO / "scripts" / "benchmark.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    measured = mod.run_depth_benchmark()
    recorded = json.loads(BASELINE.read_text())["recall_by_depth"]
    for depth, rec in recorded.items():
        assert measured[depth]["pass"] == rec["pass"], (
            f"{depth}: baseline records {rec['pass']}/{rec['total']}, "
            f"scanner does {measured[depth]['pass']}/{measured[depth]['total']}"
        )


def test_every_family_has_all_four_depths():
    """No family may quietly skip the depth where it does badly."""
    for family in FAMILIES:
        for depth in ("depth0", "depth1", "depth2"):
            assert (DEPTH_DIR / f"{family}_{depth}.py").is_file(), family
        crossfile = DEPTH_DIR / f"{family}_crossfile"
        assert crossfile.is_dir()
        assert (crossfile / "tool_entry.py").is_file()
        assert len(list(crossfile.glob("*.py"))) == 2
