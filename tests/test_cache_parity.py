"""A cache hit must describe the file exactly as a fresh scan would.

RULE 5 in this project is that the cache never changes findings. Two ways it
did, both surfaced by the A4 reconciliation — which is the point of making
the printed numbers agree: a contradiction that used to be invisible now
fails loudly.

1. Capabilities were never cached at all. A warm cache reported the findings
   while the capability summary counted only the files that happened to miss:
   "Consequential capabilities: 5" printed directly above "can reach 87
   consequential actions".

2. A cache hit reset every finding's suppression state and re-applied only
   the baseline and inline suppressions, dropping declarative-guard
   suppression. A cached scan therefore REPORTED findings a fresh scan
   suppresses — the cache changing findings, in the false-positive direction.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from actenon_scan.cache import FileCache
from actenon_scan.engine import scan_path

REPO = Path(__file__).resolve().parent.parent
DECLARATIVE_GUARD_SAFE = REPO / "tests" / "corpus" / "DECLARATIVE-GUARD" / "safe"

TOOL_WITH_SINK = '''from agents import tool
import subprocess


@tool
def run_it(cmd):
    subprocess.run(cmd, shell=True)
'''

ONE_HOP = '''from agents import tool
import requests


@tool
def publish(data):
    send(data)


def send(data):
    requests.post("https://example.com", json=data)
'''


@pytest.fixture
def cached_pair(tmp_path: Path):
    """Scan the same tree twice through one cache; return (fresh, cached)."""
    def run(write_tree):
        tree = tmp_path / "tree"
        tree.mkdir()
        write_tree(tree)
        cache = FileCache(tmp_path / "cache")
        return scan_path(tree, cache=cache), scan_path(tree, cache=cache)
    return run


def test_declarative_guard_suppression_survives_a_cache_hit(tmp_path: Path):
    """A cached scan must not report what a fresh scan suppresses."""
    tree = tmp_path / "tree"
    shutil.copytree(DECLARATIVE_GUARD_SAFE, tree)
    cache = FileCache(tmp_path / "cache")
    fresh = scan_path(tree, cache=cache)
    cached = scan_path(tree, cache=cache)

    assert fresh.rule_match_count == 0
    assert cached.rule_match_count == 0
    assert [
        (f.line, f.suppression_reason) for f in cached.findings if f.suppressed
    ] == [
        (f.line, f.suppression_reason) for f in fresh.findings if f.suppressed
    ]


def test_capabilities_survive_a_cache_hit(cached_pair):
    fresh, cached = cached_pair(
        lambda t: (t / "a.py").write_text(TOOL_WITH_SINK)
    )
    assert len(cached.capabilities) == len(fresh.capabilities)
    assert cached.capability_summary == fresh.capability_summary


def test_the_headline_numbers_still_agree_on_a_warm_cache(cached_pair):
    """The A4 invariant must hold on the second run, not only the first."""
    fresh, cached = cached_pair(
        lambda t: (t / "a.py").write_text(TOOL_WITH_SINK)
    )
    for result in (fresh, cached):
        assert (
            result.capability_summary.review_required
            == result.consequential_action_count
        )
    assert cached.consequential_action_count == fresh.consequential_action_count


def test_unfollowed_calls_and_coverage_survive_a_cache_hit(cached_pair):
    fresh, cached = cached_pair(
        lambda t: (t / "a.py").write_text(ONE_HOP)
    )
    assert cached.analysis_coverage == fresh.analysis_coverage


def test_a_baseline_added_between_runs_still_takes_effect(tmp_path: Path):
    """The reset exists for user-supplied suppression; that must still work."""
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.py").write_text(TOOL_WITH_SINK)
    cache = FileCache(tmp_path / "cache")

    first = scan_path(tree, cache=cache)
    assert first.rule_match_count == 1
    hashes = {f.file: {f.snippet_hash} for f in first.findings}

    second = scan_path(tree, cache=cache, baseline_findings=hashes)
    assert second.rule_match_count == 0
    assert all(f.suppressed for f in second.findings)
