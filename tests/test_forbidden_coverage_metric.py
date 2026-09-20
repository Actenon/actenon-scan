"""No output may divide findings by an ESTIMATE of total consequential actions.

The only permitted coverage figure is analysis coverage: followed call edges
over followed-plus-unfollowed call edges. Both terms are directly observed.

Anything of the form "authority coverage", "% of actions protected" or
"% safe" needs a denominator this tool does not have — the total number of
consequential actions in the code. That number is unknown by exactly the
amount `unfollowed_local_calls` reports. A percentage built on it would read
as reassurance and would bury the disclosure it silently depends on.

This test exists because the number is tempting: it is the figure a reader
asks for, and the pressure to invent one does not go away.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path
from actenon_scan.report.html_out import format_html
from actenon_scan.report.json_out import format_json
from actenon_scan.report.markdown_out import format_markdown
from actenon_scan.report.pretty import format_list, format_pretty
from actenon_scan.report.sarif import format_sarif

#: Phrases that must never appear at all — there is no innocent use.
FORBIDDEN_PHRASES = (
    "authority coverage",
    "% of actions protected",
    "percent of actions protected",
    "actions protected",
    "protection coverage",
    "risk coverage",
    "% guarded",
    "% covered by a guard",
)

#: Phrases that appear legitimately in a DENIAL ("this is not safety
#: coverage") but never legitimately as a measurement. Banned only when a
#: number sits next to them, which is what turns a phrase into a metric.
FORBIDDEN_AS_METRIC = (
    "safety coverage",
    "safe",
    "protected",
    "secure",
)

_NEAR_NUMBER = 16

SAMPLE = '''from agents import tool
import requests


@tool
def publish(data):
    relay(data)


@tool
def direct(data):
    requests.post("https://example.com/upload", json=data)


def relay(data):
    requests.post("https://example.com/relay", json=data)
'''


@pytest.fixture
def scanned(tmp_path: Path):
    (tmp_path / "sample.py").write_text(SAMPLE)
    return scan_path(tmp_path)


@pytest.mark.parametrize(
    "formatter",
    [format_pretty, format_list, format_markdown, format_html, format_json,
     format_sarif],
    ids=["pretty", "list", "markdown", "html", "json", "sarif"],
)
def test_no_output_path_publishes_a_safety_percentage(scanned, formatter):
    lowered = formatter(scanned).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in lowered, (
            f"{formatter.__name__} emits {phrase!r}. The only permitted "
            f"coverage figure is analysis coverage, whose denominator is "
            f"fully observed."
        )
    for phrase in FORBIDDEN_AS_METRIC:
        for match in re.finditer(re.escape(phrase), lowered):
            window = lowered[
                max(0, match.start() - _NEAR_NUMBER): match.end() + _NEAR_NUMBER
            ]
            assert not re.search(r"\d+\s*%|\d+\s*(?:of|/)\s*\d+", window), (
                f"{formatter.__name__} puts a number next to {phrase!r}: "
                f"{window!r}. That is a safety ratio, and its denominator is "
                f"unknown by exactly the amount unfollowed_local_calls reports."
            )


def test_the_coverage_figure_names_itself_analysis_coverage(scanned):
    """The label is load-bearing: it says what the denominator is."""
    out = format_pretty(scanned)
    assert "analysis coverage" in out.lower()
    assert "not a measure of how safe" in out.lower()


def test_coverage_denominator_is_edges_not_findings(tmp_path: Path):
    """followed + unfollowed must equal observed edges, never a finding count."""
    (tmp_path / "sample.py").write_text(SAMPLE)
    result = scan_path(tmp_path)
    followed, unfollowed, _ = result.analysis_coverage
    assert followed + unfollowed == followed + len(result.unfollowed_local_calls)
    # The sample has two findings-worth of sinks but exactly one local edge.
    assert followed + unfollowed == 1


def test_json_coverage_block_states_its_own_limits(scanned):
    cov = json.loads(format_json(scanned))["analysis_coverage"]
    assert set(cov) == {
        "followed_edges", "unfollowed_edges", "percent_followed",
        "_meaning", "unfollowed_calls",
    }
    assert "not how much of the code is protected" in cov["_meaning"]


def test_coverage_pair_leads_with_counts(scanned):
    """Counts first, percentage second — the percentage is the derived part."""
    line = next(
        ln for ln in format_list(scanned).splitlines()
        if "Call edges from agent-reachable code" in ln
    )
    counts_at = line.index("followed,")
    pct_at = line.index("%")
    assert counts_at < pct_at
