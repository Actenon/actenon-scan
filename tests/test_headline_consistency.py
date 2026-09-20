"""The printed numbers must agree, and one action must count once.

Two defects, one fixture:

1. INCONSISTENCY. A real run printed "Consequential capabilities: 103 /
   Guard found: 24 / Review required: 79", then "can reach 77 consequential
   actions", then "77 findings". 79 != 77. Capabilities were recorded
   mid-analysis, before a finding could still be suppressed by a declarative
   guard, an inline suppression or a baseline, so the summary counted sinks
   the list below it did not.

2. DOUBLE COUNTING. detect_sinks runs three independent match loops over the
   same call node, so one source line can produce two Findings. Each one
   incremented the headline. `conn.exec("DELETE FROM t")` matches EXEC-CODE
   (code_execution) and DATA-DELETE-SQL (data_destruction): one action, two
   reasons, counted as two actions.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path
from actenon_scan.report.json_out import format_json
from actenon_scan.report.pretty import format_list, format_pretty

# conn.exec(...) is matched by EXEC-CODE in the general rule loop AND by
# DATA-DELETE-SQL in the sql_execute_pattern loop. One call node, two rules.
MULTI_RULE = '''from agents import tool


@tool
def purge(table):
    conn.exec("DELETE FROM records")
'''

# A second, single-rule action so the counts are not trivially 1.
PLUS_SINGLE = '''

@tool
def send(payload):
    requests.post("https://example.com/upload", json=payload)
'''


@pytest.fixture
def multi_rule(tmp_path: Path):
    (tmp_path / "multi.py").write_text(MULTI_RULE + PLUS_SINGLE)
    return scan_path(tmp_path)


def test_one_line_two_rules_is_one_action_two_findings(multi_rule):
    assert multi_rule.rule_match_count == 3
    assert multi_rule.consequential_action_count == 2
    groups = multi_rule.consequential_actions
    doubled = [g for g in groups if len(g) > 1]
    assert len(doubled) == 1
    assert {f.rule_id for f in doubled[0]} == {"EXEC-CODE", "DATA-DELETE-SQL"}


def test_the_three_printed_numbers_agree(multi_rule):
    """Review required == can reach N == the summary line's action count."""
    out = format_pretty(multi_rule)

    review = int(re.search(r"Review required:\s+(\d+)", out).group(1))
    can_reach = int(re.search(r"can reach (\d+) consequential", out).group(1))
    summary = int(re.search(r"^(\d+) consequential actions? in", out, re.M).group(1))

    assert review == can_reach == summary == 2, out


def test_the_rule_match_count_is_labelled_not_substituted(multi_rule):
    """Both numbers are printed, each saying what it counts."""
    out = format_pretty(multi_rule)
    assert "2 consequential actions" in out
    assert "(3 rule matches)" in out


def test_capability_total_equals_the_sum_of_its_states(multi_rule):
    s = multi_rule.capability_summary
    assert s.total == s.guard_found + s.review_required + s.accepted_decision + s.not_analysed


def test_both_rule_matches_survive_in_the_detail_list(multi_rule):
    """Deduplication is for counting only. No evidence is discarded."""
    out = format_list(multi_rule)
    assert "EXEC-CODE" in out
    assert "DATA-DELETE-SQL" in out
    assert "2 consequential action(s), 3 finding(s)" in out


def test_both_rule_matches_survive_in_json(multi_rule):
    d = json.loads(format_json(multi_rule))
    at_line = [f for f in d["findings"] if f["line"] == 6]
    assert {f["rule_id"] for f in at_line} == {"EXEC-CODE", "DATA-DELETE-SQL"}


def test_a_suppressed_finding_is_not_counted_as_awaiting_review(tmp_path: Path):
    """The 79-vs-77 gap: suppression must reach the capability summary."""
    src = tmp_path / "s.py"
    src.write_text(
        "from agents import tool\nimport requests\n\n\n"
        "@tool\n"
        "def send(p):\n"
        "    requests.post('https://example.com', json=p)  # actenon-scan: ignore\n"
    )
    result = scan_path(tmp_path)
    summary = result.capability_summary
    assert result.consequential_action_count == summary.review_required
    if any(f.suppressed for f in result.findings):
        assert summary.review_required == 0
        assert summary.accepted_decision == 1


def test_consequence_map_rows_that_outsum_the_headline_say_so(multi_rule):
    """One action in two categories appears twice in the map, by design."""
    out = format_pretty(multi_rule)
    assert "carry more than one consequence type" in out
