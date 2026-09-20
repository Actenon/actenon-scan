"""The scanner must disclose the calls it did not follow.

Before this, the analysis was per-function and silent about it: a sink one
hop from an entry point was not reported, and the scan printed CLEAN with
nothing to say a call had been stepped over. Silence read as safety.

These tests pin the disclosure into every output path. They are written
against the DEFECT-1 pair — the same helper call, once behind a local
function and once inline — so the control proves the sink is otherwise
detectable and the fixture proves the gap is real.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path
from actenon_scan.report.html_out import format_html
from actenon_scan.report.json_out import format_json
from actenon_scan.report.markdown_out import format_markdown
from actenon_scan.report.pretty import format_list, format_pretty
from actenon_scan.report.sarif import format_sarif

ONE_HOP = '''from agents import tool


@tool
def publish(data):
    send_to_external_service(data)


def send_to_external_service(data):
    requests.post("https://example.com/upload", json=data)
'''

INLINE = '''from agents import tool


@tool
def publish(data):
    requests.post("https://example.com/upload", json=data)
'''


@pytest.fixture
def one_hop_tree(tmp_path: Path) -> Path:
    (tmp_path / "missed.py").write_text(ONE_HOP)
    return tmp_path


def test_the_one_hop_call_is_counted_as_unfollowed(one_hop_tree):
    result = scan_path(one_hop_tree)
    assert len(result.unfollowed_local_calls) == 1
    edge = result.unfollowed_local_calls[0]
    assert edge.caller == "publish"
    assert edge.callee == "send_to_external_service"
    assert edge.line == 6
    assert edge.followed is False


def test_a_clean_scan_of_the_one_hop_case_does_not_claim_nothing_was_missed(one_hop_tree):
    """The regression that motivated all of this.

    This exact tree used to print the clean statement and nothing else.
    """
    result = scan_path(one_hop_tree)
    out = format_pretty(result)
    assert "not followed" in out
    assert "send_to_external_service" in out


def test_inline_control_has_nothing_to_disclose(tmp_path: Path):
    """The control case reports the sink and claims no gap it does not have."""
    (tmp_path / "control.py").write_text(INLINE)
    result = scan_path(tmp_path)
    assert result.unfollowed_local_calls == []
    assert len([f for f in result.findings if not f.suppressed]) == 1
    assert "not followed" not in format_pretty(result)


@pytest.mark.parametrize(
    "formatter",
    [format_pretty, format_list, format_markdown, format_html],
    ids=["pretty", "list", "markdown", "html"],
)
def test_every_text_output_path_discloses_the_gap(one_hop_tree, formatter):
    """A partial scan misleads as much as a clean one, in every format."""
    out = formatter(scan_path(one_hop_tree))
    assert "not followed" in out
    assert "send_to_external_service" in out


def test_json_carries_the_gap_machine_readably(one_hop_tree):
    d = json.loads(format_json(scan_path(one_hop_tree)))
    assert len(d["unfollowed_local_calls"]) == 1
    assert d["unfollowed_local_calls"][0]["callee"] == "send_to_external_service"


def test_sarif_reports_the_gap_as_a_tool_execution_notification(one_hop_tree):
    """An empty SARIF results array must not read as an all-clear."""
    d = json.loads(format_sarif(scan_path(one_hop_tree)))
    run = d["runs"][0]
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert len(notes) == 1
    assert "was not followed" in notes[0]["message"]["text"]


def test_headline_does_not_stand_alone_while_calls_are_unfollowed(tmp_path: Path):
    """The 'can reach N' sentence must carry the caveat, not defer to a footer."""
    (tmp_path / "both.py").write_text(INLINE + "\n\n" + ONE_HOP.split("\n\n", 1)[1])
    result = scan_path(tmp_path)
    assert result.unfollowed_local_calls
    headline = next(
        ln for ln in format_pretty(result).splitlines()
        if "consequential action" in ln
    )
    assert "floor, not a total" in headline


def test_clean_scan_limitations_states_the_real_count_not_a_literal_N(one_hop_tree):
    out = format_pretty(scan_path(one_hop_tree))
    assert "N call(s)" not in out
    assert "1 call from agent-reachable code" in out




def test_ambiguous_binding_is_disclosed_not_followed(tmp_path: Path):
    """Conservative direction: a shadowed name is not resolved, and is disclosed."""
    (tmp_path / "shadow.py").write_text(
        "from agents import tool\n\n\n"
        "@tool\n"
        "def run(x):\n"
        "    helper = x.get_callback()\n"
        "    helper(x)\n\n\n"
        "def helper(x):\n"
        "    requests.post('https://example.com', json=x)\n"
    )
    result = scan_path(tmp_path)
    assert [e.reason for e in result.unfollowed_local_calls] == ["ambiguous_binding"]


def test_a_call_to_a_library_function_is_not_an_edge(tmp_path: Path):
    """Edges count local calls only. A library call is the sink layer itself."""
    (tmp_path / "lib.py").write_text(
        "from agents import tool\nimport requests\n\n\n"
        "@tool\n"
        "def run(x):\n"
        "    requests.post('https://example.com', json=x)\n"
    )
    result = scan_path(tmp_path)
    assert result.unfollowed_local_calls == []


def test_cache_hit_discloses_the_same_gap_as_a_fresh_scan(one_hop_tree, tmp_path: Path):
    """A cached run must not under-report the gap the first run disclosed."""
    from actenon_scan.cache import FileCache

    cache = FileCache(tmp_path / "cachedir")
    first = scan_path(one_hop_tree, cache=cache)
    second = scan_path(one_hop_tree, cache=cache)
    assert [
        (e.file, e.line, e.callee) for e in second.unfollowed_local_calls
    ] == [(e.file, e.line, e.callee) for e in first.unfollowed_local_calls]


def test_entry_point_index_agrees_with_the_direct_path(tmp_path: Path):
    """The fast path must decide exactly what the slow path decides.

    ``build_entry_point_index`` exists only to stop entry-point detection
    being quadratic in module size. If it ever disagreed with
    ``entry_point_signal``'s direct path, the call-edge walk would treat a
    function as non-reachable that the sink path treats as reachable, and the
    scan would report FEWER unfollowed calls than it actually has — the gap
    under-reported by the very machinery built to disclose it.
    """
    import ast

    from actenon_scan.detectors.reachability import (
        build_entry_point_index,
        entry_point_signal,
    )
    from actenon_scan.rules.loader import load_rules

    source = '''
from agents import tool
from langchain.tools import Tool


@tool
def decorated(x):
    pass


def wrapped(x):
    pass


def listed(x):
    pass


def plain(x):
    pass


def dispatch(name, payload):
    if name == "run_command":
        pass


TOOLS = [{"name": "run_command", "description": "runs"}]
t = Tool.from_function(wrapped)
agent = Agent(tools=[listed])
handler = SOME_MAP["k"](plain)
'''
    tree = ast.parse(source)
    cfg = load_rules(None).reachability
    index = build_entry_point_index(tree, cfg)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assert entry_point_signal(
                tree, node, cfg, index=index
            ) == entry_point_signal(tree, node, cfg), node.name
