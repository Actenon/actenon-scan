"""Known false negative: an authority check on a different resource than the action uses.

Reported by an independent audit (counterfeit-guards scenario): the agent authorises one value
(`attacker_id`) and then refunds another (`payment_intent`). Scan treats the dominating
`authorize(...)` call as a guard and reports nothing. docs/COVERAGE.md lists this class: the
parameter-binding limitation for assert-style guards.

The expected-failure test is strict. When binding analysis starts reporting this case it will
XPASS and fail, so the miss is reclassified deliberately, not silently.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from actenon_scan.engine import scan_path

AGENT = '''import stripe
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("billing")


def authorize(principal_id: str) -> None:
    if principal_id not in {"admin"}:
        raise PermissionError(principal_id)


@mcp.tool()
def refund_wrong_resource(attacker_id: str, payment_intent: str) -> str:
    authorize(attacker_id)
    return stripe.Refund.create(payment_intent=payment_intent).id


@mcp.tool()
def refund_bound(payment_intent: str) -> str:
    authorize(payment_intent)
    return stripe.Refund.create(payment_intent=payment_intent).id


@mcp.tool()
def refund_unguarded(payment_intent: str) -> str:
    return stripe.Refund.create(payment_intent=payment_intent).id
'''


def _lines_reported(tmp_path: Path) -> set[int]:
    (tmp_path / "agent.py").write_text(AGENT)
    result = scan_path(tmp_path)
    return {f.line for f in result.findings if not f.suppressed}


def _line_of(needle: str, occurrence: int = 1) -> int:
    hits = [i for i, text in enumerate(AGENT.splitlines(), 1) if needle in text]
    return hits[occurrence - 1]


def test_unguarded_refund_is_reported(tmp_path):
    assert _line_of("stripe.Refund.create", 3) in _lines_reported(tmp_path)


def test_refund_guarded_on_the_same_value_is_not_reported(tmp_path):
    assert _line_of("stripe.Refund.create", 2) not in _lines_reported(tmp_path)


@pytest.mark.xfail(strict=True, reason="known limitation: guard bound to a different parameter than the sink")
def test_refund_guarded_on_a_different_value_is_reported(tmp_path):
    assert _line_of("stripe.Refund.create", 1) in _lines_reported(tmp_path)
