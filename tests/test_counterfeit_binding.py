"""Counterfeit-binding detection for assert-style guards (soundness case s02).

Assert-style guards are exempt from the binding check, because the three
legitimate idioms below all share zero identifiers with the sink they guard:

    authorize("refund")                        -- authorize by action name
    casbin_enforce("user", "record", "delete") -- Casbin subject/object/action
    verify_pccb(proof, intent, action)         -- Actenon's own PCCB pattern

Binding intersection cannot separate any of those from a defeated guard.
What IS separable is a guard that passes VARIABLES — appearing to inspect
runtime data — where every variable provably resolves to a compile-time
constant. That is s02, and it is what this module pins.

These tests exist because an earlier revision "fixed" s02 by rewriting the
benchmark fixture into an all-literal guard call, which is not distinguishable
from casbin_enforce by any sound rule. The fixture is the specification; the
cases below keep both sides of the line honest.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from actenon_scan.engine import scan_path

SINK = "    import stripe; stripe.Refund.create(payment_intent=pi)"
HEADER = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n\n@mcp.tool()\ndef refund(pi: str):\n'


def _scan(source: str) -> list:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(source)
        f.flush()
        result = scan_path(f.name)
    Path(f.name).unlink()
    return [f for f in result.findings if not f.suppressed]


def _guard(body: str) -> str:
    return HEADER + body + "\n" + SINK + "\n"


class TestCounterfeitBindingIsFlagged:
    """A guard whose variables all resolve to constants is UNBOUND."""

    def test_s02_local_constant(self):
        """s02 itself: authorize(attacker) where attacker = "evil_intent"."""
        findings = _scan(_guard('    attacker = "evil_intent"\n    authorize(attacker)'))
        assert len(findings) == 1, f"expected 1 UNBOUND finding: {findings}"
        assert findings[0].rule_id.endswith("-UNBOUND"), findings[0].rule_id

    def test_alias_chain(self):
        """Constants laundered through an alias chain are still constants."""
        findings = _scan(_guard('    a = "evil"\n    b = a\n    authorize(b)'))
        assert len(findings) == 1, f"expected 1 UNBOUND finding: {findings}"

    def test_keyword_argument(self):
        """The rule reads keyword arguments, not just positional ones."""
        findings = _scan(_guard('    who = "evil"\n    authorize(subject=who)'))
        assert len(findings) == 1, f"expected 1 UNBOUND finding: {findings}"

    def test_severity_stays_below_fail_threshold(self):
        """UNBOUND is medium — it must never fail a --fail-on high gate."""
        findings = _scan(_guard('    attacker = "evil_intent"\n    authorize(attacker)'))
        assert all(f.severity != "high" for f in findings), findings


class TestLegitimateGuardsAreNotFlagged:
    """The three idioms that share no identifier with the sink stay clean."""

    def test_authorize_by_action_name(self):
        assert _scan(_guard('    authorize("refund")')) == []

    def test_casbin_three_literals(self):
        """Casbin's enforce(sub, obj, act) is all-literal and correct.

        An arity heuristic ("more than one literal argument means UNBOUND")
        flags this. That is a false positive on the canonical Casbin call.
        """
        assert _scan(_guard('    casbin_enforce("user", "record", "delete")')) == []

    def test_verify_pccb_with_parameters(self):
        """Actenon's own guard pattern — parameters, no overlap with the sink."""
        source = (
            'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n\n'
            "@mcp.tool()\ndef refund(proof, intent, action, amount: int):\n"
            "    verify_pccb(proof, intent, action)\n"
            "    import stripe; stripe.Refund.create(amount=amount)\n"
        )
        assert _scan(source) == []

    def test_guard_holding_a_call_result(self):
        """A name bound from a call carries runtime data — not counterfeit."""
        assert _scan(_guard("    who = get_current_user()\n    authorize(who)")) == []

    def test_guard_holding_an_attribute(self):
        """Attributes are unresolvable, so the guard is treated as bound."""
        assert _scan(_guard("    authorize(ctx.user)")) == []

    def test_guard_holding_an_unbound_global(self):
        """A name never assigned locally is a global or closure — unknown."""
        assert _scan(_guard("    authorize(CURRENT_PRINCIPAL)")) == []

    def test_guard_sharing_a_parameter_with_the_sink(self):
        """Genuine binding: the guard inspects exactly what the sink acts on."""
        assert _scan(_guard('    policy_gate("refund", pi)')) == []

    def test_loop_target_is_unresolvable(self):
        """A name bound by a for-loop is not provably constant."""
        source = _guard(
            "    who = None\n"
            "    for who in principals():\n"
            "        pass\n"
            "    authorize(who)"
        )
        assert _scan(source) == []


class TestKnownLimitation:
    """The gap this rule does NOT close, pinned so it stays visible.

    An assert-style guard passing real parameters that happen to be the WRONG
    parameters is syntactically identical to one passing the right ones. See
    docs/COVERAGE.md — the binding that makes PCCB sound is cryptographic and
    lives inside the proof object, invisible at the call site.
    """

    def test_wrong_parameters_are_not_detected(self):
        source = (
            'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n\n'
            "@mcp.tool()\ndef refund(pi: str, other: str):\n"
            "    authorize(other)\n"
            "    import stripe; stripe.Refund.create(payment_intent=pi)\n"
        )
        assert _scan(source) == [], "documented limitation — see docs/COVERAGE.md"
