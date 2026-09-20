"""Tests for the effect-summary layer (Objective 3)."""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from actenon_scan.repository import (
    EffectType,
    EffectSummary,
    propagate_effects,
    build_call_graph,
    RepositoryIndex,
)


def _index_and_graph(files: dict[str, str]) -> tuple[RepositoryIndex, "CallGraph"]:
    tmp = tempfile.mkdtemp()
    root = Path(tmp)
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    idx = RepositoryIndex.build(root)
    return idx, build_call_graph(idx)


class EffectPropagationTests(unittest.TestCase):
    def test_direct_sink_seeds_summary(self) -> None:
        files = {
            "app.py": (
                "def destroy(id):\n"
                "    subprocess.run(['rm', '-rf', id])\n"
            ),
        }
        _idx, g = _index_and_graph(files)
        # Seed: app.destroy has a direct SHELL_EXECUTION sink at line 2
        direct_sinks = {
            "app.destroy": [(EffectType.SHELL_EXECUTION, ("app.py", 2), "EXEC-SHELL")]
        }
        prop = propagate_effects(g, direct_sinks=direct_sinks)
        s = prop.summaries.get("app.destroy")
        self.assertIsNotNone(s)
        self.assertIn(EffectType.SHELL_EXECUTION, s.effects)
        provs = s.effects[EffectType.SHELL_EXECUTION]
        self.assertEqual(len(provs), 1)
        self.assertEqual(provs[0].concrete_sink, ("app.py", 2))
        self.assertEqual(provs[0].propagated_from, None)
        self.assertEqual(provs[0].rule_id, "EXEC-SHELL")

    def test_effect_propagates_through_one_hop(self) -> None:
        """If a function calls a helper that has a sink, the caller inherits
        the helper's effect with provenance pointing back to the helper."""
        files = {
            "app.py": (
                "def destroy_account(id):\n"
                "    delete_database(id)\n"
                "    delete_files(id)\n"
                "    revoke_credentials(id)\n"
                "def delete_database(id):\n"
                "    cursor.execute('DELETE FROM accounts WHERE id=%s', (id,))\n"
                "def delete_files(id):\n"
                "    os.remove(id)\n"
                "def revoke_credentials(id):\n"
                "    secret_manager.revoke(id)\n"
            ),
        }
        _idx, g = _index_and_graph(files)
        # Seed direct sinks on the helpers.
        direct_sinks = {
            "app.delete_database": [(EffectType.DATA_DELETION, ("app.py", 6), "DATA-DELETE-SQL")],
            "app.delete_files": [(EffectType.FILE_DELETE, ("app.py", 8), "DATA-DELETE-FILE")],
            "app.revoke_credentials": [(EffectType.CREDENTIAL_ACCESS, ("app.py", 10), "SECRET-READ")],
        }
        prop = propagate_effects(g, direct_sinks=direct_sinks)
        s = prop.summaries.get("app.destroy_account")
        self.assertIsNotNone(s)
        self.assertIn(EffectType.DATA_DELETION, s.effects)
        self.assertIn(EffectType.FILE_DELETE, s.effects)
        self.assertIn(EffectType.CREDENTIAL_ACCESS, s.effects)
        # Provenance: each effect came from a callee.
        for prov in s.effects[EffectType.DATA_DELETION]:
            self.assertEqual(prov.propagated_from, "app.delete_database")
            self.assertEqual(prov.concrete_sink, ("app.py", 6))

    def test_effect_propagates_through_two_hops(self) -> None:
        files = {
            "app.py": (
                "@tool\n"
                "def agent_action():\n"
                "    layer_one()\n"
                "def layer_one():\n"
                "    layer_two()\n"
                "def layer_two():\n"
                "    subprocess.run(['rm'])\n"
            ),
        }
        _idx, g = _index_and_graph(files)
        direct_sinks = {
            "app.layer_two": [(EffectType.SHELL_EXECUTION, ("app.py", 6), "EXEC-SHELL")],
        }
        prop = propagate_effects(g, direct_sinks=direct_sinks)
        # layer_one inherits from layer_two.
        s1 = prop.summaries.get("app.layer_one")
        self.assertIn(EffectType.SHELL_EXECUTION, s1.effects)
        # agent_action inherits from layer_one (and transitively layer_two).
        s2 = prop.summaries.get("app.agent_action")
        self.assertIn(EffectType.SHELL_EXECUTION, s2.effects)
        # Provenance at the top points to layer_one (the immediate callee)
        prov = s2.effects[EffectType.SHELL_EXECUTION][0]
        self.assertEqual(prov.propagated_from, "app.layer_one")

    def test_recursion_converges(self) -> None:
        files = {
            "app.py": (
                "def recur(n):\n"
                "    if n < 10:\n"
                "        recur(n + 1)\n"
                "    subprocess.run(['ls'])\n"
            ),
        }
        _idx, g = _index_and_graph(files)
        direct_sinks = {
            "app.recur": [(EffectType.SHELL_EXECUTION, ("app.py", 4), "EXEC-SHELL")],
        }
        # Must not infinite-loop.
        prop = propagate_effects(g, direct_sinks=direct_sinks, max_iterations=16)
        s = prop.summaries.get("app.recur")
        self.assertIn(EffectType.SHELL_EXECUTION, s.effects)
        # Should converge in few iterations.
        self.assertLess(prop.iterations, 8)

    def test_mutual_recursion_converges(self) -> None:
        files = {
            "app.py": (
                "def a():\n"
                "    b()\n"
                "    subprocess.run(['ls'])\n"
                "def b():\n"
                "    a()\n"
            ),
        }
        _idx, g = _index_and_graph(files)
        direct_sinks = {
            "app.a": [(EffectType.SHELL_EXECUTION, ("app.py", 3), "EXEC-SHELL")],
        }
        prop = propagate_effects(g, direct_sinks=direct_sinks, max_iterations=16)
        # b inherits SHELL_EXECUTION from a (despite the cycle).
        s = prop.summaries.get("app.b")
        self.assertIn(EffectType.SHELL_EXECUTION, s.effects)

    def test_unresolved_callee_marks_summary_incomplete(self) -> None:
        """A function calling an UNRESOLVED callee (e.g. ``getattr(...)()``)
        must have has_unresolved_callee=True — never silently treated as
        safe / no-effects."""
        files = {
            "app.py": (
                "def handler():\n"
                "    fn = getattr(someobj, 'do_thing')\n"
                "    fn()\n"
            ),
        }
        _idx, g = _index_and_graph(files)
        prop = propagate_effects(g, direct_sinks={})
        s = prop.summaries.get("app.handler")
        self.assertTrue(s.has_unresolved_callee)
        self.assertIn("app.handler", prop.incomplete)

    def test_rule_id_to_effect_mapping(self) -> None:
        from actenon_scan.repository.effect_summary import effect_for_rule_id
        self.assertEqual(effect_for_rule_id("EXEC-SHELL"), EffectType.SHELL_EXECUTION)
        self.assertEqual(effect_for_rule_id("EXEC-SHELL-WEAK"), EffectType.SHELL_EXECUTION)
        self.assertEqual(effect_for_rule_id("EXEC-SHELL-UNBOUND"), EffectType.SHELL_EXECUTION)
        self.assertEqual(effect_for_rule_id("PAY-STRIPE-REFUND"), EffectType.MONEY_REFUND)
        self.assertEqual(effect_for_rule_id("DATA-DELETE-SQL"), EffectType.DATA_DELETION)
        # Unknown rule IDs return None (not silently mapped to UNKNOWN_EFFECT).
        self.assertIsNone(effect_for_rule_id("UNKNOWN-RULE"))


if __name__ == "__main__":
    unittest.main()
