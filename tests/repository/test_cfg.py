"""Tests for the CFG / dominator primitive (Objective 6).

Verifies that the CFG correctly models:

- Sequential dominance chains (test 7)
- ``if`` branching and the merge point (tests 1, 2, 8)
- Early ``return`` terminating a path (test 4)
- ``raise`` correctly modelled as a terminator (test 5)
- ``for``-loop back-edges — loop body does NOT dominate after-loop
  code because the loop may execute zero times (test 6)
- Nested ``if`` dominance and the fall-through merge (test 8)
- Empty function body (test 9) and docstring-only body (test 10)

Conservative invariant pinned by these tests:

- A node inside a conditional branch does NOT dominate code after the
  branch merges (tests 1, 8-foo-vs-bar).
- A node inside a loop body does NOT dominate code after the loop
  (test 6).
- A node that appears AFTER the sink cannot dominate the sink
  (test 3).
- A node BEFORE a branching point DOES dominate the merge point
  (tests 2, 8-authorize-dominates-sink).

These invariants are the path-sensitive foundation that the existing
AST-ancestry guard-dominance check in :mod:`actenon_scan.detectors.guards`
will eventually be migrated onto.
"""

from __future__ import annotations

import ast
import unittest

from actenon_scan.repository.cfg import (
    CFG,
    CFGNode,
    build_cfg,
    dominators,
    dominates,
    reverse_postorder,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build(source: str):
    """Parse source, build the CFG, compute dominators.

    Returns ``(cfg, doms, tree)`` where ``tree`` is the parsed module
    (so tests can look up line numbers via :func:`_find_call_line`).
    """
    tree = ast.parse(source)
    func = None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func = node
            break
    assert func is not None, "no function def in source"
    cfg = build_cfg(func)
    doms = dominators(cfg)
    return cfg, doms, tree


def _find_call_line(tree: ast.AST, callee_name: str):
    """Find the lineno of the first Call to ``callee_name`` in ``tree``.

    Matches both ``Name``-form (``authorize(...)``) and
    ``Attribute``-form (``self.authorize(...)``) callees.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id == callee_name:
                return node.lineno
            if isinstance(f, ast.Attribute) and f.attr == callee_name:
                return node.lineno
    return None


def _find_stmt_line(tree: ast.AST, stmt_type: type):
    """Find the lineno of the first statement of the given type in ``tree``."""
    for node in ast.walk(tree):
        if isinstance(node, stmt_type):
            return node.lineno
    return None


def _node_for_call(cfg: CFG, tree: ast.AST, callee_name: str) -> int:
    """Find the CFG node containing the first call to ``callee_name``."""
    line = _find_call_line(tree, callee_name)
    assert line is not None, f"no call to {callee_name!r} found in source"
    nid = cfg.find_node_containing_line(line)
    assert nid is not None, (
        f"no CFG node covers line {line} (call to {callee_name!r})"
    )
    return nid


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class CFGDominanceTests(unittest.TestCase):

    # --- Case A: authorize in if-body, sink after if ---------------

    def test_case_a_if_authorize_then_sink_no_dominate(self):
        source = """
def f():
    if cond:
        authorize()
    sink()
"""
        cfg, doms, tree = _build(source)
        auth_id = _node_for_call(cfg, tree, "authorize")
        sink_id = _node_for_call(cfg, tree, "sink")
        self.assertFalse(
            dominates(cfg, doms, auth_id, sink_id),
            "authorize inside an if-branch must NOT dominate code after "
            "the if (the if test may be false, skipping authorize)",
        )

    # --- Case B: authorize before if, sink after -------------------

    def test_case_b_authorize_before_if_dominates_sink(self):
        source = """
def f():
    authorize()
    if cond:
        foo()
    else:
        bar()
    sink()
"""
        cfg, doms, tree = _build(source)
        auth_id = _node_for_call(cfg, tree, "authorize")
        sink_id = _node_for_call(cfg, tree, "sink")
        self.assertTrue(
            dominates(cfg, doms, auth_id, sink_id),
            "authorize before the if must dominate sink after the if "
            "(every path to sink runs authorize first)",
        )

    # --- Case C: sink before authorize -----------------------------

    def test_case_c_sink_before_authorize_not_guarded(self):
        source = """
def f():
    sink()
    authorize()
"""
        cfg, doms, tree = _build(source)
        auth_id = _node_for_call(cfg, tree, "authorize")
        sink_id = _node_for_call(cfg, tree, "sink")
        self.assertFalse(
            dominates(cfg, doms, auth_id, sink_id),
            "authorize after the sink cannot dominate the sink "
            "(dominance is a forward property)",
        )

    # --- Early return terminates the path --------------------------

    def test_early_return_terminates_path(self):
        source = """
def f():
    if cond:
        return
    sink()
"""
        cfg, doms, tree = _build(source)
        sink_id = _node_for_call(cfg, tree, "sink")
        sink_preds = cfg.preds(sink_id)
        self.assertEqual(
            len(sink_preds), 1,
            f"sink should have exactly one predecessor (the if merge "
            f"reachable only when cond is false); got {sink_preds}",
        )

    # --- Raise terminates the path --------------------------------

    def test_raise_terminates_path(self):
        source = """
def f():
    if not authorized:
        raise E()
    sink()
"""
        cfg, doms, tree = _build(source)
        raise_line = _find_stmt_line(tree, ast.Raise)
        self.assertIsNotNone(raise_line, "no Raise statement in source")
        raise_id = cfg.find_node_containing_line(raise_line)
        self.assertIsNotNone(raise_id, "no CFG node covers the raise line")
        raise_node = cfg.nodes[raise_id]
        self.assertEqual(
            raise_node.terminator, "raise",
            "raise must be modelled as a terminator with terminator='raise'",
        )
        self.assertEqual(
            raise_node.successors, [],
            "raise must terminate the path (no successors)",
        )
        # Sink is still reachable via the else fall-through (when the
        # guard test is false, i.e. authorised is truthy).
        sink_id = _node_for_call(cfg, tree, "sink")
        sink_preds = cfg.preds(sink_id)
        self.assertEqual(
            len(sink_preds), 1,
            f"sink should have one predecessor (the if header, reachable "
            f"only when not authorized is false); got {sink_preds}",
        )

    # --- Loop body does NOT dominate after-loop code ---------------

    def test_loop_body_does_not_dominate_after(self):
        source = """
def f():
    for x in items:
        authorize(x)
    sink()
"""
        cfg, doms, tree = _build(source)
        auth_id = _node_for_call(cfg, tree, "authorize")
        sink_id = _node_for_call(cfg, tree, "sink")
        self.assertFalse(
            dominates(cfg, doms, auth_id, sink_id),
            "a guard inside a loop body does NOT dominate code after "
            "the loop (the loop may execute zero times)",
        )

    # --- Sequential dominance chain -------------------------------

    def test_sequential_chain_dominance(self):
        source = """
def f():
    a()
    b()
    c()
"""
        cfg, doms, tree = _build(source)
        a_id = _node_for_call(cfg, tree, "a")
        b_id = _node_for_call(cfg, tree, "b")
        c_id = _node_for_call(cfg, tree, "c")
        self.assertTrue(dominates(cfg, doms, a_id, b_id), "a dominates b")
        self.assertTrue(dominates(cfg, doms, b_id, c_id), "b dominates c")
        self.assertTrue(dominates(cfg, doms, a_id, c_id), "a dominates c")
        # Transitivity sanity: b does NOT dominate a (dominance is forward).
        self.assertFalse(
            dominates(cfg, doms, b_id, a_id),
            "b does NOT dominate a (dominance is forward)",
        )

    # --- Nested if dominance --------------------------------------

    def test_nested_if_dominance(self):
        source = """
def f():
    authorize()
    if cond1:
        if cond2:
            foo()
        bar()
    sink()
"""
        cfg, doms, tree = _build(source)
        auth_id = _node_for_call(cfg, tree, "authorize")
        foo_id = _node_for_call(cfg, tree, "foo")
        bar_id = _node_for_call(cfg, tree, "bar")
        sink_id = _node_for_call(cfg, tree, "sink")
        # authorize dominates foo, bar, and sink.
        self.assertTrue(
            dominates(cfg, doms, auth_id, foo_id),
            "authorize dominates foo",
        )
        self.assertTrue(
            dominates(cfg, doms, auth_id, bar_id),
            "authorize dominates bar",
        )
        self.assertTrue(
            dominates(cfg, doms, auth_id, sink_id),
            "authorize dominates sink",
        )
        # foo does NOT dominate bar — bar is in the outer if, reachable
        # via the inner if's else fall-through without going through foo.
        self.assertFalse(
            dominates(cfg, doms, foo_id, bar_id),
            "foo (inner if body) must NOT dominate bar (outer if body) "
            "because bar is reachable when cond2 is false, skipping foo",
        )

    # --- Empty function body --------------------------------------

    def test_empty_function_has_entry_only(self):
        source = """
def f():
    pass
"""
        cfg, _doms, _tree = _build(source)
        self.assertEqual(
            len(cfg.nodes), 1,
            "pass-only function has exactly one CFG node (the entry)",
        )
        self.assertIn(cfg.entry, cfg.nodes)
        entry_node = cfg.nodes[cfg.entry]
        self.assertEqual(
            entry_node.successors, [],
            "entry node of a pass-only function has no successors",
        )

    # --- Docstring-only function body -----------------------------

    def test_function_with_docstring_only(self):
        source = '''
def f():
    """doc"""
'''
        cfg, _doms, _tree = _build(source)
        self.assertEqual(
            len(cfg.nodes), 1,
            "docstring-only function has exactly one CFG node (the entry)",
        )
        self.assertIn(cfg.entry, cfg.nodes)


# ---------------------------------------------------------------------------
# Secondary surface tests (not in the required 10 — kept minimal)
# ---------------------------------------------------------------------------


class CFGSurfaceTests(unittest.TestCase):
    """Sanity checks on the public API surface (CFG/CFGNode dataclasses)."""

    def test_dataclass_fields_have_documented_defaults(self):
        node = CFGNode(id=0)
        self.assertEqual(node.id, 0)
        self.assertEqual(node.statements, [])
        self.assertEqual(node.successors, [])
        self.assertEqual(node.start_line, 0)
        self.assertEqual(node.terminator, "")

        cfg = CFG(entry=-1)
        self.assertEqual(cfg.entry, -1)
        self.assertEqual(cfg.nodes, {})
        self.assertEqual(cfg.function_name, "")

    def test_succ_and_preds_round_trip(self):
        source = """
def f():
    a()
    b()
"""
        cfg, _doms, tree = _build(source)
        a_id = _node_for_call(cfg, tree, "a")
        b_id = _node_for_call(cfg, tree, "b")
        self.assertEqual(cfg.succ(a_id), [b_id])
        self.assertEqual(cfg.preds(b_id), [a_id])
        # Unknown node IDs return empty.
        self.assertEqual(cfg.succ(999), [])
        self.assertEqual(cfg.preds(999), [])

    def test_find_node_containing_line_returns_none_for_unknown_line(self):
        source = """
def f():
    a()
"""
        cfg, _doms, _tree = _build(source)
        self.assertIsNone(cfg.find_node_containing_line(9999))

    def test_reverse_postorder_starts_with_entry(self):
        source = """
def f():
    if cond:
        a()
    else:
        b()
    c()
"""
        cfg, _doms, _tree = _build(source)
        rpo = reverse_postorder(cfg)
        self.assertGreater(len(rpo), 0)
        self.assertEqual(rpo[0], cfg.entry,
                         "RPO must start with the entry node")


if __name__ == "__main__":
    unittest.main()
