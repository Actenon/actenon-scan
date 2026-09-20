"""Cross-layer consequence tests for the repository-level analysis layers.

These adversarial end-to-end tests exercise MULTIPLE new repository layers
in concert:

- :class:`RepositoryIndex` (symbol index + import resolution)
- :func:`build_call_graph` + :func:`transitive_reachable` (call graph)
- :func:`resolve_guard_call` (cross-file guard body inspection)
- :func:`classify_guard_name` + :func:`action_authorization_strength`
  (semantic guard taxonomy)
- :func:`compare_authority_to_sink` /
  :func:`compare_all_authority_to_sink_params` (authority binding)
- :func:`build_cfg` + :func:`dominators` + :func:`dominates` (CFG)

Each test builds a tiny multi-file repo, constructs a
:class:`RepositoryIndex` via :meth:`RepositoryIndex.build`, then drives
the layers directly. The central concern is *consequence*: when a sink
is reachable through a chain of calls and a guard is supposed to
authorize the action, does the analyser correctly:

- resolve the guard cross-file and inspect its body (ASSERT vs
  PREDICATE vs UNKNOWN);
- prove the authority's parameters are *the same values* as the
  sink's parameters (BOUND plumbing proof); and
- distinguish AUTHENTICATION / VALIDATION (cannot authorize an
  action) from AUTHORIZATION (can, when the action parameter is
  bound)?

Conservative invariant (NON-NEGOTIABLE): FALSE ASSURANCE IS WORSE
THAN A REVIEWABLE FALSE POSITIVE. When a test surfaces a real bug in
one of the new modules — i.e. the analyser would silently promote
UNKNOWN to BOUND / ASSERT — the test is left intact (NOT weakened) and
``unittest.skip`` is applied with a comment explaining the bug. The
finding is also recorded in the worklog.
"""
from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from actenon_scan.repository import (
    RepositoryIndex,
    ResolutionCertainty,
    build_call_graph,
    transitive_reachable,
    resolve_guard_call,
    classify_guard_name,
    action_authorization_strength,
    compare_authority_to_sink,
    compare_all_authority_to_sink_params,
    overall_binding_state,
    build_cfg,
    dominators,
    dominates,
    GuardStyle,
    GuardKind,
    BindingState,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_repo(files: dict[str, str]) -> str:
    """Write a temp repo and return its root path.

    Mirrors the helper in :mod:`tests.adversarial.test_transitive_reachability`.
    """
    tmp = tempfile.mkdtemp()
    for rel, src in files.items():
        p = Path(tmp) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    return tmp


def _find_call(tree: ast.Module, callee_name: str) -> ast.Call:
    """Find the first ``ast.Call`` (BFS order) whose callee matches.

    Matches both ``ast.Name`` (``require_admin()``) and ``ast.Attribute``
    (``self.require_admin()``) callee forms.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        n: str | None = None
        if isinstance(f, ast.Name):
            n = f.id
        elif isinstance(f, ast.Attribute):
            n = f.attr
        if n == callee_name:
            return node
    raise AssertionError(f"No Call node with callee {callee_name!r}")


def _find_first_func(tree: ast.Module) -> ast.FunctionDef | ast.AsyncFunctionDef:
    """Return the first top-level FunctionDef in ``tree``."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    raise AssertionError("no top-level FunctionDef in tree")


def _find_func(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    """Return the top-level FunctionDef named ``name`` in ``tree``."""
    for node in tree.body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ):
            return node
    raise AssertionError(f"no top-level FunctionDef named {name!r}")


# ---------------------------------------------------------------------------
# Cross-layer consequence tests
# ---------------------------------------------------------------------------


class CrossLayerConsequenceTests(unittest.TestCase):
    """End-to-end exercises of multiple new repository layers together."""

    # ------------------------------------------------------------------
    # 1. Transitive reach + cross-file guard body inspection
    # ------------------------------------------------------------------
    def test_transitive_reach_plus_cross_file_guard(self) -> None:
        """The central Objective-2 scenario plus a cross-file guard.

        Repo layout:
            main.py     — @tool agent_action calls require_admin (from
                          security.py) and layer_one; layer_one calls
                          layer_two; layer_two calls subprocess.run.
            security.py — require_admin defined with a ``raise`` body.

        Verifies, in concert:
          - The 3-hop chain ``agent_action → layer_one → layer_two`` is
            transitively reachable from the @tool entrypoint
            (:func:`transitive_reachable`).
          - The cross-file guard ``require_admin`` (imported into main.py
            from security.py) is resolved by :func:`resolve_guard_call`
            and classified as :data:`GuardStyle.ASSERT` because its body
            raises.
        """
        root = _write_repo({
            "main.py": (
                "from langchain.tools import tool\n"
                "from security import require_admin\n"
                "import subprocess\n"
                "\n"
                "@tool\n"
                "def agent_action(x):\n"
                "    require_admin()\n"
                "    layer_one(x)\n"
                "\n"
                "def layer_one(x):\n"
                "    layer_two(x)\n"
                "\n"
                "def layer_two(x):\n"
                "    subprocess.run(x, shell=True)\n"
            ),
            "security.py": (
                "def require_admin():\n"
                "    raise RuntimeError('not admin')\n"
            ),
        })
        idx = RepositoryIndex.build(Path(root))
        graph = build_call_graph(idx)

        # Transitive reachability from the @tool entrypoint.
        reachable = transitive_reachable(graph, ["main.agent_action"])
        self.assertIn(
            "main.layer_one",
            reachable,
            f"layer_one must be reachable from agent_action; got {sorted(reachable)}",
        )
        self.assertIn(
            "main.layer_two",
            reachable,
            f"layer_two must be transitively reachable (2 hops); got {sorted(reachable)}",
        )
        # The 2-hop chain's certainty must NOT be silently UNRESOLVED-only
        # — the agent_action → layer_one and layer_one → layer_two edges
        # are intra-repo bare-name calls and resolve to RESOLVED.
        path_to_layer_two = reachable["main.layer_two"]
        self.assertGreaterEqual(
            len(path_to_layer_two.edges),
            2,
            f"expected at least 2 edges to layer_two; got {path_to_layer_two.edges}",
        )

        # Cross-file guard resolution: require_admin() call inside
        # agent_action is imported from security.py and its body raises.
        main_tree = idx.get_ast("main.py")[1]
        require_admin_call = _find_call(main_tree, "require_admin")
        res = resolve_guard_call(require_admin_call, "main", idx)
        self.assertTrue(
            res.resolved,
            f"require_admin should resolve cross-file; evidence: {res.evidence}",
        )
        self.assertEqual(
            res.style,
            GuardStyle.ASSERT,
            f"require_admin body raises → ASSERT; got {res.style!r}: {res.evidence}",
        )
        self.assertEqual(res.confidence, ResolutionCertainty.RESOLVED)
        self.assertIsNotNone(res.body_inspection)
        self.assertTrue(res.body_inspection.raises_on_failure)
        self.assertFalse(res.body_inspection.returns_bool)
        # Evidence should mention the cross-file target.
        self.assertIn("security.require_admin", res.evidence)

    # ------------------------------------------------------------------
    # 2. Authority binding + transitive reach (cross-file authority & sink)
    # ------------------------------------------------------------------
    def test_authority_binding_with_transitive_reach(self) -> None:
        """Authority and sink live in different files but the *call
        sites* are inside ``refund_pipeline`` in main.py.

        ``def refund_pipeline(cust, amt): authorize_refund(cust, amt);
        process_refund(cust, amt)``

        Verifies:
          - The two cross-file callees resolve via the index (so the
            authority and sink are *real* cross-file functions, not
            phantoms).
          - :func:`compare_authority_to_sink` proves BOUND plumbing for
            the matching ``(cust, amt)`` parameters — both trace back
            to ``refund_pipeline``'s parameters of the same name.
        """
        root = _write_repo({
            "main.py": (
                "from auth import authorize_refund\n"
                "from sink import process_refund\n"
                "\n"
                "def refund_pipeline(cust, amt):\n"
                "    authorize_refund(cust, amt)\n"
                "    process_refund(cust, amt)\n"
            ),
            "auth.py": (
                "def authorize_refund(cust, amt):\n"
                "    pass\n"
            ),
            "sink.py": (
                "def process_refund(cust, amt):\n"
                "    pass\n"
            ),
        })
        idx = RepositoryIndex.build(Path(root))
        graph = build_call_graph(idx)

        # Verify the two cross-file callees ARE reachable from
        # refund_pipeline — proving the index resolved them.
        reachable = transitive_reachable(graph, ["main.refund_pipeline"])
        self.assertIn(
            "auth.authorize_refund",
            reachable,
            f"authority cross-file callee must resolve; got {sorted(reachable)}",
        )
        self.assertIn(
            "sink.process_refund",
            reachable,
            f"sink cross-file callee must resolve; got {sorted(reachable)}",
        )

        # Authority binding: both pairs (cust, amt) must be BOUND.
        main_tree = idx.get_ast("main.py")[1]
        func_node = _find_func(main_tree, "refund_pipeline")
        auth_call = _find_call(main_tree, "authorize_refund")
        sink_call = _find_call(main_tree, "process_refund")

        results = compare_all_authority_to_sink_params(
            auth_call, sink_call, func_node, index=idx, module_qname="main",
        )
        self.assertEqual(len(results), 2)
        for i, r in enumerate(results):
            self.assertEqual(
                r.state,
                BindingState.BOUND,
                f"pair {i}: expected BOUND (same plumbing), got "
                f"{r.state!r}: {r.evidence}",
            )
        self.assertEqual(
            overall_binding_state(results),
            BindingState.BOUND,
            "overall binding for matching (cust, amt) must be BOUND",
        )

    # ------------------------------------------------------------------
    # 3. Authority for a DIFFERENT action must not silently bind
    # ------------------------------------------------------------------
    def test_authority_binding_wrong_action_unbound(self) -> None:
        """``def f(cust, amt): authorize_read(cust); refund(cust, amt)``

        Even though ``cust`` matches at index 0, the authority is for a
        DIFFERENT action (read vs refund). The overall binding state
        MUST be UNBOUND or UNKNOWN — never BOUND — because authorizing
        a read does not authorize a refund.

        FIXED in this slice via the action-label soundness gate in
        `compare_authority_to_sink`: the authority's action label
        ('read', extracted from `authorize_read`) is compared against
        the sink's action label ('refund', inferred from `refund`)
        BEFORE the parameter-binding check. When the labels differ,
        the binding is provably UNBOUND regardless of parameter matching.
        """
        root = _write_repo({
            "main.py": (
                "def f(cust, amt):\n"
                "    authorize_read(cust)\n"
                "    refund(cust, amt)\n"
            ),
        })
        idx = RepositoryIndex.build(Path(root))
        main_tree = idx.get_ast("main.py")[1]
        func_node = _find_func(main_tree, "f")
        auth_call = _find_call(main_tree, "authorize_read")
        sink_call = _find_call(main_tree, "refund")

        results = compare_all_authority_to_sink_params(
            auth_call, sink_call, func_node, index=idx, module_qname="main",
        )
        overall = overall_binding_state(results)
        self.assertIn(
            overall,
            (BindingState.UNBOUND, BindingState.UNKNOWN),
            f"authority for 'read' must NOT bind to 'refund' sink; "
            f"got overall={overall!r}, results={[(r.state, r.evidence) for r in results]}",
        )
        # Critical: never BOUND.
        self.assertNotEqual(overall, BindingState.BOUND)

    # ------------------------------------------------------------------
    # 4. CFG dominance (case B) + authority binding
    # ------------------------------------------------------------------
    def test_cfg_dominance_with_authority_binding(self) -> None:
        """Case B from the CFG brief: guard BEFORE an if, sink AFTER.

        ``@tool def f(cust, amt): authorize_refund(cust, amt); if cond:
        log(); refund(cust, amt)``

        Verifies, in concert:
          - The CFG layer proves authorize_refund DOMINATES refund
            (every path to refund runs authorize_refund first).
          - The authority binding layer proves the (cust, amt) pairs
            are BOUND — same plumbing on both sides.
        """
        src = (
            "@tool\n"
            "def f(cust, amt):\n"
            "    authorize_refund(cust, amt)\n"
            "    if cond:\n"
            "        log()\n"
            "    refund(cust, amt)\n"
        )
        tree = ast.parse(src)
        func_node = _find_first_func(tree)

        # CFG dominance.
        cfg = build_cfg(func_node)
        doms = dominators(cfg)

        auth_line = _find_call(tree, "authorize_refund").lineno
        sink_line = _find_call(tree, "refund").lineno
        auth_id = cfg.find_node_containing_line(auth_line)
        sink_id = cfg.find_node_containing_line(sink_line)
        self.assertIsNotNone(auth_id, "no CFG node covers authorize_refund")
        self.assertIsNotNone(sink_id, "no CFG node covers refund")
        self.assertTrue(
            dominates(cfg, doms, auth_id, sink_id),
            "authorize_refund before the if must dominate refund after "
            "the if (every path runs authorize_refund first)",
        )

        # Authority binding: both (cust, amt) pairs BOUND.
        auth_call = _find_call(tree, "authorize_refund")
        sink_call = _find_call(tree, "refund")
        results = compare_all_authority_to_sink_params(auth_call, sink_call, func_node)
        self.assertEqual(len(results), 2)
        for i, r in enumerate(results):
            self.assertEqual(
                r.state,
                BindingState.BOUND,
                f"pair {i}: expected BOUND, got {r.state!r}: {r.evidence}",
            )
        self.assertEqual(overall_binding_state(results), BindingState.BOUND)

    # ------------------------------------------------------------------
    # 5. AUTHENTICATION is not ACTION-AUTHORIZATION
    # ------------------------------------------------------------------
    def test_authentication_does_not_authorize_refund(self) -> None:
        """``authenticate(user); refund(user, amt)``

        Hostile invariant: AUTHENTICATION proves *who* the caller is;
        it NEVER authorizes a specific action like refund. Asserts:
          - ``classify_guard_name("authenticate")`` returns
            :data:`GuardKind.AUTHENTICATION`.
          - ``is_action_authorization`` is False.
          - ``action_authorization_strength`` returns 'none'.
        """
        cls = classify_guard_name("authenticate")
        self.assertEqual(
            cls.kind,
            GuardKind.AUTHENTICATION,
            f"authenticate should be AUTHENTICATION; got {cls.kind!r}: {cls.evidence}",
        )
        self.assertFalse(
            cls.is_action_authorization,
            "AUTHENTICATION must NOT be action-authorization",
        )
        self.assertTrue(cls.is_identity_only)
        self.assertEqual(action_authorization_strength(cls), "none")

    # ------------------------------------------------------------------
    # 6. VALIDATION is not ACTION-AUTHORIZATION
    # ------------------------------------------------------------------
    def test_validation_does_not_authorize_email_send(self) -> None:
        """``validate_email(addr); send_email(addr, body)``

        Hostile invariant: VALIDATION proves an input is well-formed;
        it NEVER authorizes sending email. Asserts:
          - ``classify_guard_name("validate_email")`` returns
            :data:`GuardKind.VALIDATION`.
          - ``is_action_authorization`` is False.
          - ``action_authorization_strength`` returns 'none'.
        """
        cls = classify_guard_name("validate_email")
        self.assertEqual(
            cls.kind,
            GuardKind.VALIDATION,
            f"validate_email should be VALIDATION; got {cls.kind!r}: {cls.evidence}",
        )
        self.assertFalse(
            cls.is_action_authorization,
            "VALIDATION must NOT be action-authorization",
        )
        self.assertFalse(cls.is_identity_only)
        self.assertEqual(action_authorization_strength(cls), "none")


if __name__ == "__main__":
    unittest.main()
