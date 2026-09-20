"""Hostile tests for the repository-level analysis layers.

Every test in this file attempts to break a conservative invariant of
the new repository analysis modules. The test PASSES when the analyser
refuses to silently promote UNKNOWN → ASSERT / BOUND — i.e. when the
conservative invariant HOLDS.

Central mandate: FALSE ASSURANCE IS WORSE THAN A REVIEWABLE FALSE
POSITIVE. If the analyser were to silently treat an unresolved /
ambiguous / dynamic case as authoritative, a downstream consumer
might trust a guard that does not actually guard. These tests pin
the surfaces where such silent promotion would happen and verify it
does NOT.

Surfaces exercised:

- :func:`resolve_guard_call` (Slice 7) — dynamic dispatch, dual
  raise/return bodies, ambiguous guard names, external wrapper
  fallback.
- :func:`compare_authority_to_sink` (Slice 8) — unrecognized call
  args (UNKNOWN taint), parameter-swap (UNBOUND).
- :func:`classify_guard_name` / :func:`action_authorization_strength`
  (Slice 5) — AUTHENTICATION vs AUTHORIZATION discrimination.
- :func:`build_cfg` / :func:`dominates` (Slice 6) — loop body does
  not dominate after-loop code.
- :func:`propagate_effects` (Slice 3) — UNRESOLVED callees mark the
  summary incomplete.

When a test surfaces a real bug — i.e. the analyser WOULD silently
promote UNKNOWN to ASSERT/BOUND — the test is left intact (NOT
weakened) and ``unittest.skip`` is applied with a comment explaining
the bug. The finding is also recorded in the worklog.
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
    propagate_effects,
    resolve_guard_call,
    classify_guard_name,
    action_authorization_strength,
    compare_authority_to_sink,
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
    """Write a temp repo and return its root path."""
    tmp = tempfile.mkdtemp()
    for rel, src in files.items():
        p = Path(tmp) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    return tmp


def _find_call(tree: ast.Module, callee_name: str) -> ast.Call:
    """Find the first ``ast.Call`` (BFS order) whose callee matches."""
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


# ---------------------------------------------------------------------------
# Hostile invariants — UNKNOWN must never silently become ASSERT/BOUND
# ---------------------------------------------------------------------------


class HostileInvariantsTests(unittest.TestCase):

    # ------------------------------------------------------------------
    # 1. Dynamic dispatch guard: getattr(security, 'require_admin')() →
    #    UNKNOWN, never ASSERT.
    # ------------------------------------------------------------------
    def test_dynamic_dispatch_guard_remains_unknown(self) -> None:
        """``fn = getattr(security, 'require_admin'); fn()``

        The callee ``fn`` is a bare name bound to a dynamic
        ``getattr`` dispatch. The index has no local binding for
        ``fn`` (local-variable assignments are not tracked), and the
        name ``fn`` is not in the conservative assert-name set.
        Therefore :func:`resolve_guard_call` must return
        :data:`GuardStyle.UNKNOWN`, never silently ASSERT.
        """
        root = _write_repo({
            "app.py": (
                "def handler():\n"
                "    fn = getattr(security, 'require_admin')\n"
                "    fn()\n"
            ),
        })
        idx = RepositoryIndex.build(Path(root))
        tree = idx.get_ast("app.py")[1]
        call = _find_call(tree, "fn")
        res = resolve_guard_call(call, "app", idx)

        self.assertFalse(
            res.resolved,
            "dynamic-dispatch guard must not be marked resolved",
        )
        self.assertEqual(
            res.style,
            GuardStyle.UNKNOWN,
            f"dynamic-dispatch guard must be UNKNOWN, not ASSERT; "
            f"got {res.style!r}: {res.evidence}",
        )
        self.assertEqual(res.confidence, ResolutionCertainty.UNRESOLVED)
        self.assertIsNone(res.body_inspection)
        # CRITICAL: never silently promoted to ASSERT.
        self.assertNotEqual(res.style, GuardStyle.ASSERT)

    # ------------------------------------------------------------------
    # 2. Guard body with BOTH raise and return → UNKNOWN.
    # ------------------------------------------------------------------
    def test_both_raises_and_returns_guard_unknown(self) -> None:
        """``def guard(): if x: raise E('no'); return True``

        The guard body has BOTH a ``raise`` (in a branch) AND a
        top-level ``return True``. We cannot statically prove which
        path runs, so the conservative answer is UNKNOWN — never
        ASSERT (which would risk trusting a guard that might just
        return a bool and fall through).
        """
        root = _write_repo({
            "app.py": (
                "def handler():\n"
                "    guard()\n"
                "def guard():\n"
                "    if x:\n"
                "        raise E('no')\n"
                "    return True\n"
            ),
        })
        idx = RepositoryIndex.build(Path(root))
        tree = idx.get_ast("app.py")[1]
        call = _find_call(tree, "guard")
        res = resolve_guard_call(call, "app", idx)

        self.assertTrue(res.resolved)
        self.assertEqual(
            res.style,
            GuardStyle.UNKNOWN,
            f"both raise and return → UNKNOWN; got {res.style!r}: "
            f"{res.evidence}",
        )
        self.assertIsNotNone(res.body_inspection)
        self.assertTrue(res.body_inspection.raises_on_failure)
        self.assertTrue(res.body_inspection.returns_bool)
        # CRITICAL: never silently promoted to ASSERT.
        self.assertNotEqual(res.style, GuardStyle.ASSERT)

    # ------------------------------------------------------------------
    # 3. Authority arg is an unrecognized call → UNKNOWN, never BOUND.
    # ------------------------------------------------------------------
    def test_authority_unknown_never_silently_bound(self) -> None:
        """``def f(cust): authorize(get_dynamic_user()); refund(cust)``

        The authority's arg is an unrecognized call
        ``get_dynamic_user()`` — taint analysis cannot prove its
        provenance, so the taint state is UNKNOWN. Per the
        authority-binding invariant, UNKNOWN is NEVER silently
        promoted to BOUND.
        """
        src = (
            "def f(cust):\n"
            "    authorize(get_dynamic_user())\n"
            "    refund(cust)\n"
        )
        tree = ast.parse(src)
        func_node = _find_first_func(tree)
        auth_call = _find_call(tree, "authorize")
        sink_call = _find_call(tree, "refund")

        result = compare_authority_to_sink(auth_call, sink_call, func_node)
        self.assertEqual(
            result.state,
            BindingState.UNKNOWN,
            f"unrecognized authority arg → UNKNOWN, never BOUND; "
            f"got {result.state!r}: {result.evidence}",
        )
        # CRITICAL: never silently BOUND.
        self.assertNotEqual(result.state, BindingState.BOUND)

    # ------------------------------------------------------------------
    # 4. Authority parameter swap → UNBOUND for first pair.
    # ------------------------------------------------------------------
    def test_authority_param_swap_unbound(self) -> None:
        """``def f(cust, amt): authorize_refund(amt, cust); refund(cust, amt)``

        Params swapped. The authority's first arg is ``amt``, the
        sink's first arg is ``cust`` — provably different parameters
        → UNBOUND.
        """
        src = (
            "def f(cust, amt):\n"
            "    authorize_refund(amt, cust)\n"
            "    refund(cust, amt)\n"
        )
        tree = ast.parse(src)
        func_node = _find_first_func(tree)
        auth_call = _find_call(tree, "authorize_refund")
        sink_call = _find_call(tree, "refund")

        result = compare_authority_to_sink(
            auth_call,
            sink_call,
            func_node,
            authority_param_index=0,
            sink_param_index=0,
        )
        self.assertEqual(
            result.state,
            BindingState.UNBOUND,
            f"param-swap: first pair must be UNBOUND (amt vs cust); "
            f"got {result.state!r}: {result.evidence}",
        )
        self.assertIsNotNone(result.authority_provenance)
        self.assertIsNotNone(result.sink_provenance)
        self.assertEqual(result.authority_provenance.parameter_name, "amt")
        self.assertEqual(result.sink_provenance.parameter_name, "cust")

    # ------------------------------------------------------------------
    # 5. Ambiguous guard name 'check_permission' → UNKNOWN.
    #    CRITICAL hostile invariant: never silently ASSERT.
    # ------------------------------------------------------------------
    def test_ambiguous_guard_name_check_permission_unknown(self) -> None:
        """``check_permission(user)`` with no body evidence → UNKNOWN.

        ``check_permission`` is ambiguous — it could either raise on
        failure (ASSERT-style) or return a bool (PREDICATE-style).
        It is deliberately NOT in the conservative assert-name set
        (see ``actenon_scan.repository.guard_resolution``). With no
        body evidence (call unresolved to a definition), the
        conservative answer is UNKNOWN — NEVER ASSERT.
        """
        root = _write_repo({
            "app.py": (
                "def handler():\n"
                "    check_permission(user)\n"
            ),
        })
        idx = RepositoryIndex.build(Path(root))
        tree = idx.get_ast("app.py")[1]
        call = _find_call(tree, "check_permission")
        res = resolve_guard_call(call, "app", idx)

        self.assertFalse(
            res.resolved,
            "check_permission with no body evidence must not be resolved",
        )
        self.assertEqual(
            res.style,
            GuardStyle.UNKNOWN,
            f"check_permission must be UNKNOWN, never ASSERT; got "
            f"{res.style!r}: {res.evidence}",
        )
        self.assertEqual(res.confidence, ResolutionCertainty.UNRESOLVED)
        self.assertIsNone(res.body_inspection)
        # CRITICAL: never silently promoted to ASSERT.
        self.assertNotEqual(res.style, GuardStyle.ASSERT)
        # Evidence must NOT claim assert-style matching.
        self.assertNotIn("assert-style", res.evidence)
        self.assertNotIn("name heuristic", res.evidence)
        self.assertIn("check_permission", res.evidence)

    # ------------------------------------------------------------------
    # 6. Recursive authority helper must not infinite-loop.
    # ------------------------------------------------------------------
    def test_recursive_authority_path_does_not_crash(self) -> None:
        """``def authorize(cust): if cond: authorize(cust); raise ...``

        A recursive authority helper. :func:`inspect_guard_body` uses
        ``ast.walk`` (does NOT follow call edges), so it must
        terminate even when the authority's body calls itself. The
        test verifies :func:`resolve_guard_call` and
        :func:`compare_authority_to_sink` both terminate on such a
        recursive helper — the analyser must never infinite-loop.
        """
        root = _write_repo({
            "app.py": (
                "def f(cust):\n"
                "    authorize(cust)\n"
                "    refund(cust)\n"
                "\n"
                "def authorize(cust):\n"
                "    if cond:\n"
                "        authorize(cust)\n"
                "    raise RuntimeError('forbidden')\n"
            ),
        })
        idx = RepositoryIndex.build(Path(root))
        tree = idx.get_ast("app.py")[1]

        # resolve_guard_call on the authorize() call inside f.
        auth_call_in_f = _find_call(tree, "authorize")
        res = resolve_guard_call(auth_call_in_f, "app", idx)
        # Body has a raise (after the if), no top-level return → ASSERT.
        self.assertTrue(res.resolved)
        self.assertEqual(res.style, GuardStyle.ASSERT)
        self.assertIsNotNone(res.body_inspection)
        self.assertTrue(res.body_inspection.raises_on_failure)

        # compare_authority_to_sink on the two args (both `cust`) —
        # must terminate and return BOUND (same parameter 'cust').
        sink_call_in_f = _find_call(tree, "refund")
        func_f = None
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "f":
                func_f = node
                break
        self.assertIsNotNone(func_f)
        result = compare_authority_to_sink(
            auth_call_in_f, sink_call_in_f, func_f,
        )
        self.assertEqual(result.state, BindingState.BOUND)

    # ------------------------------------------------------------------
    # 7. CFG: guard inside a loop body does NOT dominate after-loop.
    # ------------------------------------------------------------------
    def test_cfg_loop_guard_does_not_dominate_after(self) -> None:
        """``def f(): for x in items: authorize(x); sink()``

        The loop may execute zero times (empty ``items``), so
        ``authorize`` inside the loop body does NOT dominate ``sink``
        after the loop. Per the CFG brief, this is the conservative
        invariant: a guard inside a loop body must NOT be trusted to
        guard code that runs after the loop.
        """
        src = (
            "def f():\n"
            "    for x in items:\n"
            "        authorize(x)\n"
            "    sink()\n"
        )
        tree = ast.parse(src)
        func_node = _find_first_func(tree)
        cfg = build_cfg(func_node)
        doms = dominators(cfg)

        auth_line = _find_call(tree, "authorize").lineno
        sink_line = _find_call(tree, "sink").lineno
        auth_id = cfg.find_node_containing_line(auth_line)
        sink_id = cfg.find_node_containing_line(sink_line)
        self.assertIsNotNone(auth_id, "no CFG node covers authorize")
        self.assertIsNotNone(sink_id, "no CFG node covers sink")
        self.assertFalse(
            dominates(cfg, doms, auth_id, sink_id),
            "guard inside loop body must NOT dominate code after the "
            "loop (the loop may execute zero times)",
        )

    # ------------------------------------------------------------------
    # 8. External guard (Depends(require_admin)) → HEURISTIC, not RESOLVED.
    # ------------------------------------------------------------------
    def test_external_guard_falls_back_to_heuristic_not_resolved(self) -> None:
        """``from fastapi import Depends; Depends(require_admin)``

        The primary callee ``Depends`` is external (FastAPI), so we
        cannot resolve a body. The wrapper-case inspection finds the
        arg ``require_admin`` and matches the conservative name
        heuristic. Crucially, the resolution confidence is
        :data:`ResolutionCertainty.HEURISTIC`, NOT RESOLVED — so
        downstream consumers know this is name-evidence-only and
        must NOT treat it as a body-inspected assertion.
        """
        root = _write_repo({
            "main.py": (
                "from fastapi import Depends\n"
                "def handler():\n"
                "    Depends(require_admin)\n"
            ),
        })
        idx = RepositoryIndex.build(Path(root))
        tree = idx.get_ast("main.py")[1]
        call = _find_call(tree, "Depends")
        res = resolve_guard_call(call, "main", idx)

        self.assertFalse(
            res.resolved,
            "external Depends(...) must not be marked resolved",
        )
        self.assertEqual(
            res.style,
            GuardStyle.ASSERT,
            f"wrapper-case inspection found require_admin name; got "
            f"{res.style!r}: {res.evidence}",
        )
        # CRITICAL: confidence is HEURISTIC (name-evidence only),
        # NOT RESOLVED (no body inspection).
        self.assertEqual(res.confidence, ResolutionCertainty.HEURISTIC)
        self.assertNotEqual(res.confidence, ResolutionCertainty.RESOLVED)
        self.assertIsNone(res.body_inspection)
        self.assertIn("require_admin", res.evidence)
        self.assertIn("name heuristic", res.evidence)

    # ------------------------------------------------------------------
    # 9. Semantic kind: authenticate != authorize_user (action-authz).
    # ------------------------------------------------------------------
    def test_semantic_kind_prevents_action_authorization_claim(self) -> None:
        """Hostile scenario: ``authenticate(user); authorize_user(user);
        refund(user, amt)``

        The semantic guard taxonomy MUST distinguish:
          - ``authenticate`` → :data:`GuardKind.AUTHENTICATION` (
            ``is_action_authorization=False`` — proves *who*, not
            *what they may do*).
          - ``authorize_user`` → :data:`GuardKind.AUTHORIZATION` (
            ``is_action_authorization=True`` — can authorize a refund
            when the action parameter is bound).

        Without this discrimination, an attacker could pass an
        ``authenticate(user)`` guard and the analyser would treat
        ``refund`` as authorized. The taxonomy layer prevents that.
        """
        auth_cls = classify_guard_name("authenticate")
        authz_cls = classify_guard_name("authorize_user")

        # AUTHENTICATION — never action-authorization.
        self.assertEqual(
            auth_cls.kind,
            GuardKind.AUTHENTICATION,
            f"authenticate should be AUTHENTICATION; got {auth_cls.kind!r}",
        )
        self.assertFalse(
            auth_cls.is_action_authorization,
            "AUTHENTICATION must NOT be action-authorization",
        )
        self.assertTrue(auth_cls.is_identity_only)
        self.assertEqual(action_authorization_strength(auth_cls), "none")

        # AUTHORIZATION — action-authorization when bound.
        self.assertEqual(
            authz_cls.kind,
            GuardKind.AUTHORIZATION,
            f"authorize_user should be AUTHORIZATION; got {authz_cls.kind!r}",
        )
        self.assertTrue(
            authz_cls.is_action_authorization,
            "AUTHORIZATION must be action-authorization",
        )
        self.assertFalse(authz_cls.is_identity_only)
        self.assertEqual(action_authorization_strength(authz_cls), "strong")

        # CRITICAL: the two are distinguished — authenticate's
        # is_action_authorization is False, authorize_user's is True.
        self.assertNotEqual(
            auth_cls.is_action_authorization,
            authz_cls.is_action_authorization,
            "authenticate and authorize_user MUST be distinguished on "
            "is_action_authorization (the hostile-test invariant)",
        )

    # ------------------------------------------------------------------
    # 10. UNRESOLVED callee → effect summary's has_unresolved_callee=True.
    # ------------------------------------------------------------------
    def test_unresolved_callee_marks_summary_incomplete(self) -> None:
        """A function calling an unresolved callee has
        ``has_unresolved_callee=True`` per its effect summary.

        This is the "incomplete" property: a function whose call set
        includes a dynamic / unrecognized callee has an *incomplete*
        effect set — downstream authority analysis must NOT treat it
        as silently safe.
        """
        root = _write_repo({
            "app.py": (
                "def f():\n"
                "    do_dynamic_thing()\n"
            ),
        })
        idx = RepositoryIndex.build(Path(root))
        graph = build_call_graph(idx)

        # Sanity: the call graph has an UNRESOLVED edge from app.f to
        # the textual callee 'do_dynamic_thing'.
        edges = graph.edges_by_caller.get("app.f", [])
        self.assertGreaterEqual(
            len(edges), 1, f"app.f should have at least one edge; got {edges}",
        )
        self.assertTrue(
            any(e.is_unresolved() for e in edges),
            f"app.f should have an UNRESOLVED edge; got {edges}",
        )

        # Effect propagation: the summary must mark has_unresolved_callee.
        prop = propagate_effects(graph)
        summary = prop.summaries.get("app.f")
        self.assertIsNotNone(
            summary,
            f"app.f summary must exist; got {sorted(prop.summaries)}",
        )
        self.assertTrue(
            summary.has_unresolved_callee,
            "app.f calls an unresolved callee → summary must be marked "
            "incomplete (has_unresolved_callee=True); never silently safe",
        )
        # The 'incomplete' list must include app.f.
        self.assertIn("app.f", prop.incomplete)


if __name__ == "__main__":
    unittest.main()
