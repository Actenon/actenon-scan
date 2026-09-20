"""Unit tests for cross-file guard body inspection (Slice 7).

These tests exercise the cross-file guard resolver's:

- ASSERT-style body inspection (raise on failure)
- PREDICATE-style body inspection (top-level bool return)
- cross-file resolution (guard imported via from-import)
- dynamic-dispatch UNRESOLVED → UNKNOWN
- both-raise-and-return → UNKNOWN (conservative)
- wrapper-call fallback (Depends(require_admin))
- no-raise-no-return → UNKNOWN
- ambiguous name (check_permission) → UNKNOWN (CRITICAL hostile
  invariant: never silently promote to ASSERT)
- authentication != action-authorization hostile invariant
"""
from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from actenon_scan.repository import RepositoryIndex, ResolutionCertainty
from actenon_scan.repository.guard_resolution import (
    GuardResolution,
    GuardStyle,
    inspect_guard_body,
    resolve_guard_call,
)


# ---------------------------------------------------------------------------
# Helpers (mirrors tests/repository/test_symbol_index_and_call_graph.py)
# ---------------------------------------------------------------------------


def _index_sources(files: dict[str, str]) -> RepositoryIndex:
    """Build an index from a {relpath: source} map, with a temp root."""
    tmp = tempfile.mkdtemp()
    root = Path(tmp)
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    return RepositoryIndex.build(root)


def _find_call(tree: ast.Module, callee_name: str) -> ast.Call:
    """Find the first Call node (BFS order) whose func matches `callee_name`."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            n: str | None = None
            if isinstance(f, ast.Name):
                n = f.id
            elif isinstance(f, ast.Attribute):
                n = f.attr
            if n == callee_name:
                return node
    raise AssertionError(f"No Call node with callee {callee_name!r}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class GuardResolutionTests(unittest.TestCase):
    def test_assert_style_guard_raises_on_failure(self) -> None:
        files = {
            "app.py": (
                "def handler():\n"
                "    require_admin()\n"
                "def require_admin():\n"
                "    if not is_admin():\n"
                "        raise RuntimeError('not admin')\n"
            ),
        }
        idx = _index_sources(files)
        tree = idx.get_ast("app.py")[1]
        call = _find_call(tree, "require_admin")
        res = resolve_guard_call(call, "app", idx)

        self.assertTrue(res.resolved)
        self.assertEqual(res.style, GuardStyle.ASSERT)
        self.assertEqual(res.confidence, ResolutionCertainty.RESOLVED)
        self.assertIn("require_admin", res.evidence)
        self.assertIn("raises at line", res.evidence)
        self.assertIsNotNone(res.body_inspection)
        self.assertTrue(res.body_inspection.raises_on_failure)
        self.assertFalse(res.body_inspection.returns_bool)
        self.assertFalse(res.body_inspection.has_unconditional_raise)

    def test_predicate_style_guard_returns_bool(self) -> None:
        files = {
            "app.py": (
                "def handler():\n"
                "    if is_admin():\n"
                "        do_refund()\n"
                "def is_admin() -> bool:\n"
                "    return user.role == 'admin'\n"
            ),
        }
        idx = _index_sources(files)
        tree = idx.get_ast("app.py")[1]
        call = _find_call(tree, "is_admin")
        res = resolve_guard_call(call, "app", idx)

        self.assertTrue(res.resolved)
        self.assertEqual(res.style, GuardStyle.PREDICATE)
        self.assertEqual(res.confidence, ResolutionCertainty.RESOLVED)
        self.assertIn("returns at line", res.evidence)
        self.assertIsNotNone(res.body_inspection)
        self.assertTrue(res.body_inspection.returns_bool)
        self.assertFalse(res.body_inspection.raises_on_failure)

    def test_cross_file_guard_resolved(self) -> None:
        files = {
            "main.py": (
                "from security import require_admin\n"
                "def handler():\n"
                "    require_admin()\n"
            ),
            "security.py": (
                "def require_admin():\n"
                "    raise RuntimeError('forbidden')\n"
            ),
        }
        idx = _index_sources(files)
        tree = idx.get_ast("main.py")[1]
        call = _find_call(tree, "require_admin")
        res = resolve_guard_call(call, "main", idx)

        self.assertTrue(res.resolved)
        self.assertEqual(res.style, GuardStyle.ASSERT)
        self.assertEqual(res.confidence, ResolutionCertainty.RESOLVED)
        self.assertIn("security.require_admin", res.evidence)
        self.assertIn("raises at line", res.evidence)
        self.assertIsNotNone(res.body_inspection)
        self.assertTrue(res.body_inspection.raises_on_failure)
        # The raise is at the top level of the function body — the
        # stronger "unconditional raise" signal fires.
        self.assertTrue(res.body_inspection.has_unconditional_raise)

    def test_dynamic_dispatch_guard_unknown(self) -> None:
        files = {
            "app.py": (
                "def handler():\n"
                "    fn = getattr(obj, 'guard')\n"
                "    fn()\n"
            ),
        }
        idx = _index_sources(files)
        tree = idx.get_ast("app.py")[1]
        call = _find_call(tree, "fn")
        res = resolve_guard_call(call, "app", idx)

        self.assertFalse(res.resolved)
        self.assertEqual(res.style, GuardStyle.UNKNOWN)
        self.assertEqual(res.confidence, ResolutionCertainty.UNRESOLVED)
        self.assertIsNone(res.body_inspection)

    def test_guard_both_raises_and_returns_unknown(self) -> None:
        # CRITICAL: a guard with BOTH a raise and a top-level return is
        # UNKNOWN — never silently promoted to ASSERT.
        files = {
            "app.py": (
                "def handler():\n"
                "    guard()\n"
                "def guard():\n"
                "    if x:\n"
                "        raise E('no')\n"
                "    return True\n"
            ),
        }
        idx = _index_sources(files)
        tree = idx.get_ast("app.py")[1]
        call = _find_call(tree, "guard")
        res = resolve_guard_call(call, "app", idx)

        self.assertTrue(res.resolved)
        self.assertEqual(res.style, GuardStyle.UNKNOWN)
        self.assertIsNotNone(res.body_inspection)
        self.assertTrue(res.body_inspection.raises_on_failure)
        self.assertTrue(res.body_inspection.returns_bool)

    def test_external_guard_falls_back_to_name_heuristic(self) -> None:
        files = {
            "main.py": (
                "from fastapi import Depends\n"
                "def handler():\n"
                "    Depends(require_admin)\n"
            ),
        }
        idx = _index_sources(files)
        tree = idx.get_ast("main.py")[1]
        call = _find_call(tree, "Depends")
        res = resolve_guard_call(call, "main", idx)

        self.assertFalse(res.resolved)
        self.assertEqual(res.style, GuardStyle.ASSERT)
        self.assertEqual(res.confidence, ResolutionCertainty.HEURISTIC)
        self.assertIn("require_admin", res.evidence)
        self.assertIn("name heuristic", res.evidence)

    def test_guard_no_return_no_raise_unknown(self) -> None:
        files = {
            "app.py": (
                "def handler():\n"
                "    guard()\n"
                "def guard():\n"
                "    pass\n"
            ),
        }
        idx = _index_sources(files)
        tree = idx.get_ast("app.py")[1]
        call = _find_call(tree, "guard")
        res = resolve_guard_call(call, "app", idx)

        self.assertTrue(res.resolved)
        self.assertEqual(res.style, GuardStyle.UNKNOWN)
        self.assertIsNotNone(res.body_inspection)
        self.assertFalse(res.body_inspection.raises_on_failure)
        self.assertFalse(res.body_inspection.returns_bool)
        self.assertFalse(res.body_inspection.has_unconditional_raise)
        self.assertFalse(res.body_inspection.has_return_statement)

    def test_ambiguous_guard_name_unknown(self) -> None:
        # CRITICAL hostile invariant: check_permission is ambiguous
        # (could return bool rather than raise) and MUST NOT be
        # promoted to ASSERT, even though it sounds like an
        # authorization guard. Bias to UNKNOWN.
        files = {
            "app.py": (
                "def handler():\n"
                "    check_permission(user)\n"
            ),
        }
        idx = _index_sources(files)
        tree = idx.get_ast("app.py")[1]
        call = _find_call(tree, "check_permission")
        res = resolve_guard_call(call, "app", idx)

        self.assertFalse(res.resolved)
        self.assertEqual(res.style, GuardStyle.UNKNOWN)
        self.assertEqual(res.confidence, ResolutionCertainty.UNRESOLVED)
        self.assertIsNone(res.body_inspection)
        # The evidence must NOT claim assert-style matching.
        self.assertNotIn("assert-style", res.evidence)
        self.assertNotIn("name heuristic", res.evidence)
        self.assertIn("check_permission", res.evidence)

    def test_authentication_does_not_authorize_refund(self) -> None:
        # CRITICAL hostile invariant: authenticate(user) is ASSERT
        # (it does raise), but its evidence must distinguish
        # AUTHENTICATION from ACTION-AUTHORIZATION. A sink
        # refund(amount) guarded only by authenticate(user) must NOT
        # be treated as authorized.
        files = {
            "app.py": (
                "def handler():\n"
                "    authenticate(user)\n"
                "    refund(amount)\n"
                "def authenticate(user):\n"
                "    if not user.valid:\n"
                "        raise RuntimeError('not authenticated')\n"
                "def refund(amount):\n"
                "    pass\n"
            ),
        }
        idx = _index_sources(files)
        tree = idx.get_ast("app.py")[1]
        call = _find_call(tree, "authenticate")
        res = resolve_guard_call(call, "app", idx)

        # authenticate is assert-style: it raises on failure.
        self.assertTrue(res.resolved)
        self.assertEqual(res.style, GuardStyle.ASSERT)
        # BUT the evidence string must clearly distinguish authentication
        # from action authorization — authenticate(user) does NOT
        # authorize the refund(amount) sink.
        self.assertIn(
            "authentication only, not action authorization",
            res.evidence,
        )
        self.assertIn("authenticate", res.evidence)
        self.assertIn("raises at line", res.evidence)


# ---------------------------------------------------------------------------
# Sanity test for inspect_guard_body directly (covers the public API
# surface not exercised through resolve_guard_call).
# ---------------------------------------------------------------------------


class InspectGuardBodyDirectTests(unittest.TestCase):
    def test_inspect_body_returns_unresolved_when_no_ast(self) -> None:
        files = {
            "app.py": (
                "def guard():\n"
                "    raise RuntimeError()\n"
            ),
        }
        idx = _index_sources(files)
        sym = idx.lookup_symbol("app.guard")
        self.assertIsNotNone(sym)
        # Build a different index whose AST cache is gone — we can
        # simulate this by directly calling inspect_guard_body on a
        # symbol whose file isn't in the index. Easiest path: make a
        # fresh index that has no files.
        empty_idx = RepositoryIndex()
        empty_idx.finalize()
        body = inspect_guard_body(sym, empty_idx)
        self.assertEqual(
            body.inspection_certainty, ResolutionCertainty.UNRESOLVED
        )
        self.assertFalse(body.raises_on_failure)
        self.assertFalse(body.returns_bool)

    def test_inspect_body_unconditional_raise_top_level(self) -> None:
        files = {
            "app.py": (
                "def guard():\n"
                "    raise RuntimeError('always')\n"
            ),
        }
        idx = _index_sources(files)
        sym = idx.lookup_symbol("app.guard")
        self.assertIsNotNone(sym)
        body = inspect_guard_body(sym, idx)
        self.assertEqual(
            body.inspection_certainty, ResolutionCertainty.RESOLVED
        )
        self.assertTrue(body.raises_on_failure)
        self.assertTrue(body.has_unconditional_raise)
        self.assertFalse(body.returns_bool)
        self.assertEqual(body.evidence_lines, (2,))


if __name__ == "__main__":
    unittest.main()
