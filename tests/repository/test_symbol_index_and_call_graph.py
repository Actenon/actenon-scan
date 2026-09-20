"""Unit tests for the repository symbol index.

These tests exercise every resolution case the symbol index claims to
support, including the explicit UNRESOLVED state for dynamic forms.
"""

from __future__ import annotations

import ast
import os
import tempfile
import unittest
from pathlib import Path

from actenon_scan.repository import (
    RepositoryIndex,
    ResolutionCertainty,
    SymbolKind,
    build_call_graph,
    transitive_reachable,
)
from actenon_scan.repository.symbol_index import ImportKind


# ---------------------------------------------------------------------------
# Helpers
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


# ---------------------------------------------------------------------------
# Symbol index resolution tests (Objective 1)
# ---------------------------------------------------------------------------


class SymbolIndexResolutionTests(unittest.TestCase):
    def test_direct_call_within_module(self) -> None:
        files = {
            "app.py": (
                "def handler():\n"
                "    run()\n"
                "def run():\n"
                "    pass\n"
            ),
        }
        idx = _index_sources(files)
        # `run` should resolve to app.run via the local-symbols map
        # (no import needed — it's defined in the same module).
        # We resolve the call site of `run()` inside `handler`.
        # Find the call site first.
        sites = idx.call_sites_in("app.handler")
        self.assertEqual(len(sites), 1)
        tree = idx.get_ast("app.py")[1]
        call_node = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.lineno == sites[0].location.line:
                call_node = node
                break
        self.assertIsNotNone(call_node)
        sym, certainty, qname = idx.resolve_call_target(call_node.func, "app")
        self.assertEqual(sym.name, "run")
        self.assertEqual(certainty, ResolutionCertainty.RESOLVED)
        self.assertEqual(qname, "app.run")

    def test_imported_function_call(self) -> None:
        files = {
            "main.py": (
                "from helpers import run\n"
                "def handler():\n"
                "    run()\n"
            ),
            "helpers.py": (
                "def run():\n"
                "    pass\n"
            ),
        }
        idx = _index_sources(files)
        sites = idx.call_sites_in("main.handler")
        self.assertEqual(len(sites), 1)
        tree = idx.get_ast("main.py")[1]
        call_node = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.lineno == sites[0].location.line:
                call_node = node
                break
        self.assertIsNotNone(call_node)
        sym, certainty, qname = idx.resolve_call_target(call_node.func, "main")
        self.assertIsNotNone(sym)
        self.assertEqual(sym.name, "run")
        self.assertEqual(certainty, ResolutionCertainty.RESOLVED)
        self.assertEqual(qname, "helpers.run")

    def test_aliased_import_call(self) -> None:
        files = {
            "main.py": (
                "from helpers import run as go\n"
                "def handler():\n"
                "    go()\n"
            ),
            "helpers.py": (
                "def run():\n"
                "    pass\n"
            ),
        }
        idx = _index_sources(files)
        sites = idx.call_sites_in("main.handler")
        tree = idx.get_ast("main.py")[1]
        call_node = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.lineno == sites[0].location.line:
                call_node = node
                break
        sym, certainty, qname = idx.resolve_call_target(call_node.func, "main")
        self.assertIsNotNone(sym)
        self.assertEqual(sym.name, "run")
        self.assertEqual(certainty, ResolutionCertainty.RESOLVED)
        self.assertEqual(qname, "helpers.run")

    def test_method_self_call(self) -> None:
        files = {
            "app.py": (
                "class Runner:\n"
                "    def go(self):\n"
                "        self._inner()\n"
                "    def _inner(self):\n"
                "        pass\n"
            ),
        }
        idx = _index_sources(files)
        sites = idx.call_sites_in("app.Runner.go")
        self.assertEqual(len(sites), 1)
        tree = idx.get_ast("app.py")[1]
        call_node = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.lineno == sites[0].location.line:
                call_node = node
                break
        sym, certainty, qname = idx.resolve_call_target(call_node.func, "app")
        self.assertIsNotNone(sym)
        self.assertEqual(sym.name, "_inner")
        self.assertEqual(certainty, ResolutionCertainty.RESOLVED)

    def test_unresolved_dynamic_call(self) -> None:
        files = {
            "app.py": (
                "def handler():\n"
                "    fn = getattr(someobj, 'do_thing')\n"
                "    fn()\n"
            ),
        }
        idx = _index_sources(files)
        sites = idx.call_sites_in("app.handler")
        # `fn()` is a bare-name call on a local var bound to a dynamic call.
        # We cannot resolve it — must be UNRESOLVED, never silently
        # promoted to a name match.
        tree = idx.get_ast("app.py")[1]
        call_node = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.lineno == sites[-1].location.line:
                call_node = node
                break
        sym, certainty, qname = idx.resolve_call_target(call_node.func, "app")
        self.assertIsNone(sym)
        self.assertEqual(certainty, ResolutionCertainty.UNRESOLVED)

    def test_same_name_functions_in_different_modules(self) -> None:
        """Two modules define a function called `run` — bare `run()` in a
        third module without an import must NOT resolve to either."""
        files = {
            "a.py": "def run():\n    pass\n",
            "b.py": "def run():\n    pass\n",
            "c.py": (
                "def handler():\n"
                "    run()\n"  # ambiguous without an import
            ),
        }
        idx = _index_sources(files)
        sites = idx.call_sites_in("c.handler")
        tree = idx.get_ast("c.py")[1]
        call_node = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.lineno == sites[0].location.line:
                call_node = node
                break
        sym, certainty, qname = idx.resolve_call_target(call_node.func, "c")
        # Must NOT silently resolve to a.py.run or b.py.run.
        self.assertIsNone(sym)
        self.assertEqual(certainty, ResolutionCertainty.UNRESOLVED)


# ---------------------------------------------------------------------------
# Call graph transitive reachability tests (Objective 2)
# ---------------------------------------------------------------------------


class CallGraphReachabilityTests(unittest.TestCase):
    def _build_graph(self, files: dict[str, str]) -> tuple[RepositoryIndex, "CallGraph"]:
        idx = _index_sources(files)
        from actenon_scan.repository import CallGraph
        g = build_call_graph(idx)
        return idx, g

    def test_depth_1_direct(self) -> None:
        files = {
            "app.py": (
                "@tool\n"
                "def agent_action():\n"
                "    subprocess.run(['ls'])\n"
            ),
        }
        _idx, g = self._build_graph(files)
        # agent_action calls subprocess.run (unresolved — subprocess is external)
        reach = transitive_reachable(g, ["app.agent_action"])
        # The entrypoint itself is reachable (empty path)
        self.assertIn("app.agent_action", reach)

    def test_depth_2(self) -> None:
        files = {
            "app.py": (
                "@tool\n"
                "def agent_action():\n"
                "    layer_one()\n"
                "def layer_one():\n"
                "    layer_two()\n"
                "def layer_two():\n"
                "    subprocess.run(['ls'])\n"
            ),
        }
        _idx, g = self._build_graph(files)
        reach = transitive_reachable(g, ["app.agent_action"])
        # layer_one and layer_two must be reachable.
        self.assertIn("app.layer_one", reach)
        self.assertIn("app.layer_two", reach)
        # The chain text must show the full path.
        path = reach["app.layer_two"]
        self.assertEqual(path.entrypoint, "app.agent_action")
        self.assertEqual(path.target, "app.layer_two")
        self.assertEqual(path.length, 2)
        chain = path.chain_text()
        self.assertIn("agent_action", chain)
        self.assertIn("layer_one", chain)
        self.assertIn("layer_two", chain)

    def test_depth_5(self) -> None:
        files = {
            "app.py": (
                "@tool\n"
                "def agent_action():\n"
                "    f1()\n"
                "def f1():\n"
                "    f2()\n"
                "def f2():\n"
                "    f3()\n"
                "def f3():\n"
                "    f4()\n"
                "def f4():\n"
                "    f5()\n"
                "def f5():\n"
                "    subprocess.run(['ls'])\n"
            ),
        }
        _idx, g = self._build_graph(files)
        reach = transitive_reachable(g, ["app.agent_action"])
        self.assertIn("app.f5", reach)
        path = reach["app.f5"]
        self.assertEqual(path.length, 5)
        self.assertEqual(path.entrypoint, "app.agent_action")

    def test_cross_file(self) -> None:
        files = {
            "main.py": (
                "from srv import process\n"
                "@tool\n"
                "def agent_action():\n"
                "    process()\n"
            ),
            "srv.py": (
                "def process():\n"
                "    subprocess.run(['rm'])\n"
            ),
        }
        idx, g = self._build_graph(files)
        reach = transitive_reachable(g, ["main.agent_action"])
        self.assertIn("srv.process", reach)
        path = reach["srv.process"]
        self.assertEqual(path.entrypoint, "main.agent_action")
        self.assertEqual(path.target, "srv.process")
        # The edge to srv.process should be RESOLVED.
        self.assertTrue(all(e.is_resolved() for e in path.edges))

    def test_imported_alias(self) -> None:
        files = {
            "main.py": (
                "from srv import process as go\n"
                "@tool\n"
                "def agent_action():\n"
                "    go()\n"
            ),
            "srv.py": (
                "def process():\n"
                "    subprocess.run(['rm'])\n"
            ),
        }
        _idx, g = self._build_graph(files)
        reach = transitive_reachable(g, ["main.agent_action"])
        self.assertIn("srv.process", reach)

    def test_recursion(self) -> None:
        files = {
            "app.py": (
                "@tool\n"
                "def agent_action():\n"
                "    recur(0)\n"
                "def recur(n):\n"
                "    if n < 10:\n"
                "        recur(n + 1)\n"
                "    subprocess.run(['ls'])\n"
            ),
        }
        _idx, g = self._build_graph(files)
        # Must not infinite-loop.
        reach = transitive_reachable(g, ["app.agent_action"], max_depth=16)
        self.assertIn("app.recur", reach)

    def test_mutual_recursion(self) -> None:
        files = {
            "app.py": (
                "@tool\n"
                "def agent_action():\n"
                "    a()\n"
                "def a():\n"
                "    b()\n"
                "def b():\n"
                "    a()\n"
                "    subprocess.run(['ls'])\n"
            ),
        }
        _idx, g = self._build_graph(files)
        reach = transitive_reachable(g, ["app.agent_action"], max_depth=16)
        self.assertIn("app.a", reach)
        self.assertIn("app.b", reach)

    def test_unreachable_helper(self) -> None:
        """A helper that is not called from any entrypoint must NOT be reachable."""
        files = {
            "app.py": (
                "@tool\n"
                "def agent_action():\n"
                "    used()\n"
                "def used():\n"
                "    pass\n"
                "def never_called():\n"
                "    subprocess.run(['rm'])\n"
            ),
        }
        _idx, g = self._build_graph(files)
        reach = transitive_reachable(g, ["app.agent_action"])
        self.assertIn("app.used", reach)
        self.assertNotIn("app.never_called", reach)

    def test_two_entrypoints_share_helper(self) -> None:
        files = {
            "app.py": (
                "@tool\n"
                "def entry_a():\n"
                "    shared()\n"
                "@tool\n"
                "def entry_b():\n"
                "    shared()\n"
                "def shared():\n"
                "    subprocess.run(['ls'])\n"
            ),
        }
        _idx, g = self._build_graph(files)
        reach = transitive_reachable(g, ["app.entry_a", "app.entry_b"])
        self.assertIn("app.shared", reach)
        path = reach["app.shared"]
        # Path should come from whichever entrypoint was first in the input list.
        self.assertEqual(path.entrypoint, "app.entry_a")


if __name__ == "__main__":
    unittest.main()
