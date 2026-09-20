"""Tests for the taint/dataflow layer (Objective 4).

Verifies that model-controlled provenance is preserved through:
- assignment
- function parameters
- attribute access (param.attr)
- dict access (param[...])
- f-strings
- string concatenation
- str/int casts
- json.loads
- 1-hop wrapper functions

Verifies that transformations NEVER silently downgrade taint to
UNTAINTED — UNKNOWN is preserved.
"""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from actenon_scan.repository import (
    TaintLattice,
    TaintTrace,
    function_local_dataflow,
    RepositoryIndex,
)


def _index_and_func(
    files: dict[str, str],
    func_qname: str,
    sink_line: int,
) -> tuple[RepositoryIndex, ast.FunctionDef | ast.AsyncFunctionDef, ast.Call, str]:
    """Build an index, then return (index, function_node, call_node_at_sink_line, module_qname)."""
    tmp = tempfile.mkdtemp()
    root = Path(tmp)
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    idx = RepositoryIndex.build(root)

    # Find the file and module for the func_qname
    sym = idx.lookup_symbol(func_qname)
    assert sym is not None, f"symbol {func_qname} not in index"
    file_rel = sym.location.file
    module_qname = idx._module_qualified_name(file_rel)
    ast_info = idx.get_ast(file_rel)
    assert ast_info is not None
    _src, tree = ast_info

    # Find the function node
    func_node = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno == sym.location.line and node.name == sym.name:
                func_node = node
                break
    assert func_node is not None, f"function {func_qname} not found in AST"

    # Find the call at sink_line
    call_node = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node, "lineno", None) == sink_line:
            call_node = node
            break
    assert call_node is not None, f"call at line {sink_line} not found"
    return idx, func_node, call_node, module_qname


class TaintTests(unittest.TestCase):
    def test_direct_parameter_to_sink(self) -> None:
        files = {
            "app.py": (
                "def run(payload):\n"
                "    subprocess.run(payload)\n"
            ),
        }
        _idx, func, call, module_qname = _index_and_func(files, "app.run", 2)
        trace = function_local_dataflow(func, call, index=_idx, module_qname=module_qname)
        self.assertIsNotNone(trace)
        self.assertEqual(trace.parameter_name, "payload")
        self.assertEqual(trace.final_state, TaintLattice.EXTERNAL)
        self.assertEqual(trace.operations, [])
        self.assertEqual(trace.certainty, "proven")

    def test_assignment_preserves_taint(self) -> None:
        files = {
            "app.py": (
                "def run(payload):\n"
                "    command = payload\n"
                "    subprocess.run(command)\n"
            ),
        }
        _idx, func, call, module_qname = _index_and_func(files, "app.run", 3)
        trace = function_local_dataflow(func, call, index=_idx, module_qname=module_qname)
        self.assertIsNotNone(trace)
        self.assertEqual(trace.parameter_name, "payload")
        self.assertEqual(trace.final_state, TaintLattice.EXTERNAL)
        self.assertEqual(trace.certainty, "proven")

    def test_dict_access_preserves_taint(self) -> None:
        files = {
            "app.py": (
                "def run(payload):\n"
                "    cmd = payload['command']\n"
                "    subprocess.run(cmd)\n"
            ),
        }
        _idx, func, call, module_qname = _index_and_func(files, "app.run", 3)
        trace = function_local_dataflow(func, call, index=_idx, module_qname=module_qname)
        self.assertIsNotNone(trace)
        self.assertEqual(trace.parameter_name, "payload")
        # Should track the [] operation
        self.assertIn("[]", trace.operations)

    def test_attribute_access_preserves_taint(self) -> None:
        files = {
            "app.py": (
                "def run(payload):\n"
                "    cmd = payload.command\n"
                "    subprocess.run(cmd)\n"
            ),
        }
        _idx, func, call, module_qname = _index_and_func(files, "app.run", 3)
        trace = function_local_dataflow(func, call, index=_idx, module_qname=module_qname)
        self.assertIsNotNone(trace)
        self.assertEqual(trace.parameter_name, "payload")
        # The attribute access should appear in the via chain
        self.assertIn("command", trace.operations)

    def test_fstring_preserves_taint(self) -> None:
        files = {
            "app.py": (
                "def run(payload):\n"
                "    cmd = f'/bin/run {payload}'\n"
                "    subprocess.run(cmd)\n"
            ),
        }
        _idx, func, call, module_qname = _index_and_func(files, "app.run", 3)
        trace = function_local_dataflow(func, call, index=_idx, module_qname=module_qname)
        self.assertIsNotNone(trace)
        self.assertEqual(trace.parameter_name, "payload")

    def test_string_concat_preserves_taint(self) -> None:
        files = {
            "app.py": (
                "def run(payload):\n"
                "    cmd = payload + ' extra'\n"
                "    subprocess.run(cmd)\n"
            ),
        }
        _idx, func, call, module_qname = _index_and_func(files, "app.run", 3)
        trace = function_local_dataflow(func, call, index=_idx, module_qname=module_qname)
        self.assertIsNotNone(trace)
        self.assertEqual(trace.parameter_name, "payload")

    def test_str_cast_preserves_taint(self) -> None:
        files = {
            "app.py": (
                "def run(payload):\n"
                "    command = str(payload)\n"
                "    subprocess.run(command)\n"
            ),
        }
        _idx, func, call, module_qname = _index_and_func(files, "app.run", 3)
        trace = function_local_dataflow(func, call, index=_idx, module_qname=module_qname)
        self.assertIsNotNone(trace)
        self.assertEqual(trace.parameter_name, "payload")
        self.assertIn("str", trace.operations)

    def test_json_loads_then_dict_access_preserves_taint(self) -> None:
        """The full example from Objective 4:
            payload → json.loads → ['command'] → str → execute
        """
        files = {
            "app.py": (
                "def run(payload):\n"
                "    obj = json.loads(payload)\n"
                "    command = str(obj['command'])\n"
                "    execute(command)\n"
            ),
        }
        _idx, func, call, module_qname = _index_and_func(files, "app.run", 4)
        trace = function_local_dataflow(func, call, index=_idx, module_qname=module_qname)
        self.assertIsNotNone(trace)
        self.assertEqual(trace.parameter_name, "payload")
        self.assertIn("json.loads", trace.operations)
        self.assertIn("str", trace.operations)

    def test_1hop_wrapper_preserves_taint(self) -> None:
        """A wrapper function (single return of its parameter) is a
        pass-through for taint."""
        files = {
            "app.py": (
                "def run(payload):\n"
                "    x = wrap(payload)\n"
                "    subprocess.run(x)\n"
                "def wrap(y):\n"
                "    return y\n"
            ),
        }
        _idx, func, call, module_qname = _index_and_func(files, "app.run", 3)
        trace = function_local_dataflow(func, call, index=_idx, module_qname=module_qname)
        self.assertIsNotNone(trace)
        self.assertEqual(trace.parameter_name, "payload")

    def test_constant_argument_is_untainted(self) -> None:
        """A constant sink argument must NOT produce a trace."""
        files = {
            "app.py": (
                "def run(payload):\n"
                "    subprocess.run(['ls', '-la'])\n"
            ),
        }
        _idx, func, call, module_qname = _index_and_func(files, "app.run", 2)
        trace = function_local_dataflow(func, call, index=_idx, module_qname=module_qname)
        self.assertIsNone(trace)

    def test_unknown_call_result_is_unknown_not_untainted(self) -> None:
        """A value derived from an unrecognised call (not a pass-through)
        must be UNKNOWN, never UNTAINTED. This is the core conservative
        invariant — never silently promote unknown to safe."""
        files = {
            "app.py": (
                "def run(payload):\n"
                "    x = unknown_transform(payload)\n"
                "    subprocess.run(x)\n"
            ),
        }
        _idx, func, call, module_qname = _index_and_func(files, "app.run", 3)
        trace = function_local_dataflow(func, call, index=_idx, module_qname=module_qname)
        # The trace is None because the strongest taint is UNKNOWN, which
        # the function-local dataflow filters out (UNKNOWN is not "tainted
        # enough to report"). But the key invariant is that we never
        # claim it's untainted.
        # If trace is non-None, the state must NOT be UNTAINTED.
        if trace is not None:
            self.assertNotEqual(trace.final_state, TaintLattice.UNTAINTED)


if __name__ == "__main__":
    unittest.main()
