"""Tests for guard detection."""

import ast
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from actenon_scan.engine import (
    _callee_name,
    _find_declarative_guarded_classes,
    scan_path,
)
from actenon_scan.rules.loader import load_rules

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class GuardTests(unittest.TestCase):
    def test_safe_actenon_guard_no_findings(self):
        """refund_tool_actenon.py has an actenon verify_proof call before the sink."""
        result = scan_path(FIXTURES / "safe" / "refund_tool_actenon.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertEqual(0, len(findings), "refund_tool_actenon.py should have no findings — guarded by actenon")

    def test_safe_generic_guard_no_findings(self):
        """refund_tool_generic.py has a generic authorize() call before the sink."""
        result = scan_path(FIXTURES / "safe" / "refund_tool_generic.py")
        findings = [f for f in result.findings if not f.suppressed]
        self.assertEqual(0, len(findings), "refund_tool_generic.py should have no findings — guarded by generic authorize()")


class CalleeNameTests(unittest.TestCase):
    """Direct tests for _callee_name — the helper that fixes the v0.2.2 crash.

    ast.Name exposes `.id`, NOT `.name`. Only ClassDef/FunctionDef have `.name`.
    The pre-fix code did `node.func.name` on every Call whose func was a Name,
    which crashed with AttributeError on any plain constructor call.
    """

    def _func_of_first_call(self, src: str) -> ast.expr:
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                return node.func
        raise AssertionError(f"no Call in: {src!r}")

    def test_plain_name_call(self):
        # The crash case from v0.2.2: Tool(dependencies=[...])
        func = self._func_of_first_call("Tool(dependencies=[1, 2])\n")
        self.assertEqual(_callee_name(func), "Tool")

    def test_attribute_call(self):
        # module.Tool(...)
        func = self._func_of_first_call("pkg.Tool(dependencies=[1])\n")
        self.assertEqual(_callee_name(func), "Tool")

    def test_chained_call(self):
        # Foo()(...)
        func = self._func_of_first_call("Foo()(dependencies=[1])\n")
        self.assertEqual(_callee_name(func), "Foo")

    def test_lambda_call_returns_none(self):
        # No useful name — must return None, not crash.
        func = self._func_of_first_call("(lambda x: x)(dependencies=[1])\n")
        self.assertIsNone(_callee_name(func))


class DeclarativeGuardConstructorParamsTests(unittest.TestCase):
    """Regression tests for the v0.2.2 release-blocking crash.

    The constructor_params branch of _find_declarative_guarded_classes must:
      - not crash on plain Name calls (the bug)
      - not crash on Attribute calls or chained calls
      - still correctly add the class to guarded_classes
      - still correctly NOT add it when the kwarg is absent
    """

    def _scan_source(self, src: str) -> set[str]:
        tree = ast.parse(src)
        rules = load_rules()
        return _find_declarative_guarded_classes(tree, rules.reachability)

    def test_plain_name_constructor_params_does_not_crash(self):
        """The exact case that crashed v0.2.2."""
        src = """
import subprocess

class ShellTool:
    def _run(self, cmd):
        return subprocess.run(cmd, shell=True)

app = ShellTool(dependencies=[Depends(auth)])
"""
        guarded = self._scan_source(src)
        self.assertIn("ShellTool", guarded)

    def test_attribute_constructor_params_does_not_crash(self):
        src = """
import tools

app = tools.ShellTool(dependencies=[Depends(auth)])
"""
        guarded = self._scan_source(src)
        self.assertIn("ShellTool", guarded)

    def test_no_constructor_params_kwarg_not_guarded(self):
        """Negative control: without the kwarg, the class is not guarded."""
        src = """
class ShellTool:
    def _run(self, cmd):
        return subprocess.run(cmd, shell=True)

app = ShellTool()
"""
        guarded = self._scan_source(src)
        self.assertNotIn("ShellTool", guarded)

    def test_constructor_params_inheritance_propagates(self):
        """Pass 3 inheritance: a subclass of a constructor_params-guarded
        class must also be guarded."""
        src = """
class Guarded:
    pass

class Child(Guarded):
    pass

app = Guarded(dependencies=[Depends(auth)])
"""
        guarded = self._scan_source(src)
        self.assertIn("Guarded", guarded)
        self.assertIn("Child", guarded)


class PerFileDefensiveWrapperTests(unittest.TestCase):
    """The per-file try/except wrapper in scan_path.

    This is the second half of the v0.2.2 lesson: even when a detector
    crashes, the rest of the repo must still be scanned, and the error
    must be surfaced in result.analysis_errors.
    """

    def _write_repo(self, files: dict[str, str]) -> Path:
        tmpdir = Path(tempfile.mkdtemp(prefix="actenon-test-"))
        for rel, content in files.items():
            p = tmpdir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return tmpdir

    def test_one_bad_file_does_not_zero_out_repo(self):
        """If a detector crashes on file A, file B must still be scanned.

        We simulate a detector bug by patching _find_declarative_guarded_classes
        to raise whenever it sees a file containing the marker class
        `class CrashMe`. The wrapper must:
          - catch the exception
          - record it in analysis_errors
          - continue to the next file
          - return findings from the other file
        """
        repo = self._write_repo({
            # 'crash.py' has a marker class. The patched detector raises
            # when it sees it — this simulates a future regression of the
            # same shape as v0.2.2.
            "crash.py": (
                "class CrashMe:\n"
                "    pass\n"
            ),
            # 'good.py' is a real sink that should still fire.
            "good.py": (
                "from langchain.tools import tool\n"
                "import subprocess\n"
                "@tool\n"
                "def run_cmd(cmd: str):\n"
                "    return subprocess.run(cmd, shell=True)\n"
            ),
        })

        original = _find_declarative_guarded_classes

        def patched(tree, cfg):
            # Walk the tree once to detect the marker; raise if found.
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == "CrashMe":
                    raise RuntimeError("simulated detector crash on CrashMe file")
            return original(tree, cfg)

        with mock.patch(
            "actenon_scan.engine._find_declarative_guarded_classes",
            side_effect=patched,
        ):
            result = scan_path(repo)

        # The crash file was recorded, not raised.
        self.assertEqual(len(result.analysis_errors), 1)
        rel, err = result.analysis_errors[0]
        self.assertEqual(rel, "crash.py")
        self.assertIn("simulated detector crash", err)
        # The good file was still scanned and produced findings.
        active = [f for f in result.findings if not f.suppressed]
        self.assertGreater(len(active), 0, "good.py should still produce findings")
        self.assertEqual(result.files_scanned, 2)


if __name__ == "__main__":
    unittest.main()
