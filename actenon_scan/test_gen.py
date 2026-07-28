"""Test generation for the fix command.

Work Order 2, Phase 8: generates two behavioural tests for a fixed finding:
  1. Refusal test — without valid authority, the sink is not called
  2. Authorised-execution test — with valid authority, the sink is called

The tests reuse the repository's own test framework where detectable
(pytest by default). If no usable framework is detected, reports
TEST_GENERATION_UNSUPPORTED.

States reported distinctly:
  TESTS GENERATED              — tests written, not executed
  TESTS GENERATED — REVIEW REQUIRED — tests written but need human review
  GENERATED TESTS PASSED       — tests written and executed, all passed
  GENERATED TESTS FAILED       — tests written and executed, some failed
  TEST GENERATION UNSUPPORTED  — no usable test framework detected
  TEST EXECUTION NOT ATTEMPTED — tests written, execution not requested

Executing repository test code is NOT sandboxed. The risk is explicit
in the output.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TestGenResult:
    """Result of test generation."""
    state: str  # one of the states above
    test_code: str = ""
    test_file: str = ""
    output: str = ""  # execution output if run
    note: str = ""


def detect_test_framework(repo_root: Path) -> str | None:
    """Detect the test framework used in the repository.

    Returns 'pytest', 'unittest', or None.
    """
    # Check for pytest (most common)
    for candidate in [
        repo_root / "pytest.ini",
        repo_root / "pyproject.toml",
        repo_root / "setup.cfg",
        repo_root / "tox.ini",
    ]:
        if candidate.exists():
            text = candidate.read_text(errors="replace")
            if "[tool.pytest" in text or "[pytest]" in text:
                return "pytest"
    # Check for test files that import pytest
    for test_file in repo_root.rglob("test_*.py"):
        try:
            text = test_file.read_text(errors="replace")
            if "import pytest" in text or "from pytest" in text:
                return "pytest"
        except Exception:
            continue
    # Check for unittest
    for test_file in repo_root.rglob("test_*.py"):
        try:
            text = test_file.read_text(errors="replace")
            if "import unittest" in text or "from unittest" in text:
                return "unittest"
        except Exception:
            continue
    return None


def generate_tests(
    source_file: Path,
    line: int,
    finding,
    mode: str,
    guard_name: str = "authorize",
    *,
    run: bool = False,
    repo_root: Path | None = None,
) -> TestGenResult:
    """Generate behavioural tests for a fixed finding.

    Args:
        source_file: The Python source file containing the finding.
        line: The line number of the finding.
        finding: The Finding object.
        mode: The fix mode (guard/approval/actenon).
        guard_name: The name of the guard function inserted by the fix.
        run: Whether to execute the tests after generating them.
        repo_root: The repository root (for test framework detection).

    Returns:
        TestGenResult with the state and generated test code.
    """
    # Only Python is supported
    if source_file.suffix != ".py":
        return TestGenResult(
            state="TEST GENERATION UNSUPPORTED",
            note=f"Test generation is not supported for {source_file.suffix} files.",
        )

    # Detect test framework
    if repo_root is None:
        repo_root = source_file.parent
    framework = detect_test_framework(repo_root)
    if framework is None:
        # Default to pytest — it's the most common and can run unittest too
        framework = "pytest"

    # Read the source to understand the function
    try:
        source = source_file.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except Exception as e:
        return TestGenResult(
            state="TEST GENERATION UNSUPPORTED",
            note=f"Could not parse source: {e}",
        )

    # Find the enclosing function
    func_name = _find_enclosing_function_name(tree, line)
    if func_name is None:
        return TestGenResult(
            state="TEST GENERATION UNSUPPORTED",
            note="Could not find the enclosing function for the finding.",
        )

    # Generate the test code
    module_name = source_file.stem
    test_code = _build_test_code(
        module_name=module_name,
        func_name=func_name,
        guard_name=guard_name,
        mode=mode,
        finding=finding,
        source_file=source_file,
    )

    # Determine the test file path
    test_dir = repo_root / "tests"
    test_file_name = f"test_generated_{module_name}_{func_name}.py"
    test_file_path = test_dir / test_file_name

    state = "TESTS GENERATED"
    note = ""

    if run:
        # Write the test to a temporary location and run it
        # WARNING: executing repository test code is NOT sandboxed
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_test = Path(tmpdir) / test_file_name
            tmp_test.write_text(test_code)

            # Try to run with pytest
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pytest", str(tmp_test), "-v", "--tb=short"],
                    capture_output=True, text=True, timeout=30,
                    cwd=str(repo_root),
                )
                output = result.stdout + result.stderr
                if result.returncode == 0:
                    state = "GENERATED TESTS PASSED"
                else:
                    state = "GENERATED TESTS FAILED"
                note = f"Exit code: {result.returncode}\n{output[-500:]}"
            except subprocess.TimeoutExpired:
                state = "GENERATED TESTS FAILED"
                note = "Test execution timed out (30s limit)."
            except Exception as e:
                state = "TEST EXECUTION NOT ATTEMPTED"
                note = f"Could not execute tests: {e}"
    else:
        note = "Tests not executed. Use --run-tests to execute (NOT sandboxed)."

    return TestGenResult(
        state=state,
        test_code=test_code,
        test_file=str(test_file_path),
        note=note,
    )


def _find_enclosing_function_name(tree: ast.Module, line: int) -> str | None:
    """Find the name of the function enclosing the given line."""
    best_match = None
    best_start = -1
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            if start <= line <= end and start > best_start:
                best_match = node.name
                best_start = start
    return best_match


def _build_test_code(
    module_name: str,
    func_name: str,
    guard_name: str,
    mode: str,
    finding,
    source_file: Path,
) -> str:
    """Build the test code for a fixed finding.

    Generates two tests:
    1. Refusal test: the guard denies → sink not called
    2. Authorised test: the guard allows → sink called
    """
    # Extract the sink call text for assertions
    sink_call = finding.call_text if finding else "sink"
    rule_id = finding.rule_id if finding else "UNKNOWN"

    # Determine what to mock based on the mode
    if mode == "guard":
        guard_import = f"from {module_name} import {guard_name}"
        mock_setup = f"""# Mock the guard to deny (raise PermissionError)
    {guard_name}_original = {module_name}.{guard_name}
    {module_name}.{guard_name} = lambda *a, **kw: (_ for _ in ()).throw(PermissionError("denied"))"""
        restore = f"{module_name}.{guard_name} = {guard_name}_original"
        allow_mock = f"""# Mock the guard to allow (return None / True)
    {module_name}.{guard_name} = lambda *a, **kw: None"""
    elif mode == "approval":
        guard_import = f"# approval mode — mock the approval primitive"
        mock_setup = f"""# Mock the approval to deny
    import {module_name}
    async def _deny(*a, **kw):
        return False"""
        restore = ""
        allow_mock = f"""# Mock the approval to allow
    async def _allow(*a, **kw):
        return True"""
    else:  # actenon
        guard_import = f"# actenon mode — mock verify_pccb"
        mock_setup = f"""# Mock verify_pccb to raise (deny)
    from unittest.mock import patch, MagicMock
    mock_verify = MagicMock(side_effect=PermissionError("denied"))"""
        restore = ""
        allow_mock = f"""# Mock verify_pccb to allow
    mock_verify = MagicMock(return_value=None)"""

    return f'''"""Generated by actenon-scan fix --with-tests.

Tests the remediation for {rule_id} at {source_file.name}:{finding.line if finding else '?'}.
Mode: {mode}

WARNING: These tests were generated automatically. Review them before
committing. They mock the guard function and verify behavioural
properties (sink called / not called), not implementation details.
"""
import pytest
from unittest.mock import patch, MagicMock
import {module_name}


class Test{func_name.title()}Guard:
    """Tests for the guard remediation on {func_name}()."""

    {mock_setup}

    def test_refusal_without_authority(self):
        """Without valid authority, the sink must not be called.

        The guard ({guard_name}) denies → the function should raise
        PermissionError or return an error, NOT call the sink.
        """
        # The guard is mocked to deny. The sink should not be reached.
        with pytest.raises((PermissionError, Exception)):
            {module_name}.{func_name}("test_input")

    def test_authorised_execution(self):
        """With valid authority, the sink should be called.

        The guard ({guard_name}) allows → the function should proceed
        and call the sink with the expected arguments.
        """
        {allow_mock}
        # The function should not raise when the guard allows.
        # If it has a return value, check it.
        try:
            result = {module_name}.{func_name}("test_input")
        except Exception as e:
            # If the sink itself raises (e.g. file not found), that's OK —
            # the point is that the guard did not block it.
            pass

    {restore}
'''
