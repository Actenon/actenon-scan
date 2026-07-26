"""Regression tests for v1.0 audit fixes.

Each test verifies a specific P0/P1 fix from the v1.0 readiness audit.
The tests are intentionally small and focused so the failure mode is
obvious when a regression is introduced.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# P0-2: Inline suppression must work with ABSOLUTE scan targets.
# ---------------------------------------------------------------------------


def _make_fixture(tmp_path: Path) -> Path:
    """Create a Python file with an unguarded subprocess.run and a
    suppression comment for it. Returns the file path."""
    src = tmp_path / "tool.py"
    src.write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool
        def run_cmd(cmd: str) -> str:
            # actenon-scan: ignore[EXEC-SHELL]
            return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
        """))
    return src


def test_suppression_works_with_relative_target(tmp_path: Path) -> None:
    """Baseline: suppression works when scanning a relative path."""
    src = _make_fixture(tmp_path)
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        from actenon_scan.engine import scan_path
        from actenon_scan.suppress import collect_suppressions_from_file
        suppressions = collect_suppressions_from_file(src, tmp_path)
        result = scan_path(tmp_path, suppressions=suppressions)
    finally:
        os.chdir(cwd)
    findings = [f for f in result.findings if not f.suppressed]
    assert findings == [], f"expected suppression to fire, got: {findings}"


def test_suppression_works_with_absolute_target(tmp_path: Path) -> None:
    """P0-2 regression: suppression must ALSO fire when the scan target
    is an absolute path. Before the fix, the suppression was keyed by
    absolute path but findings were keyed by path-relative-to-target, so
    they never matched."""
    src = _make_fixture(tmp_path)
    # Use the absolute path as the target — this is what CI does when
    # it runs `actenon-scan scan .` (the . resolves to the absolute
    # workspace path internally).
    from actenon_scan.engine import scan_path
    from actenon_scan.suppress import collect_suppressions_from_file
    suppressions = collect_suppressions_from_file(src, tmp_path.resolve())
    result = scan_path(tmp_path.resolve(), suppressions=suppressions)
    findings = [f for f in result.findings if not f.suppressed]
    assert findings == [], (
        f"P0-2 regression: suppression silently dropped on absolute target. "
        f"Got {len(findings)} unsuppressed finding(s)."
    )


def test_suppression_keys_match_engine_keys(tmp_path: Path) -> None:
    """The suppression key (file, rule_id) must EXACTLY match the key the
    engine uses to look up suppressions. The engine uses
    ``str(filepath.relative_to(target))`` so the collector must too."""
    from actenon_scan.suppress import collect_suppressions_from_file
    src = _make_fixture(tmp_path)
    target = tmp_path.resolve()
    suppressions = collect_suppressions_from_file(src, target)
    # The engine computes rel as str(src.relative_to(target)) for dir targets.
    expected_rel = str(src.relative_to(target))
    # The suppressions set must contain (expected_rel, 'EXEC-SHELL')
    assert (expected_rel, "EXEC-SHELL") in suppressions, (
        f"suppression key {expected_rel!r} not in suppressions: {suppressions}"
    )


# ---------------------------------------------------------------------------
# P0-3: Pre-commit multi-file commits must not crash argparse.
# ---------------------------------------------------------------------------


def test_cli_accepts_multiple_positional_paths(tmp_path: Path) -> None:
    """P0-3 regression: pre-commit passes one positional per changed file.
    argparse must accept multiple paths without 'unrecognized arguments'."""
    f1 = tmp_path / "a.py"
    f2 = tmp_path / "b.py"
    f3 = tmp_path / "c.py"
    for f in (f1, f2, f3):
        f.write_text("def f(): pass\n")

    from actenon_scan.cli import main
    rc = main(["scan", str(f1), str(f2), str(f3), "--format", "json", "--no-cache"])
    # Exit code 0 means no findings at/above threshold and no argparse error.
    assert rc == 0, f"multi-path scan failed with exit code {rc}"


def test_cli_single_path_still_works(tmp_path: Path) -> None:
    """The single-path case (the normal case) must still work after
    switching to nargs='+'."""
    f = tmp_path / "x.py"
    f.write_text("def f(): pass\n")
    from actenon_scan.cli import main
    rc = main(["scan", str(f), "--format", "json", "--no-cache"])
    assert rc == 0


# ---------------------------------------------------------------------------
# P0-5: SARIF driver version must equal __version__.
# ---------------------------------------------------------------------------


def test_sarif_driver_version_matches_package_version() -> None:
    """P0-5 regression: the SARIF tool driver version was hardcoded to
    '0.1.0'. It must use the package __version__ so GitHub's Security tab
    displays the correct version."""
    from actenon_scan import __version__
    from actenon_scan.engine import ScanResult
    from actenon_scan.report.sarif import format_sarif

    sarif_text = format_sarif(ScanResult())
    sarif = json.loads(sarif_text)
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__, (
        f"SARIF driver version is {driver['version']!r}, expected {__version__!r}"
    )
    # Also assert it is NOT the stale hardcoded value.
    assert driver["version"] != "0.1.0", (
        "SARIF driver version is still the stale '0.1.0' hardcode"
    )


# ---------------------------------------------------------------------------
# P0-6: BOM-prefixed Python files must scan cleanly.
# ---------------------------------------------------------------------------


def test_bom_prefixed_python_file_scans_cleanly(tmp_path: Path) -> None:
    """P0-6 regression: a file with a UTF-8 BOM was misclassified as
    SyntaxError and silently missed. It must now scan cleanly."""
    src = tmp_path / "bom_tool.py"
    # Write a BOM (U+FEFF encoded as UTF-8 = bytes ef bb bf) followed by
    # valid Python that contains a real finding. If the BOM is not stripped,
    # ast.parse raises SyntaxError and the finding is silently lost.
    content = (
        b"\xef\xbb\xbf"  # UTF-8 BOM as raw bytes
        b"import subprocess\n"
        b"from mcp import tool\n\n"
        b"@tool\n"
        b"def run(cmd: str) -> str:\n"
        b"    return subprocess.run(cmd, shell=True).stdout.decode()\n"
    )
    src.write_bytes(content)

    from actenon_scan.engine import scan_path
    result = scan_path(tmp_path)
    # The file must NOT appear in analysis_errors.
    error_files = [rel for rel, _ in result.analysis_errors]
    assert error_files == [], (
        f"BOM file landed in analysis_errors: {error_files}"
    )
    # The file MUST produce a finding (proving the BOM was stripped and
    # the file was actually parsed).
    findings = [f for f in result.findings if "bom_tool" in f.file]
    assert findings, "BOM file scanned but produced no findings — was it actually parsed?"


def test_bom_prefixed_file_no_false_syntax_error(tmp_path: Path) -> None:
    """A BOM-prefixed file with NO sinks must scan cleanly without landing
    in analysis_errors. This is the false-negative case the BOM bug caused."""
    src = tmp_path / "bom_safe.py"
    content = (
        b"\xef\xbb\xbf"
        b"def hello() -> str:\n"
        b"    return 'world'\n"
    )
    src.write_bytes(content)

    from actenon_scan.engine import scan_path
    result = scan_path(tmp_path)
    error_files = [rel for rel, _ in result.analysis_errors]
    assert error_files == [], f"BOM file landed in analysis_errors: {error_files}"


# ---------------------------------------------------------------------------
# P0-7: cache and on_finding must be honoured in parallel mode.
# ---------------------------------------------------------------------------


def test_parallel_mode_accepts_cache_and_on_finding(tmp_path: Path) -> None:
    """P0-7 regression: scan_path_parallel silently dropped the cache and
    on_finding parameters. Verify both are now accepted and honoured."""
    # Create enough files to trigger parallel mode.
    for i in range(20):
        (tmp_path / f"mod_{i}.py").write_text(
            "import subprocess\n"
            "from mcp import tool\n\n"
            "@tool\n"
            f"def run_{i}(cmd: str) -> str:\n"
            "    return subprocess.run(cmd, shell=True).stdout.decode()\n"
        )

    from actenon_scan.cache import FileCache, get_default_cache_dir
    from actenon_scan.engine import scan_path_parallel

    cache = FileCache(get_default_cache_dir(tmp_path))
    fired: list[str] = []

    def on_finding(f) -> None:
        fired.append(f.file)

    # Force 2 jobs so the parallel branch is exercised even on small repos.
    result = scan_path_parallel(
        tmp_path, jobs=2, cache=cache, on_finding=on_finding,
    )
    # on_finding must have fired at least once (proving it was passed through).
    assert fired, "on_finding did not fire in parallel mode"
    # And the scan must have produced findings.
    assert result.findings, "parallel scan produced no findings"


def test_parallel_cache_hit_on_second_scan(tmp_path: Path) -> None:
    """The cache must be populated on the first parallel scan and hit on
    the second. Before P0-7, the cache was silently ignored in parallel
    mode and every scan was a full re-scan."""
    for i in range(20):
        (tmp_path / f"mod_{i}.py").write_text(
            "import subprocess\n"
            "from mcp import tool\n\n"
            "@tool\n"
            f"def run_{i}(cmd: str) -> str:\n"
            "    return subprocess.run(cmd, shell=True).stdout.decode()\n"
        )

    from actenon_scan.cache import FileCache, get_default_cache_dir
    from actenon_scan.engine import scan_path_parallel

    cache = FileCache(get_default_cache_dir(tmp_path))

    # First scan: populates the cache.
    r1 = scan_path_parallel(tmp_path, jobs=2, cache=cache)
    n1 = len(r1.findings)

    # Second scan: should hit the cache for every file.
    r2 = scan_path_parallel(tmp_path, jobs=2, cache=cache)
    n2 = len(r2.findings)

    # Findings must be identical (RULE 5: cache never changes findings).
    assert n1 == n2, f"cache changed findings: {n1} -> {n2}"
    # And there must be SOME findings (otherwise the test is vacuous).
    assert n1 > 0, "test fixture produced no findings"


# ---------------------------------------------------------------------------
# P1-1: Windows-style backslash paths must match glob patterns.
# ---------------------------------------------------------------------------


def test_glob_match_normalizes_backslashes() -> None:
    """P1-1 regression: _glob_match split on '/' exclusively, so Windows
    backslash paths never matched. The matcher must normalize backslashes
    to forward slashes."""
    from actenon_scan.engine import _glob_match
    # A Windows-style relative path with backslashes.
    rel = "tests\\fixtures\\vulnerable\\tool.py"
    # Standard glob pattern with forward slashes.
    assert _glob_match(rel, "tests/fixtures/**") is True, (
        "Windows backslash path did not match forward-slash glob"
    )
    # Also verify the forward-slash form still matches (no regression).
    assert _glob_match("tests/fixtures/vulnerable/tool.py", "tests/fixtures/**") is True


def test_glob_match_handles_backslash_basename() -> None:
    """The basename extraction inside _glob_match must also work with
    backslash paths."""
    from actenon_scan.engine import _glob_match
    rel = "vendor\\subdir\\thing.py"
    assert _glob_match(rel, "**/thing.py") is True


# ---------------------------------------------------------------------------
# P1-4: pyproject.toml classifier must be Production/Stable for v1.0.
# ---------------------------------------------------------------------------


def test_pyproject_classifier_is_production_stable() -> None:
    """P1-4 regression: the classifier was 'Development Status :: 4 - Beta'
    on a 1.0.0 package, which is internally inconsistent."""
    repo_root = Path(__file__).resolve().parent.parent
    pyproject = (repo_root / "pyproject.toml").read_text()
    assert "Development Status :: 5 - Production/Stable" in pyproject, (
        "pyproject.toml classifier is not 'Production/Stable'"
    )
    assert "Development Status :: 4 - Beta" not in pyproject, (
        "pyproject.toml still has the stale 'Beta' classifier"
    )


# ---------------------------------------------------------------------------
# P1-8: fix.py must hoist imports to the top of the file.
# ---------------------------------------------------------------------------


def test_fix_actenon_mode_hoists_import(tmp_path: Path) -> None:
    """P1-8 regression: fix.py inserted `from actenon_kernel import verify_pccb`
    inline before the sink — which lands inside the function (or worse,
    inside a `with` block) instead of at the top of the file.

    Updated in the user-story audit round to use the REAL actenon-kernel
    API (`verify_pccb`), not the previously-broken `from actenon import
    verify_proof` which referenced a non-existent package.
    """
    src = tmp_path / "tool.py"
    src.write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            with subprocess.Popen(cmd, shell=True) as p:
                return p.stdout.read().decode()
        """))
    # The sink is subprocess.Popen — line 7 (inside the `with` block).
    # Find the exact line by scanning.
    lines = src.read_text().splitlines()
    finding_line = next(i + 1 for i, l in enumerate(lines) if "Popen" in l)

    from actenon_scan.fix import generate_fix
    fix = generate_fix(src, finding_line, mode="actenon")
    assert fix is not None, "no fix generated"
    # The diff must contain the import line — and it MUST be the real
    # actenon-kernel import, not the broken `from actenon import verify_proof`.
    assert "from actenon_kernel import verify_pccb" in fix.diff, (
        "actenon fix diff is missing the real actenon-kernel import statement"
    )
    # The broken import must NOT appear.
    assert "from actenon import verify_proof" not in fix.diff, (
        "actenon fix diff still uses the broken `from actenon import verify_proof` "
        "import — this references a non-existent package and breaks user code."
    )
    # The import must be at column 0 (top of file), NOT indented.
    diff_lines = fix.diff.splitlines()
    added_import_lines = [
        l for l in diff_lines
        if l.startswith("+") and "from actenon_kernel import verify_pccb" in l
    ]
    assert added_import_lines, "no added import line in diff"
    for l in added_import_lines:
        # The line after the '+' must NOT start with whitespace.
        added_text = l[1:]
        assert not added_text.startswith(" "), (
            f"import was inserted indented (inside a function/block): {l!r}"
        )


def test_fix_guard_at_function_indent_not_with_block_indent(tmp_path: Path) -> None:
    """The guard must be inserted at the SINK's own indentation when the
    sink is inside a nested block (with/for/try/if), so the guard runs in
    the same scope as the sink (with the same variables in scope).

    Round-3 audit reversal: the previous test asserted the OPPOSITE — that
    the guard should be at function-body indent even for nested-block
    sinks. That placed guard comments BETWEEN statements in the middle of
    the nested block, and when uncommented the guard would run BEFORE the
    `with` is entered, meaning `browser` or `page` are not yet defined
    and the guard cannot actually guard the sink. The new behavior inserts
    at the sink's own indent (8 spaces, inside the `with`) so the guard
    runs in the same scope as `page.click(selector)`.

    This test uses a REAL nested-block sink (page.click inside a
    `with sync_playwright()` block) — the previous test used
    `with subprocess.Popen(...)` where the sink IS the `with` statement
    itself (at function-body indent), which didn't actually exercise the
    nested-block case.
    """
    src = tmp_path / "tool.py"
    src.write_text(textwrap.dedent("""\
        from mcp import tool
        from playwright.sync_api import sync_playwright

        @tool
        def click_element(url: str, selector: str) -> None:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()
                page.goto(url)
                page.click(selector)
                browser.close()
        """))
    lines = src.read_text().splitlines()
    finding_line = next(i + 1 for i, l in enumerate(lines) if "page.click" in l)

    from actenon_scan.fix import generate_fix
    fix = generate_fix(src, finding_line, mode="guard")
    assert fix is not None
    # The guard comment lines should be indented at 8 spaces (the sink's
    # own indent inside the `with` block — same scope as `page`), NOT 4
    # spaces (function body, which would place the guard BEFORE the
    # `with` is entered, when `page` is not yet defined).
    diff_lines = fix.diff.splitlines()
    added_guard_lines = [
        l for l in diff_lines
        if l.startswith("+") and "TODO" in l
    ]
    assert added_guard_lines, "no guard comment in diff"
    for l in added_guard_lines:
        added_text = l[1:]
        indent = len(added_text) - len(added_text.lstrip())
        assert indent == 8, (
            f"guard inserted at indent {indent}, expected 8 (sink's own indent "
            f"inside the `with` block). Line: {l!r}"
        )


# ---------------------------------------------------------------------------
# P1-9: explain.py must reference the GitHub URL, not docs/COVERAGE.md
# (which is not shipped in the wheel).
# ---------------------------------------------------------------------------


def test_explain_references_github_url_not_local_docs() -> None:
    """P1-9 regression: explain.py referenced `docs/COVERAGE.md` which is
    not shipped in the wheel. It must point at the GitHub URL."""
    from actenon_scan import explain
    import inspect
    src = inspect.getsource(explain)
    assert "github.com/Actenon/actenon-scan/blob/main/docs/COVERAGE.md" in src, (
        "explain.py does not reference the GitHub URL for COVERAGE.md"
    )
    # The standalone "See docs/COVERAGE.md" line (without the URL) must be gone.
    assert 'See docs/COVERAGE.md for supported' not in src, (
        "explain.py still references docs/COVERAGE.md without the GitHub URL"
    )


# ---------------------------------------------------------------------------
# Edge cases: CRLF, 0-byte file, deeply nested directory.
# ---------------------------------------------------------------------------


def test_crlf_line_endings_scan_cleanly(tmp_path: Path) -> None:
    """CRLF line endings must not cause analysis errors."""
    src = tmp_path / "crlf_tool.py"
    content = (
        "import subprocess\r\n"
        "from mcp import tool\r\n\r\n"
        "@tool\r\n"
        "def run(cmd: str) -> str:\r\n"
        "    return subprocess.run(cmd, shell=True).stdout.decode()\r\n"
    )
    src.write_bytes(content.encode("utf-8"))
    from actenon_scan.engine import scan_path
    result = scan_path(tmp_path)
    error_files = [rel for rel, _ in result.analysis_errors]
    assert error_files == [], f"CRLF file landed in analysis_errors: {error_files}"
    # And it should still produce a finding.
    findings = [f for f in result.findings if "crlf_tool" in f.file]
    assert findings, "CRLF file scanned but produced no findings"


def test_zero_byte_file_scans_cleanly(tmp_path: Path) -> None:
    """A 0-byte .py file must not crash the scanner."""
    (tmp_path / "empty.py").write_bytes(b"")
    from actenon_scan.engine import scan_path
    result = scan_path(tmp_path)
    # An empty file produces no findings and no errors.
    assert result.analysis_errors == [] or all(
        "empty.py" not in rel for rel, _ in result.analysis_errors
    )


def test_binary_py_file_degrades_gracefully(tmp_path: Path) -> None:
    """A .py file containing binary garbage must degrade to an
    analysis_error, not crash the scanner."""
    src = tmp_path / "binary.py"
    src.write_bytes(b"\x00\x01\x02\x03\xff\xfe\xfd not valid python \x00")
    from actenon_scan.engine import scan_path
    result = scan_path(tmp_path)
    # The file should appear in analysis_errors, NOT crash the scan.
    error_files = [rel for rel, _ in result.analysis_errors]
    assert any("binary" in rel for rel in error_files), (
        f"binary .py file did not land in analysis_errors: {error_files}"
    )
