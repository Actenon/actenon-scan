"""Regression tests for the v1.0 three-persona audit fixes (round 3).

Each test verifies a specific P0/M fix from the three-persona first-touch
audit. The tests are intentionally small and focused so the failure mode
is obvious when a regression is introduced.
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
# P1-1: cache must NOT bypass baseline suppression.
# ---------------------------------------------------------------------------


def test_cache_does_not_bypass_baseline_suppression(tmp_path: Path) -> None:
    """P1-1 regression: previously, when the content-hash cache hit,
    findings were appended WITHOUT applying baseline or inline-suppression.
    A user who ran `scan .`, then `baseline .`, then `scan . --baseline
    baseline.json` would see all findings still."""
    # Create a fixture with one finding.
    (tmp_path / "tool.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
        """))

    from actenon_scan.cache import FileCache, get_default_cache_dir
    from actenon_scan.engine import scan_path
    from actenon_scan.baseline import load_baseline, write_baseline

    # Step 1: scan WITHOUT baseline to populate the cache.
    cache = FileCache(get_default_cache_dir(tmp_path))
    r1 = scan_path(tmp_path, cache=cache)
    n1 = len([f for f in r1.findings if not f.suppressed])
    assert n1 == 1, f"step 1 should find 1 finding, got {n1}"

    # Step 2: generate a baseline from those findings.
    baseline_path = tmp_path / "baseline.json"
    write_baseline(
        [{"file": f.file, "line": f.line, "rule_id": f.rule_id,
          "snippet_hash": f.snippet_hash, "category": f.category,
          "severity": f.severity}
         for f in r1.findings],
        baseline_path,
    )
    baseline = load_baseline(baseline_path)

    # Step 3: scan WITH baseline — the cache is warm from step 1, so this
    # exercises the cache-hit path. The finding MUST be suppressed.
    r3 = scan_path(tmp_path, baseline_findings=baseline, cache=cache)
    unsuppressed = [f for f in r3.findings if not f.suppressed]
    assert unsuppressed == [], (
        f"P1-1 regression: cache-hit path did not apply baseline. "
        f"Expected 0 unsuppressed findings, got {len(unsuppressed)}: {unsuppressed}"
    )


def test_cache_does_not_bypass_inline_suppression(tmp_path: Path) -> None:
    """P1-1 regression variant: same issue applies to inline suppressions."""
    # Create a fixture with an inline suppression comment.
    (tmp_path / "tool.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            # actenon-scan: ignore[EXEC-SHELL]
            return subprocess.run(cmd, shell=True).stdout.decode()
        """))

    from actenon_scan.cache import FileCache, get_default_cache_dir
    from actenon_scan.engine import scan_path
    from actenon_scan.suppress import collect_suppressions_from_file

    # Step 1: scan WITHOUT suppressions to populate the cache.
    cache = FileCache(get_default_cache_dir(tmp_path))
    r1 = scan_path(tmp_path, cache=cache)
    n1 = len([f for f in r1.findings if not f.suppressed])
    assert n1 == 1, f"step 1 should find 1 finding (no suppressions), got {n1}"

    # Step 2: collect suppressions.
    suppressions = collect_suppressions_from_file(tmp_path / "tool.py", tmp_path)

    # Step 3: scan WITH suppressions — cache is warm. The finding MUST be suppressed.
    r3 = scan_path(tmp_path, suppressions=suppressions, cache=cache)
    unsuppressed = [f for f in r3.findings if not f.suppressed]
    assert unsuppressed == [], (
        f"P1-1 regression: cache-hit path did not apply inline suppression. "
        f"Got {len(unsuppressed)} unsuppressed."
    )


# ---------------------------------------------------------------------------
# P1-2: `init` must merge with existing config, not overwrite.
# ---------------------------------------------------------------------------


def test_init_merges_with_existing_config(tmp_path: Path) -> None:
    """P1-2 regression: `init` previously overwrote .actenon-scan.json
    silently, destroying exclude/sinks/reachability keys."""
    # Create an existing config with an exclude key.
    existing = {
        "version": "1",
        "exclude": ["tests/**", "vendor/**"],
        "guard_patterns": ["my_existing_guard"],
    }
    (tmp_path / ".actenon-scan.json").write_text(json.dumps(existing, indent=2))

    # Run `init` in this directory.
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        from actenon_scan.cli import main
        rc = main(["init"])
    finally:
        os.chdir(cwd)
    assert rc == 0

    # The new config MUST preserve the exclude key.
    new_config = json.loads((tmp_path / ".actenon-scan.json").read_text())
    assert "exclude" in new_config, (
        f"P1-2 regression: init destroyed the exclude key. Config: {new_config}"
    )
    assert new_config["exclude"] == ["tests/**", "vendor/**"], (
        f"exclude key changed: {new_config['exclude']}"
    )
    # The existing guard_pattern must be preserved.
    assert "my_existing_guard" in new_config.get("guard_patterns", []), (
        f"existing guard_pattern lost: {new_config.get('guard_patterns')}"
    )


def test_init_force_overwrites_existing_config(tmp_path: Path) -> None:
    """The --force flag restores the old overwrite behaviour."""
    existing = {
        "version": "1",
        "exclude": ["tests/**"],
        "guard_patterns": ["my_existing_guard"],
    }
    (tmp_path / ".actenon-scan.json").write_text(json.dumps(existing, indent=2))

    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        from actenon_scan.cli import main
        rc = main(["init", "--force"])
    finally:
        os.chdir(cwd)
    assert rc == 0

    new_config = json.loads((tmp_path / ".actenon-scan.json").read_text())
    # --force should NOT preserve the exclude key.
    assert "exclude" not in new_config, (
        f"--force should have overwritten, but exclude survived: {new_config}"
    )


# ---------------------------------------------------------------------------
# P1-3: fix.py must insert guard at sink's indent in nested blocks.
# ---------------------------------------------------------------------------


def test_fix_nested_block_sink_gets_sink_indent(tmp_path: Path) -> None:
    """P1-3 regression: `fix` previously inserted the guard at the
    function-body indent even when the sink was inside a `with`/`for`/
    `try`/`if` block. The guard comments landed in the middle of the
    block, and when uncommented the guard would run BEFORE the block
    was entered."""
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
    # The guard must be at the sink's own indent (8 spaces, inside the with block).
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
            f"inside the with block). Line: {l!r}"
        )


def test_fix_function_body_sink_gets_function_indent(tmp_path: Path) -> None:
    """When the sink is at function-body level (no nested block), the
    guard must still be at function-body indent (the old behavior)."""
    src = tmp_path / "tool.py"
    src.write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
        """))
    lines = src.read_text().splitlines()
    finding_line = next(i + 1 for i, l in enumerate(lines) if "subprocess.run" in l)

    from actenon_scan.fix import generate_fix
    fix = generate_fix(src, finding_line, mode="guard")
    assert fix is not None
    diff_lines = fix.diff.splitlines()
    added_guard_lines = [
        l for l in diff_lines
        if l.startswith("+") and "TODO" in l
    ]
    assert added_guard_lines, "no guard comment in diff"
    for l in added_guard_lines:
        added_text = l[1:]
        indent = len(added_text) - len(added_text.lstrip())
        assert indent == 4, (
            f"function-body sink guard should be at indent 4, got {indent}. Line: {l!r}"
        )


# ---------------------------------------------------------------------------
# P1-4 (REVERSED): --fail-on CLI default is "medium" (NOT "none").
# The round-3 audit changed it to "none" to match action.yml. That was
# wrong — the CLI has no other machine-readable signal, so a scanner that
# finds 8 unguarded consequential actions and returns 0 passes CI silently.
# Reverted to "medium" (the 1.0.0 default). action.yml stays at "none"
# (it has a sticky PR comment + SARIF upload, so findings stay visible
# even when the check is green). The two intentionally differ.
# ---------------------------------------------------------------------------


def test_fail_on_default_is_medium() -> None:
    """The CLI --fail-on default must be "medium" — not "none".

    A scanner that finds findings and exits 0 passes CI silently. The
    CLI's exit code is its only machine-readable signal, so it must fail
    on findings by default. The Action defaults to "none" because it has
    a sticky PR comment + SARIF upload; the CLI has no such surface.
    """
    import inspect
    from actenon_scan.cli import main
    src = inspect.getsource(main)
    # The default for --fail-on must be "medium".
    assert 'default="medium"' in src, (
        "CLI --fail-on default is not 'medium' — check cli.py scan_parser. "
        "A non-failing default means findings pass CI silently."
    )


def test_scan_with_findings_exits_nonzero_by_default(tmp_path: Path) -> None:
    """End-to-end: a scan with medium-or-above findings must exit 1 by default.

    This pins the default — a scanner that finds 8 unguarded consequential
    actions and returns 0 passes CI silently, which is the false-assurance
    failure this tool exists to close.
    """
    src = tmp_path / "tool.py"
    src.write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
        """))
    result = subprocess.run(
        [sys.executable, "-m", "actenon_scan", "scan", str(src), "--format", "json"],
        capture_output=True, text=True,
    )
    assert result.returncode == 1, (
        f"scan with findings exited {result.returncode} by default. "
        f"Expected 1 (--fail-on default should be medium, so findings fail the build). "
        f"stderr: {result.stderr[:300]}"
    )


def test_scan_with_findings_exits_zero_with_fail_on_none(tmp_path: Path) -> None:
    """Explicit --fail-on none still exits 0 (for triaged repos with baselines)."""
    src = tmp_path / "tool.py"
    src.write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
        """))
    result = subprocess.run(
        [sys.executable, "-m", "actenon_scan", "scan", str(src), "--format", "json", "--fail-on", "none"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"scan with --fail-on none exited {result.returncode}. Expected 0."
    )


# ---------------------------------------------------------------------------
# P1-5: --changed-only must NOT silently degrade to a full scan.
# ---------------------------------------------------------------------------


def test_changed_only_empty_diff_exits_zero(tmp_path: Path) -> None:
    """P1-5 regression: --changed-only on an empty git diff silently
    fell through to a full scan. Now it warns and exits 0."""
    import subprocess as sp
    sp.run(["git", "init"], cwd=tmp_path, capture_output=True)
    sp.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True)
    sp.run(["git", "config", "user.name", "test"], cwd=tmp_path, capture_output=True)
    (tmp_path / "tool.py").write_text("def f(): pass\n")
    sp.run(["git", "add", "."], cwd=tmp_path, capture_output=True)
    sp.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True)
    # No changes since HEAD — empty diff.

    result = subprocess.run(
        [sys.executable, "-m", "actenon_scan", "scan", str(tmp_path),
         "--changed-only", "HEAD", "--format", "json"],
        capture_output=True, text=True, cwd=tmp_path,
    )
    assert result.returncode == 0, (
        f"--changed-only on empty diff should exit 0, got {result.returncode}. "
        f"stderr: {result.stderr[:300]}"
    )
    # The output should say no scannable files changed.
    assert "no scannable files changed" in result.stderr.lower() or "0 file" in result.stdout, (
        f"--changed-only on empty diff did not warn. stderr: {result.stderr[:300]}"
    )


# ---------------------------------------------------------------------------
# P3-6: public Python API in actenon_scan.api.
# ---------------------------------------------------------------------------


def test_public_api_importable_from_top_level() -> None:
    """P3-6 regression: `from actenon_scan import scan_path` previously
    failed with ImportError because __init__.py exported only __version__."""
    from actenon_scan import (
        scan_path, scan_path_parallel, Finding, ScanResult,
        Ruleset, SinkRule, load_rules, load_default_rules, __version__,
    )
    # All symbols must be non-None.
    assert scan_path is not None
    assert scan_path_parallel is not None
    assert Finding is not None
    assert ScanResult is not None
    assert Ruleset is not None
    assert SinkRule is not None
    assert load_rules is not None
    assert load_default_rules is not None
    assert __version__ is not None


def test_public_api_module_has_all() -> None:
    """actenon_scan.api must declare __all__ for stable public surface."""
    from actenon_scan import api
    assert hasattr(api, "__all__"), "actenon_scan.api must declare __all__"
    # Must include the key symbols.
    for sym in ("scan_path", "Finding", "ScanResult", "Ruleset", "SinkRule",
                "load_rules", "load_default_rules"):
        assert sym in api.__all__, f"{sym} not in actenon_scan.api.__all__"


def test_py_typed_marker_present() -> None:
    """The py.typed marker must exist for PEP 561 typed-package support."""
    import actenon_scan
    pkg_dir = Path(actenon_scan.__file__).parent
    assert (pkg_dir / "py.typed").exists(), "py.typed marker missing"


# ---------------------------------------------------------------------------
# Cross-8: cache relocation via env var and flag.
# ---------------------------------------------------------------------------


def test_cache_dir_env_var_override(tmp_path: Path) -> None:
    """Cross-8: ACTENON_SCAN_CACHE_DIR env var overrides the cache location."""
    from actenon_scan.cache import get_default_cache_dir
    custom = tmp_path / "custom-cache-location"
    old = os.environ.pop("ACTENON_SCAN_CACHE_DIR", None)
    try:
        os.environ["ACTENON_SCAN_CACHE_DIR"] = str(custom)
        d = get_default_cache_dir(tmp_path)
        assert d == custom, f"env var override failed: {d} != {custom}"
    finally:
        if old is not None:
            os.environ["ACTENON_SCAN_CACHE_DIR"] = old
        else:
            os.environ.pop("ACTENON_SCAN_CACHE_DIR", None)


def test_cache_dir_xdg_default(tmp_path: Path) -> None:
    """Cross-8: without env var, cache goes under XDG_CACHE_HOME (not the workspace)."""
    from actenon_scan.cache import get_default_cache_dir
    old_env = os.environ.pop("ACTENON_SCAN_CACHE_DIR", None)
    old_xdg = os.environ.pop("XDG_CACHE_HOME", None)
    try:
        os.environ["XDG_CACHE_HOME"] = str(tmp_path / "xdg-cache")
        d = get_default_cache_dir(tmp_path / "myrepo")
        # The cache dir must NOT be inside the scanned directory.
        assert ".actenon-scan-cache" not in str(d), (
            f"cache dir should be under XDG, not workspace: {d}"
        )
        assert "actenon-scan" in str(d), (
            f"cache dir should be under actenon-scan/: {d}"
        )
    finally:
        if old_env is not None:
            os.environ["ACTENON_SCAN_CACHE_DIR"] = old_env
        if old_xdg is not None:
            os.environ["XDG_CACHE_HOME"] = old_xdg


# ---------------------------------------------------------------------------
# Cross-10: community files exist.
# ---------------------------------------------------------------------------


def test_community_files_exist() -> None:
    """Cross-10: GitHub community files must exist for project maturity signals."""
    repo_root = Path(__file__).resolve().parent.parent
    assert (repo_root / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml").exists()
    assert (repo_root / ".github" / "ISSUE_TEMPLATE" / "feature_request.yml").exists()
    assert (repo_root / ".github" / "ISSUE_TEMPLATE" / "security_report.md").exists()
    assert (repo_root / ".github" / "PULL_REQUEST_TEMPLATE.md").exists()
    assert (repo_root / ".github" / "CODEOWNERS").exists()
    assert (repo_root / ".github" / "dependabot.yml").exists()


# ---------------------------------------------------------------------------
# Cross-13: CHANGELOG has [Unreleased] section + deprecation policy.
# ---------------------------------------------------------------------------


def test_changelog_has_unreleased_section() -> None:
    """Cross-13: CHANGELOG must have an [Unreleased] section for the round-2/3 fixes."""
    repo_root = Path(__file__).resolve().parent.parent
    changelog = (repo_root / "CHANGELOG.md").read_text()
    assert "## [Unreleased]" in changelog, (
        "CHANGELOG.md missing [Unreleased] section"
    )


def test_changelog_has_deprecation_policy() -> None:
    """Cross-13: CHANGELOG must document the deprecation policy."""
    repo_root = Path(__file__).resolve().parent.parent
    changelog = (repo_root / "CHANGELOG.md").read_text()
    assert "Deprecation policy" in changelog, (
        "CHANGELOG.md missing deprecation policy section"
    )
    assert "actenon_scan.api" in changelog, (
        "deprecation policy must reference actenon_scan.api as the public surface"
    )
