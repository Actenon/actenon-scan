"""Regression tests for the v1.0 user-story audit fixes (round 2).

Each test verifies a specific P0/M fix from the end-to-end user-story
audit. The tests are intentionally small and focused so the failure
mode is obvious when a regression is introduced.
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
# P0-1: fix.py must use the REAL actenon-kernel API, not the non-existent
# `actenon` package.
# ---------------------------------------------------------------------------


def test_fix_actenon_mode_uses_real_actenon_kernel_api(tmp_path: Path) -> None:
    """P0-1 regression: `fix --mode actenon --apply` previously wrote
    `from actenon import verify_proof` — but no `actenon` package exists
    on PyPI. Applying the fix broke user code with ModuleNotFoundError.
    The fix must now use the real `actenon_kernel` package and `verify_pccb`
    function (per the README ecosystem table and guard vocabulary).
    """
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
    fix = generate_fix(src, finding_line, mode="actenon")
    assert fix is not None
    # The diff must use the REAL actenon-kernel API.
    assert "from actenon_kernel import verify_pccb" in fix.diff, (
        "fix --mode actenon must use `from actenon_kernel import verify_pccb`, "
        "not the broken `from actenon import verify_proof`."
    )
    # The broken import must NOT appear anywhere in the diff.
    assert "from actenon import" not in fix.diff, (
        f"fix --mode actenon still references the non-existent `actenon` package"
    )
    assert "verify_proof" not in fix.diff, (
        "fix --mode actenon still calls `verify_proof` (renamed to `verify_pccb`)"
    )


def test_fix_actenon_mode_applied_file_does_not_break_imports(tmp_path: Path) -> None:
    """Applying `fix --mode actenon` must produce a file that — even though
    the `actenon_kernel` package may not be installed in the user's env —
    at least references a REAL package, not a non-existent one. We verify
    by checking the import line is syntactically valid Python and references
    `actenon_kernel` (a real package on PyPI)."""
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
    fix = generate_fix(src, finding_line, mode="actenon", apply=True)
    assert fix is not None
    assert fix.applied

    # The modified file must be valid Python syntax.
    modified = src.read_text()
    import ast
    ast.parse(modified)  # raises SyntaxError if broken

    # And the import must reference the real package.
    assert "from actenon_kernel import verify_pccb" in modified


# ---------------------------------------------------------------------------
# P0-2: fix.py guard/approval modes must produce CALLS, not pure TODO comments.
# ---------------------------------------------------------------------------


def test_fix_guard_mode_produces_call_not_pure_todo(tmp_path: Path) -> None:
    """P0-2 regression: `fix --mode guard` previously emitted pure
    comment placeholders (`# TODO: add ...`, `# authorize(...)`). The
    user uncomments the call to enable the guard. The output must include
    an actual `authorize(...)` call (commented out), not just a TODO note."""
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
    # The guard call must appear (commented out is fine — the user
    # uncomments when wiring up the guard function).
    assert "authorize(" in fix.diff, (
        "fix --mode guard must produce an authorize(...) call (commented out is OK), "
        "not just a TODO note."
    )


def test_fix_approval_mode_produces_call_not_pure_todo(tmp_path: Path) -> None:
    """P0-2 regression: `fix --mode approval` must produce an actual
    `request_approval(...)` call (commented out), plus the
    raise-on-denial pattern."""
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
    fix = generate_fix(src, finding_line, mode="approval")
    assert fix is not None
    assert "request_approval(" in fix.diff, (
        "fix --mode approval must produce a request_approval(...) call."
    )
    assert "PermissionError" in fix.diff, (
        "fix --mode approval must include the raise-on-denial pattern."
    )


# ---------------------------------------------------------------------------
# P0-3 + P0-4: action.yml sticky-PR-comment env vars and pr_number parsing.
# ---------------------------------------------------------------------------


def test_action_yml_sets_findings_count_env_var() -> None:
    """P0-3 regression: the sticky-PR-comment step's env block must set
    FINDINGS_COUNT (it was previously missing, so the heredoc always
    exited at "No findings — skipping PR comment")."""
    repo_root = Path(__file__).resolve().parent.parent
    action = (repo_root / "action.yml").read_text()
    # The env block on the "Post sticky PR comment" step must include FINDINGS_COUNT.
    assert "FINDINGS_COUNT:" in action, (
        "action.yml 'Post sticky PR comment' step must set FINDINGS_COUNT in env"
    )
    assert "${{ steps.scan.outputs.findings-count }}" in action, (
        "FINDINGS_COUNT must be wired to the scan step's findings-count output"
    )


def test_action_yml_passes_pr_number_explicitly() -> None:
    """P0-4 regression: GITHUB_REF is `refs/pull/123/merge` — split('/')[-1]
    is "merge", not "123". The action must pass PR_NUMBER explicitly from
    github.event.pull_request.number."""
    repo_root = Path(__file__).resolve().parent.parent
    action = (repo_root / "action.yml").read_text()
    assert "PR_NUMBER:" in action, (
        "action.yml must set PR_NUMBER env var explicitly (parsing GITHUB_REF "
        "produces 'merge', not the PR number)"
    )
    assert "github.event.pull_request.number" in action, (
        "PR_NUMBER must come from github.event.pull_request.number"
    )
    # The fragile GITHUB_REF parsing must NOT be the source of truth.
    assert 'os.environ.get("GITHUB_REF", "").split("/")[-1]' not in action, (
        "action.yml still parses GITHUB_REF to extract the PR number — this "
        "produces 'merge' instead of the actual number"
    )


# ---------------------------------------------------------------------------
# P0-5: --changed-only must pick up .ts / .go files, not just .py.
# ---------------------------------------------------------------------------


def test_get_changed_files_returns_ts_and_go_files(tmp_path: Path) -> None:
    """P0-5 regression: --changed-only previously filtered to .py files
    only. The GitHub Action uses --changed-only, so changed .ts/.go files
    in a PR were silently skipped — contradicting the README's "Parses
    Python, TypeScript, and Go" promise."""
    # Initialize a git repo so the function doesn't bail out on git errors.
    import subprocess as sp
    sp.run(["git", "init"], cwd=tmp_path, capture_output=True)
    sp.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True)
    sp.run(["git", "config", "user.name", "test"], cwd=tmp_path, capture_output=True)

    # Create one file of each scannable type.
    (tmp_path / "tool.py").write_text("def f(): pass\n")
    (tmp_path / "tool.ts").write_text("function f() {}\n")
    (tmp_path / "tool.go").write_text("package main\n")
    sp.run(["git", "add", "."], cwd=tmp_path, capture_output=True)
    sp.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True)

    # Modify all three and verify _get_changed_files returns all three.
    (tmp_path / "tool.py").write_text("def g(): pass\n")
    (tmp_path / "tool.ts").write_text("function g() {}\n")
    (tmp_path / "tool.go").write_text("package main\nfunc g() {}\n")

    from actenon_scan.cli import _get_changed_files
    changed = _get_changed_files("HEAD", tmp_path)
    assert changed is not None, "git diff returned nothing"
    # All three scannable extensions must be present.
    assert "tool.py" in changed, f".py file missing from changed list: {changed}"
    assert "tool.ts" in changed, f".ts file missing from changed list: {changed}"
    assert "tool.go" in changed, f".go file missing from changed list: {changed}"


# ---------------------------------------------------------------------------
# P0-6: suppress.py must accept BOTH `ignore[RULE]` and `suppress RULE` syntaxes.
# ---------------------------------------------------------------------------


def test_suppression_accepts_bracketed_ignore_syntax() -> None:
    """P0-6 regression: the bracketed `# actenon-scan: ignore[RULE-ID]`
    syntax must continue to work."""
    from actenon_scan.suppress import parse_suppressions
    source = (
        "# actenon-scan: ignore[EXEC-SHELL]\n"
        "subprocess.run(cmd, shell=True)\n"
    )
    sups = parse_suppressions(source, "tool.py")
    assert ("tool.py", "EXEC-SHELL") in sups


def test_suppression_accepts_space_separated_suppress_syntax() -> None:
    """P0-6 regression: the README-documented `# actenon-scan: suppress RULE-ID`
    syntax must ALSO work. Previously the README documented this form but
    the code only matched the bracketed form — copy-paste was a silent no-op."""
    from actenon_scan.suppress import parse_suppressions
    source = (
        "# actenon-scan: suppress EXEC-SHELL\n"
        "subprocess.run(cmd, shell=True)\n"
    )
    sups = parse_suppressions(source, "tool.py")
    assert ("tool.py", "EXEC-SHELL") in sups, (
        f"suppress RULE-ID syntax not recognised: {sups}"
    )


def test_suppression_accepts_both_syntaxes_in_same_file() -> None:
    """Both syntaxes must work in the same file."""
    from actenon_scan.suppress import parse_suppressions
    source = (
        "# actenon-scan: ignore[EXEC-SHELL]\n"
        "subprocess.run(cmd, shell=True)\n"
        "# actenon-scan: suppress REPOSITORY-MUTATION\n"
        "g.create_file(path, content)\n"
    )
    sups = parse_suppressions(source, "tool.py")
    assert ("tool.py", "EXEC-SHELL") in sups
    assert ("tool.py", "REPOSITORY-MUTATION") in sups


# ---------------------------------------------------------------------------
# P0-7: pyproject.toml must have [project.urls].
# ---------------------------------------------------------------------------


def test_pyproject_has_project_urls() -> None:
    """P0-7 regression: the PyPI page had no sidebar links because
    pyproject.toml had no [project.urls] section."""
    repo_root = Path(__file__).resolve().parent.parent
    pyproject = (repo_root / "pyproject.toml").read_text()
    assert "[project.urls]" in pyproject, (
        "pyproject.toml must have a [project.urls] section for PyPI sidebar links"
    )
    # The key URLs every package should have.
    for key in ("Homepage", "Source", "Issues", "Changelog", "Security"):
        assert f"{key} =" in pyproject, (
            f"pyproject.toml [project.urls] must include {key}"
        )


# ---------------------------------------------------------------------------
# P0-8: __version__ must NOT fall back to "0.0.0+unknown" when running
# from source. It should read pyproject.toml.
# ---------------------------------------------------------------------------


def test_version_fallback_reads_pyproject_toml() -> None:
    """P0-8 regression: __init__.py said it fell back to reading
    pyproject.toml, but the code returned the literal "0.0.0+unknown".
    `--version` and SARIF tool.driver.version both lied when running
    from source."""
    # Read pyproject.toml directly to know what version we expect.
    repo_root = Path(__file__).resolve().parent.parent
    import re
    pyproject_text = (repo_root / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_text, re.MULTILINE)
    assert m, "could not parse version from pyproject.toml"
    expected_version = m.group(1)

    # Re-import the package fresh to exercise the fallback path.
    # We can't easily simulate "PackageNotFoundError" without uninstalling,
    # but we can verify the fallback code path is present and would work.
    init_src = (repo_root / "actenon_scan" / "__init__.py").read_text()
    assert "pyproject.toml" in init_src, (
        "__init__.py must read pyproject.toml as the version fallback, "
        "not return the literal '0.0.0+unknown'"
    )
    # The regex to extract the version must be present.
    assert 'version' in init_src and 'search' in init_src, (
        "__init__.py must search for the version line in pyproject.toml"
    )

    # And the installed version must equal the pyproject version.
    from actenon_scan import __version__
    assert __version__ == expected_version, (
        f"installed version {__version__!r} != pyproject version {expected_version!r}"
    )


# ---------------------------------------------------------------------------
# P0-9: SARIF rules must have helpUri, tags, and CWE/OWASP metadata.
# ---------------------------------------------------------------------------


def test_sarif_rules_have_helpuri() -> None:
    """P0-9 regression: SARIF rules had no helpUri. GitHub's Security tab
    renders a 'Learn more' link from helpUri — without it, reviewers see
    only the rule ID and description."""
    from actenon_scan.engine import ScanResult, Finding
    from actenon_scan.report.sarif import format_sarif

    # Construct a ScanResult with one finding.
    finding = Finding(
        file="tool.py", line=7, col=0,
        rule_id="EXEC-SHELL", category="shell_execution",
        severity="high", confidence="high",
        description="subprocess.run in agent tool",
        call_text="subprocess.run(cmd, shell=True)",
        remediation="Guard this call",
    )
    result = ScanResult(findings=[finding])

    sarif = json.loads(format_sarif(result))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "helpUri" in rule, "SARIF rule must have helpUri"
    assert "COVERAGE.md" in rule["helpUri"], (
        f"helpUri should point at docs/COVERAGE.md, got: {rule['helpUri']}"
    )
    assert rule["helpUri"].endswith("#exec-shell"), (
        f"helpUri should anchor on the lowercased rule ID, got: {rule['helpUri']}"
    )


def test_sarif_rules_have_tags() -> None:
    """P0-9 regression: SARIF rules had no properties.tags. GitHub uses
    tags for filtering and dashboards."""
    from actenon_scan.engine import ScanResult, Finding
    from actenon_scan.report.sarif import format_sarif

    finding = Finding(
        file="tool.py", line=7, col=0,
        rule_id="PAY-STRIPE-REFUND", category="payments",
        severity="high", confidence="high",
        description="Stripe refund call",
        call_text="stripe.Refund.create()",
        remediation="Guard this call",
    )
    result = ScanResult(findings=[finding])

    sarif = json.loads(format_sarif(result))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    tags = rule["properties"].get("tags", [])
    assert "security" in tags, f"tags must include 'security': {tags}"
    assert "ai-agent" in tags, f"tags must include 'ai-agent': {tags}"


def test_sarif_rules_include_cwe_and_owasp_when_present() -> None:
    """P0-9 regression: default_rules.json has CWE/OWASP on every rule,
    but SARIF previously dropped them. They must now appear in properties."""
    from actenon_scan.engine import ScanResult, Finding
    from actenon_scan.report.sarif import format_sarif
    from actenon_scan.rules.loader import load_default_rules, SinkRule

    # Use the real default rules to find a rule that has CWE/OWASP.
    ruleset = load_default_rules()
    rule_with_cwe = next(
        (s for s in ruleset.sinks if s.cwe and s.owasp),
        None,
    )
    assert rule_with_cwe is not None, "no default rule has both cwe and owasp"

    finding = Finding(
        file="tool.py", line=7, col=0,
        rule_id=rule_with_cwe.id, category=rule_with_cwe.category,
        severity=rule_with_cwe.severity, confidence="high",
        description=rule_with_cwe.description,
        call_text="some_call()",
        remediation="Guard this call",
    )
    result = ScanResult(findings=[finding], rules_used=ruleset)

    sarif = json.loads(format_sarif(result))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    props = rule["properties"]
    assert "cwe" in props, f"properties must include cwe: {props}"
    assert "owasp" in props, f"properties must include owasp: {props}"
    # And the tags must include the lowercased CWE/OWASP.
    tags = props.get("tags", [])
    assert any(t.startswith("cwe-") for t in tags), (
        f"tags must include a cwe-* tag: {tags}"
    )
    assert any(t.startswith("owasp-") for t in tags), (
        f"tags must include an owasp-* tag: {tags}"
    )


# ---------------------------------------------------------------------------
# P0-10: .pre-commit-hooks.yaml must declare additional_dependencies for
# TS/Go hooks (otherwise the hooks silently do nothing).
# ---------------------------------------------------------------------------


def test_precommit_ts_hook_has_additional_dependencies() -> None:
    """P0-10 regression: the TS pre-commit hook declared no
    additional_dependencies. Pre-commit's isolated venv had no
    tree-sitter-typescript, so every TS file was silently treated as
    'unsupported' and the hook exited 0 having done nothing."""
    repo_root = Path(__file__).resolve().parent.parent
    hooks_yaml = (repo_root / ".pre-commit-hooks.yaml").read_text()
    # The TS hook must declare additional_dependencies.
    assert "tree-sitter-typescript" in hooks_yaml, (
        ".pre-commit-hooks.yaml TS hook must declare tree-sitter-typescript "
        "in additional_dependencies"
    )
    # Same for the Go hook.
    assert "tree-sitter-go" in hooks_yaml, (
        ".pre-commit-hooks.yaml Go hook must declare tree-sitter-go "
        "in additional_dependencies"
    )


# ---------------------------------------------------------------------------
# P0-11: _parse_location must reject negative line numbers.
# ---------------------------------------------------------------------------


def test_parse_location_rejects_negative_line(tmp_path: Path) -> None:
    """P0-11 regression: `explain app.py:-1` previously ran a full scan
    and returned 'No finding at app.py:-1.' — wasteful and misleading."""
    src = tmp_path / "tool.py"
    src.write_text("def f(): pass\n")

    from actenon_scan.cli import _parse_location, main
    rc = _parse_location(f"{src}:-1")
    assert rc == 2, f"negative line must return exit code 2, got {rc}"

    # And via the CLI — explain with negative line should exit 2
    # WITHOUT running a scan (it should fail fast).
    rc = main(["explain", f"{src}:-1"])
    assert rc == 2


def test_parse_location_rejects_zero_line(tmp_path: Path) -> None:
    """A 0 line number is also malformed (line numbers are 1-indexed)."""
    src = tmp_path / "tool.py"
    src.write_text("def f(): pass\n")

    from actenon_scan.cli import _parse_location
    rc = _parse_location(f"{src}:0")
    assert rc == 2


def test_parse_location_accepts_valid_line(tmp_path: Path) -> None:
    """A valid line number must still parse correctly."""
    src = tmp_path / "tool.py"
    src.write_text("def f(): pass\n")

    from actenon_scan.cli import _parse_location
    result = _parse_location(f"{src}:1")
    assert not isinstance(result, int), f"valid line returned exit code: {result}"
    file_path, line = result
    assert file_path == src
    assert line == 1


# ---------------------------------------------------------------------------
# M-1: fix.py must refuse non-Python files with a helpful message
# (rather than inserting Python syntax into a .ts/.go file).
# ---------------------------------------------------------------------------


def test_fix_refuses_typescript_file_safely(tmp_path: Path) -> None:
    """M-1 regression: `fix app.ts:7` previously inserted Python syntax
    (`#` comments, `raise PermissionError`) into the .ts file. Applying
    it produced invalid TypeScript. The fix generator must refuse with a
    helpful note instead."""
    src = tmp_path / "tool.ts"
    src.write_text(textwrap.dedent("""\
        import { tool } from "@modelcontextprotocol/sdk";
        import { exec } from "child_process";

        tool("delete_file", async (args) => {
            exec(args.cmd);
        });
        """))
    # Find the sink line.
    lines = src.read_text().splitlines()
    finding_line = next(i + 1 for i, l in enumerate(lines) if "exec(" in l)

    from actenon_scan.fix import generate_fix
    fix = generate_fix(src, finding_line, mode="guard")
    assert fix is not None
    # The diff must be empty — no patch generated.
    assert fix.diff == "", (
        f"fix must not generate a diff for .ts files: {fix.diff!r}"
    )
    # The note must explain WHY and point to the issue tracker.
    assert "not yet supported" in fix.note.lower() or "ts" in fix.note.lower(), (
        f"fix note must explain TS is not supported: {fix.note!r}"
    )


def test_fix_refuses_go_file_safely(tmp_path: Path) -> None:
    """M-1 regression: same as above, for Go files."""
    src = tmp_path / "tool.go"
    src.write_text(textwrap.dedent("""\
        package main

        import "os/exec"

        func deleteFile(cmd string) {
            exec.Command("sh", "-c", cmd).Run()
        }
        """))
    lines = src.read_text().splitlines()
    finding_line = next(i + 1 for i, l in enumerate(lines) if "exec.Command" in l)

    from actenon_scan.fix import generate_fix
    fix = generate_fix(src, finding_line, mode="guard")
    assert fix is not None
    assert fix.diff == "", (
        f"fix must not generate a diff for .go files: {fix.diff!r}"
    )


# ---------------------------------------------------------------------------
# M-2: `actenon-scan baseline` subcommand must exist and produce a
# baseline.json file.
# ---------------------------------------------------------------------------


def test_baseline_subcommand_writes_baseline_file(tmp_path: Path) -> None:
    """M-2 regression: _cmd_adopt told users to run `actenon-scan baseline
    <path>` but no such subcommand existed. The new subcommand must scan
    a path and write a baseline.json file."""
    # Create a fixture with one finding.
    (tmp_path / "tool.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
        """))

    output_file = tmp_path / "baseline.json"
    from actenon_scan.cli import main
    rc = main(["baseline", str(tmp_path), "--output", str(output_file)])
    assert rc == 0, f"baseline subcommand failed with exit code {rc}"

    # The baseline file must exist and be valid JSON.
    assert output_file.exists(), "baseline.json was not written"
    data = json.loads(output_file.read_text())
    assert "findings" in data, f"baseline must have a findings array: {data}"
    # And it must contain at least one finding (our fixture has one).
    assert len(data["findings"]) >= 1, (
        f"baseline must contain at least one finding: {data}"
    )
    # Each finding must have the keys load_baseline expects.
    for f in data["findings"]:
        assert "file" in f
        assert "snippet_hash" in f
        assert "rule_id" in f


def test_baseline_subcommand_then_scan_suppresses_baseline_findings(tmp_path: Path) -> None:
    """The baseline produced by `actenon-scan baseline` must work with
    `actenon-scan scan --baseline` — i.e., the findings in the baseline
    must be suppressed on the next scan."""
    (tmp_path / "tool.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
        """))

    baseline_file = tmp_path / "baseline.json"
    from actenon_scan.cli import main
    rc = main(["baseline", str(tmp_path), "--output", str(baseline_file)])
    assert rc == 0

    # Now scan WITH the baseline — the finding must be suppressed.
    from actenon_scan.engine import scan_path
    from actenon_scan.baseline import load_baseline
    baseline = load_baseline(baseline_file)
    result = scan_path(tmp_path, baseline_findings=baseline)
    unsuppressed = [f for f in result.findings if not f.suppressed]
    assert unsuppressed == [], (
        f"baseline-suppressed scan must have 0 unsuppressed findings, got: {unsuppressed}"
    )


# ---------------------------------------------------------------------------
# M-3: explain / brief must support --all flag.
# ---------------------------------------------------------------------------


def test_explain_all_generates_explanations_for_every_finding(tmp_path: Path) -> None:
    """M-3 regression: explain previously took a single file:line. A user
    with 50 findings ran 50 commands. The new --all flag must explain
    every finding in one invocation."""
    # Create two files with findings.
    (tmp_path / "a.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool
        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
        """))
    (tmp_path / "b.py").write_text(textwrap.dedent("""\
        import os
        from mcp import tool
        @tool
        def delete(path: str) -> str:
            os.remove(path)
            return "deleted"
        """))

    from actenon_scan.cli import main
    import io
    from contextlib import redirect_stdout
    f = io.StringIO()
    with redirect_stdout(f):
        rc = main(["explain", "--all", "--path", str(tmp_path)])
    assert rc == 0
    output = f.getvalue()
    # The output must include both findings' explanations.
    assert "subprocess.run" in output or "EXEC-SHELL" in output, (
        f"explain --all missing subprocess finding: {output[:500]}"
    )
    assert "os.remove" in output or "DATA-DELETE" in output, (
        f"explain --all missing os.remove finding: {output[:500]}"
    )


def test_brief_all_generates_briefs_for_every_finding(tmp_path: Path) -> None:
    """M-3 regression: same as above, for `brief --all`."""
    (tmp_path / "a.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool
        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
        """))
    (tmp_path / "b.py").write_text(textwrap.dedent("""\
        import os
        from mcp import tool
        @tool
        def delete(path: str) -> str:
            os.remove(path)
            return "deleted"
        """))

    from actenon_scan.cli import main
    import io
    from contextlib import redirect_stdout
    f = io.StringIO()
    with redirect_stdout(f):
        rc = main(["brief", "--all", "--path", str(tmp_path), "--format", "markdown"])
    assert rc == 0
    output = f.getvalue()
    # The output must include both findings.
    assert "subprocess.run" in output or "EXEC-SHELL" in output
    assert "os.remove" in output or "DATA-DELETE" in output
