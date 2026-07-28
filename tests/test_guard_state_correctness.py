"""Work Order 1.5 — Guard-state correctness and parity tests.

Tests three properties that block Work Order 2's GUARD FOUND state:

1. ITEM 1 — Defeated-guard detection per variant per language.
   Every defeated-guard variant (result discarded, after sink, dead branch,
   split branch, try/catch swallow) must be FLAGGED, not suppressed, in
   every supported language.

2. ITEM 2 — Guard-outcome parity across Python, TypeScript, and Go.
   The same semantic case must produce the same guard state in all three
   languages. The v1.1.4 parity test compared sink detection but not
   guard outcomes — this test fills that gap.

3. ITEM 3 — --fail-on-unsupported exit code (CLI).
   The flag must cause exit 1 when unsupported files are present.

These tests are in the soundness suite because they test the core
soundness property: a guard that doesn't actually guard must not suppress
a finding. A permissive implementation that suppresses on any guard-named
call would clear the harness test and blind the scanner — and the first
affirmative claim this scanner will make (GUARD FOUND, Work Order 2)
would be wrong.

Requires the [typescript] and [go] extras. Automatically skipped when
either is absent.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# Skip all tests in this module if either TS or Go extras are missing.
from actenon_scan.detectors.go import is_go_extra_available
from actenon_scan.detectors.typescript import is_typescript_extra_available

pytestmark = pytest.mark.skipif(
    not is_go_extra_available() or not is_typescript_extra_available(),
    reason="[typescript] and [go] extras required for guard-state parity tests",
)


# ---------------------------------------------------------------------------
# Fixture builders — one per language, one per defeated-guard variant.
# ---------------------------------------------------------------------------

GUARD_PATTERNS = [
    "authorize", "authorizeBool", "authorize_bool",
    "authorizeAssert", "authorize_assert",
    "isAuthorized", "assertAuthorized",
]


def _py_fixture(variant: str) -> str:
    """Build a Python fixture for the given guard variant.

    Each fixture has one @tool-decorated function with a sink (os.remove)
    and a guard (authorize_bool / authorize_assert). The variant determines
    how the guard is defeated.
    """
    variants = {
        "guarded_bool": '''
            @tool
            def f(path: str) -> None:
                if authorize_bool(path):
                    os.remove(path)
        ''',
        "guarded_assert": '''
            @tool
            def f(path: str) -> None:
                authorize_assert(path)
                os.remove(path)
        ''',
        "defeated_discarded": '''
            @tool
            def f(path: str) -> None:
                authorize_bool(path)
                os.remove(path)
        ''',
        "defeated_after_sink": '''
            @tool
            def f(path: str) -> None:
                os.remove(path)
                authorize_bool(path)
        ''',
        "defeated_dead_branch": '''
            @tool
            def f(path: str) -> None:
                if False:
                    authorize_bool(path)
                os.remove(path)
        ''',
        "defeated_split_branch": '''
            @tool
            def f(path: str) -> None:
                if path.startswith("/tmp/"):
                    authorize_bool(path)
                os.remove(path)
        ''',
        "defeated_try_except_swallow": '''
            @tool
            def f(path: str) -> None:
                try:
                    authorize_assert(path)
                except Exception:
                    pass
                os.remove(path)
        ''',
        "unguarded": '''
            @tool
            def f(path: str) -> None:
                os.remove(path)
        ''',
    }
    body = textwrap.dedent(variants[variant]).strip()
    return f'''import os
from mcp import tool

{body}

def authorize_bool(path: str) -> bool:
    return path.startswith("/tmp/")

def authorize_assert(path: str) -> None:
    if not path.startswith("/tmp/"):
        raise PermissionError(path)
'''


def _ts_fixture(variant: str) -> str:
    """Build a TypeScript fixture for the given guard variant."""
    variants = {
        "guarded_bool": '''
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const path = req.params.arguments.path as string;
    if (isAuthorized(path)) { fs.rmSync(path); }
    return { content: [{ type: "text", text: "ok" }] };
});
''',
        "guarded_assert": '''
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const path = req.params.arguments.path as string;
    assertAuthorized(path);
    fs.rmSync(path);
    return { content: [{ type: "text", text: "ok" }] };
});
''',
        "defeated_discarded": '''
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const path = req.params.arguments.path as string;
    isAuthorized(path);
    fs.rmSync(path);
    return { content: [{ type: "text", text: "ok" }] };
});
''',
        "defeated_after_sink": '''
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const path = req.params.arguments.path as string;
    fs.rmSync(path);
    isAuthorized(path);
    return { content: [{ type: "text", text: "ok" }] };
});
''',
        "defeated_dead_branch": '''
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const path = req.params.arguments.path as string;
    if (false) { isAuthorized(path); }
    fs.rmSync(path);
    return { content: [{ type: "text", text: "ok" }] };
});
''',
        "defeated_split_branch": '''
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const path = req.params.arguments.path as string;
    if (path.startsWith("/tmp/")) { isAuthorized(path); }
    fs.rmSync(path);
    return { content: [{ type: "text", text: "ok" }] };
});
''',
        "defeated_try_except_swallow": '''
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const path = req.params.arguments.path as string;
    try { assertAuthorized(path); } catch (e) {}
    fs.rmSync(path);
    return { content: [{ type: "text", text: "ok" }] };
});
''',
        "unguarded": '''
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const path = req.params.arguments.path as string;
    fs.rmSync(path);
    return { content: [{ type: "text", text: "ok" }] };
});
''',
    }
    body = variants[variant]
    return f'''import * as fs from 'fs';
import {{ Server }} from "@modelcontextprotocol/sdk/server/index.js";
import {{ CallToolRequestSchema }} from "@modelcontextprotocol/sdk/types.js";

const server = new Server({{ name: "t", version: "1" }}, {{ capabilities: {{ tools: {{}} }} }});

{body}

function isAuthorized(path: string): boolean {{ return path.startsWith('/tmp/'); }}
function assertAuthorized(path: string): void {{ if (!path.startsWith('/tmp/')) throw new Error('no'); }}
'''


def _go_fixture(variant: str) -> str:
    """Build a Go fixture for the given guard variant."""
    variants = {
        "guarded_bool": '''
func f(ctx context.Context, req *mcp.CallToolRequest, args struct{ Path string }) (*mcp.CallToolResult, struct{}, error) {
    if authorizeBool(args.Path) {
        os.Remove(args.Path)
    }
    return mcp.NewToolResultText("ok"), struct{}{}, nil
}
''',
        "guarded_assert": '''
func f(ctx context.Context, req *mcp.CallToolRequest, args struct{ Path string }) (*mcp.CallToolResult, struct{}, error) {
    authorizeAssert(args.Path)
    os.Remove(args.Path)
    return mcp.NewToolResultText("ok"), struct{}{}, nil
}
''',
        "defeated_discarded": '''
func f(ctx context.Context, req *mcp.CallToolRequest, args struct{ Path string }) (*mcp.CallToolResult, struct{}, error) {
    authorizeBool(args.Path)
    os.Remove(args.Path)
    return mcp.NewToolResultText("ok"), struct{}{}, nil
}
''',
        "defeated_after_sink": '''
func f(ctx context.Context, req *mcp.CallToolRequest, args struct{ Path string }) (*mcp.CallToolResult, struct{}, error) {
    os.Remove(args.Path)
    authorizeBool(args.Path)
    return mcp.NewToolResultText("ok"), struct{}{}, nil
}
''',
        "defeated_dead_branch": '''
func f(ctx context.Context, req *mcp.CallToolRequest, args struct{ Path string }) (*mcp.CallToolResult, struct{}, error) {
    if false {
        authorizeBool(args.Path)
    }
    os.Remove(args.Path)
    return mcp.NewToolResultText("ok"), struct{}{}, nil
}
''',
        "defeated_split_branch": '''
func f(ctx context.Context, req *mcp.CallToolRequest, args struct{ Path string }) (*mcp.CallToolResult, struct{}, error) {
    if len(args.Path) > 0 {
        authorizeBool(args.Path)
    }
    os.Remove(args.Path)
    return mcp.NewToolResultText("ok"), struct{}{}, nil
}
''',
        # Go has no try/catch; this variant is N/A for Go. We use a recover()
        # pattern as the closest analog.
        "defeated_try_except_swallow": '''
func f(ctx context.Context, req *mcp.CallToolRequest, args struct{ Path string }) (*mcp.CallToolResult, struct{}, error) {
    defer func() { recover() }()
    authorizeAssert(args.Path)
    os.Remove(args.Path)
    return mcp.NewToolResultText("ok"), struct{}{}, nil
}
''',
        "unguarded": '''
func f(ctx context.Context, req *mcp.CallToolRequest, args struct{ Path string }) (*mcp.CallToolResult, struct{}, error) {
    os.Remove(args.Path)
    return mcp.NewToolResultText("ok"), struct{}{}, nil
}
''',
    }
    body = variants[variant]
    return f'''package tools

import (
    "context"
    "os"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

{body}

func authorizeBool(path string) bool {{ return len(path) > 0 }}
func authorizeAssert(path string) {{ if len(path) == 0 {{ panic("no") }} }}

func main() {{
    server := mcp.NewServer("test", "1.0")
    mcp.AddTool(server, &mcp.Tool{{Name: "f"}}, f)
}}
'''


# ---------------------------------------------------------------------------
# Expected guard state per variant.
# ---------------------------------------------------------------------------

# The expected guard state for each variant. All three languages must
# agree on these. "suppressed" = no finding; "low" = WEAK finding;
# "high" = finding at original severity.
EXPECTED_STATES = {
    "guarded_bool":              "suppressed",
    "guarded_assert":            "suppressed",
    "defeated_discarded":        "low",      # WEAK — guard name present, result discarded
    "defeated_after_sink":       "high",     # guard after sink doesn't dominate
    "defeated_dead_branch":      "high",     # if False doesn't dominate
    "defeated_split_branch":     "high",     # guard on one branch doesn't dominate
    "defeated_try_except_swallow": "high",   # swallowed raise doesn't dominate
    "unguarded":                 "high",
}


def _scan_py(source: str) -> list:
    """Scan a Python source string and return findings.

    Writes a .actenon-scan.json config to the temp directory so the
    custom guard patterns (authorize_bool, etc.) are recognised.
    """
    from actenon_scan.engine import scan_path
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        tdpath = Path(td)
        p = tdpath / "test.py"
        p.write_text(textwrap.dedent(source))
        # Write config with custom guard patterns
        config_path = tdpath / ".actenon-scan.json"
        config = {"guard_patterns": GUARD_PATTERNS}
        config_path.write_text(json.dumps(config))
        result = scan_path(tdpath, config=config_path)
        return [f for f in result.findings if not f.suppressed]


def _scan_ts(source: str) -> list:
    """Scan a TS source string and return findings (excluding guarded, as the engine does)."""
    from actenon_scan.detectors.typescript import analyze_typescript_file
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.ts"
        p.write_text(textwrap.dedent(source))
        findings, errors = analyze_typescript_file(p, guard_patterns=GUARD_PATTERNS)
        assert not errors, f"TS analysis errors: {errors}"
        # Filter out guarded findings — the engine does this, and tests
        # check what the user would see (findings, not capabilities).
        return [f for f in findings if f.guard_status != "guarded"]


def _scan_go(source: str) -> list:
    """Scan a Go source string and return findings (excluding guarded, as the engine does)."""
    from actenon_scan.detectors.go import scan_go_file
    findings = scan_go_file("test.go", textwrap.dedent(source).encode("utf-8"),
                        guard_patterns=GUARD_PATTERNS)
    # Filter out guarded findings — the engine does this, and tests
    # check what the user would see (findings, not capabilities).
    return [f for f in findings if f.guard_status != "guarded"]


def _finding_state(findings: list, sink_substring: str = "remove") -> str:
    """Determine the guard state from a list of findings.

    Returns "suppressed" (no finding), "low" (WEAK), "medium" (UNBOUND),
    or "high" (original severity).
    """
    sink_findings = [f for f in findings if sink_substring.lower() in f.call_text.lower()
                     or "rmSync" in f.call_text]
    if not sink_findings:
        return "suppressed"
    f = sink_findings[0]
    if "WEAK" in f.rule_id or f.severity == "low":
        return "low"
    if "UNBOUND" in f.rule_id or f.severity == "medium":
        return "medium"
    return "high"


# ---------------------------------------------------------------------------
# ITEM 1 + ITEM 2: Per-variant per-language tests + parity assertion.
# ---------------------------------------------------------------------------

VARIANTS = [
    "guarded_bool",
    "guarded_assert",
    "defeated_discarded",
    "defeated_after_sink",
    "defeated_dead_branch",
    "defeated_split_branch",
    "defeated_try_except_swallow",
    "unguarded",
]

LANGUAGES = ["python", "typescript", "go"]


@pytest.mark.parametrize("variant", VARIANTS)
def test_python_guard_state(variant: str) -> None:
    """Item 1 + 2: Python guard state per variant."""
    findings = _scan_py(_py_fixture(variant))
    actual = _finding_state(findings)
    expected = EXPECTED_STATES[variant]
    assert actual == expected, (
        f"Python {variant}: expected {expected!r}, got {actual!r}. "
        f"Findings: {[(f.line, f.rule_id, f.severity) for f in findings]}"
    )


@pytest.mark.parametrize("variant", VARIANTS)
def test_typescript_guard_state(variant: str) -> None:
    """Item 1 + 2: TypeScript guard state per variant."""
    findings = _scan_ts(_ts_fixture(variant))
    actual = _finding_state(findings, sink_substring="rmSync")
    expected = EXPECTED_STATES[variant]
    assert actual == expected, (
        f"TypeScript {variant}: expected {expected!r}, got {actual!r}. "
        f"Findings: {[(f.line, f.rule_id, f.severity) for f in findings]}"
    )


@pytest.mark.parametrize("variant", VARIANTS)
def test_go_guard_state(variant: str) -> None:
    """Item 1 + 2: Go guard state per variant.

    The `defeated_try_except_swallow` variant is N/A for Go: Go has no
    try/catch, and the closest analog (`defer func() { recover() }()`)
    does NOT defeat the guard — a panic still unwinds the stack, so
    code after the panicking call never runs. The guard IS effective.
    """
    if variant == "defeated_try_except_swallow":
        pytest.skip("Go has no try/catch; defer-recover does not defeat the guard (panic unwinds)")
    findings = _scan_go(_go_fixture(variant))
    actual = _finding_state(findings)
    expected = EXPECTED_STATES[variant]
    assert actual == expected, (
        f"Go {variant}: expected {expected!r}, got {actual!r}. "
        f"Findings: {[(f.line, f.rule_id, f.severity) for f in findings]}"
    )


def test_guard_state_parity_across_languages() -> None:
    """Item 2: the same semantic case must produce the same guard state
    in all three languages. This is the extended parity test that the
    v1.1.4 parity test did NOT cover — it compared sink detection but
    not guard outcomes.

    The `defeated_try_except_swallow` variant is excluded from the
    cross-language parity assertion because Go has no try/catch
    equivalent (see test_go_guard_state for details).
    """
    parity_variants = [v for v in VARIANTS if v != "defeated_try_except_swallow"]
    mismatches = []
    for variant in parity_variants:
        states = {}
        try:
            states["python"] = _finding_state(_scan_py(_py_fixture(variant)))
        except Exception as e:
            states["python"] = f"ERROR: {e}"
        try:
            states["typescript"] = _finding_state(_scan_ts(_ts_fixture(variant)), "rmSync")
        except Exception as e:
            states["typescript"] = f"ERROR: {e}"
        try:
            states["go"] = _finding_state(_scan_go(_go_fixture(variant)))
        except Exception as e:
            states["go"] = f"ERROR: {e}"

        if len(set(states.values())) > 1:
            mismatches.append((variant, states))

    assert not mismatches, (
        f"Guard-state parity mismatches:\n" +
        "\n".join(f"  {v}: {s}" for v, s in mismatches)
    )

    # Separately verify that Python and TS agree on the try/catch variant
    # (Go is excluded — see above).
    ts_catch = _finding_state(_scan_ts(_ts_fixture("defeated_try_except_swallow")), "rmSync")
    py_catch = _finding_state(_scan_py(_py_fixture("defeated_try_except_swallow")))
    assert py_catch == ts_catch == "high", (
        f"try/catch swallow: Python={py_catch!r}, TS={ts_catch!r}, both should be 'high'"
    )


# ---------------------------------------------------------------------------
# ITEM 3: --fail-on-unsupported exit code test (CLI).
# ---------------------------------------------------------------------------

def test_fail_on_unsupported_exits_nonzero(tmp_path: Path) -> None:
    """Item 3: --fail-on-unsupported must cause exit 1 when unsupported
    source files are present.

    This is the failure mode that produced the original Go incident — a
    scanner reporting clean on files it could not read. The flag exists
    specifically to prevent it.
    """
    # Create a fixture with an unsupported .rb file
    (tmp_path / "tool.py").write_text(textwrap.dedent('''
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
    '''))
    (tmp_path / "tool.rb").write_text("def foo; end\n")

    # Run the CLI with --fail-on-unsupported
    result = subprocess.run(
        [sys.executable, "-m", "actenon_scan", "scan", str(tmp_path),
         "--fail-on", "none", "--fail-on-unsupported", "--format", "json",
         "--output", str(tmp_path / "results.json")],
        capture_output=True, text=True, timeout=30,
    )

    assert result.returncode == 1, (
        f"--fail-on-unsupported should exit 1 when unsupported files present. "
        f"Got exit {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_fail_on_unsupported_not_set_exits_zero(tmp_path: Path) -> None:
    """Item 3: without --fail-on-unsupported, unsupported files do NOT
    fail the build (default behaviour). The unsupported files are still
    reported in the output, but the exit code is 0."""
    (tmp_path / "tool.py").write_text(textwrap.dedent('''
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
    '''))
    (tmp_path / "tool.rb").write_text("def foo; end\n")

    result = subprocess.run(
        [sys.executable, "-m", "actenon_scan", "scan", str(tmp_path),
         "--fail-on", "none", "--format", "json",
         "--output", str(tmp_path / "results.json")],
        capture_output=True, text=True, timeout=30,
    )

    assert result.returncode == 0, (
        f"Without --fail-on-unsupported, exit should be 0. "
        f"Got exit {result.returncode}.\nstderr: {result.stderr}"
    )


def test_fail_on_unsupported_no_unsupported_files_exits_zero(tmp_path: Path) -> None:
    """Item 3: --fail-on-unsupported with NO unsupported files exits 0."""
    (tmp_path / "tool.py").write_text(textwrap.dedent('''
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
    '''))

    result = subprocess.run(
        [sys.executable, "-m", "actenon_scan", "scan", str(tmp_path),
         "--fail-on", "none", "--fail-on-unsupported", "--format", "json",
         "--output", str(tmp_path / "results.json")],
        capture_output=True, text=True, timeout=30,
    )

    assert result.returncode == 0, (
        f"--fail-on-unsupported with no unsupported files should exit 0. "
        f"Got exit {result.returncode}.\nstderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# ITEM 3: JSON output carries a top-level version field.
# ---------------------------------------------------------------------------

def test_json_output_has_version_field(tmp_path: Path) -> None:
    """Item 3: JSON output must carry a top-level `version` field
    identifying the scanner version that produced it. This makes any
    JSON output attributable to a specific release without inspecting
    the Action logs."""
    (tmp_path / "tool.py").write_text(textwrap.dedent('''
        import subprocess
        from mcp import tool

        @tool
        def run(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout.decode()
    '''))

    out = tmp_path / "results.json"
    result = subprocess.run(
        [sys.executable, "-m", "actenon_scan", "scan", str(tmp_path),
         "--fail-on", "none", "--format", "json", "--output", str(out)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"Scan failed: {result.stderr}"

    data = json.loads(out.read_text())
    assert "version" in data, (
        f"JSON output must have a top-level 'version' field. "
        f"Keys: {list(data.keys())}"
    )
    assert data["version"] != "unknown", (
        f"JSON version field must not be 'unknown'. Got: {data['version']!r}"
    )
    # Verify it matches the installed package version
    import actenon_scan
    assert data["version"] == actenon_scan.__version__, (
        f"JSON version ({data['version']!r}) != package version ({actenon_scan.__version__!r})"
    )
    # Also check the scanner name field
    assert data.get("scanner") == "actenon-scan", (
        f"JSON scanner field should be 'actenon-scan'. Got: {data.get('scanner')!r}"
    )
