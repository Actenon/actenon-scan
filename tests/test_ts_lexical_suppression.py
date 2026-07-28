"""Work Order 1.6 — Lexical-suppression regression test.

Tests that the TS guard rewrite does NOT suppress findings based on guard
words appearing in comments, imports, string literals, or variable names.

Before WO1.5, the lexical heuristic scanned every line for guard-pattern
substrings. Any line containing a guard word was added to ``guard_lines``,
and any sink appearing after any such line was suppressed — regardless of
function boundary, dominance, binding, or result-use.

This test scans a fixture file that has:
  - a comment containing "authorize"
  - an import of a guard-named symbol (authorizeButton)
  - a string literal containing "unauthorized"
  - a variable name containing "guard" (guardedHandler)
  - a region marker containing "guard"
  - an agent-reachable sink (execSync inside a tool handler)
  - NO real guard call dominating the sink

The sink MUST be flagged. If it is suppressed, the lexical bug is back.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from actenon_scan.detectors.typescript import is_typescript_extra_available

pytestmark = pytest.mark.skipif(
    not is_typescript_extra_available(),
    reason="[typescript] extra not installed — tree-sitter-typescript required",
)


def test_lexical_suppression_regression() -> None:
    """Guard words in comments/imports/strings/variable names must NOT suppress."""
    fixture = Path(__file__).parent / "fixtures" / "typescript" / "lexical_suppression.ts"
    assert fixture.exists(), f"Fixture not found: {fixture}"

    from actenon_scan.detectors.typescript import analyze_typescript_file

    findings, errors = analyze_typescript_file(fixture)
    assert not errors, f"TS analysis errors: {errors}"

    # There MUST be at least one finding (the execSync sink).
    exec_findings = [f for f in findings if "EXEC" in f.rule_id]
    assert len(exec_findings) >= 1, (
        f"Expected at least 1 EXEC-SHELL finding (the execSync sink), got {len(findings)} findings: "
        f"{[(f.line, f.rule_id) for f in findings]}. "
        f"The lexical-suppression bug may have returned — guard words in comments, "
        f"imports, strings, or variable names are suppressing the sink."
    )


def test_comment_with_guard_word_does_not_suppress() -> None:
    """A comment line containing 'authorize' must not suppress sinks below it."""
    source = '''import { execSync } from "child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

// This file performs no authorize check at all
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    return { content: [{ type: "text", text: execSync(cmd, { encoding: 'utf-8' }) }] };
});
'''
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.ts"
        p.write_text(source)
        from actenon_scan.detectors.typescript import analyze_typescript_file
        findings, errors = analyze_typescript_file(p)
        assert not errors, f"TS analysis errors: {errors}"
        exec_findings = [f for f in findings if "EXEC" in f.rule_id]
        assert len(exec_findings) >= 1, (
            f"Comment containing 'authorize' suppressed the sink. "
            f"Findings: {[(f.line, f.rule_id) for f in findings]}"
        )


def test_string_literal_with_unauthorized_does_not_suppress() -> None:
    """A string literal containing 'unauthorized' must not suppress sinks below it."""
    source = '''import { execSync } from "child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const errorMsg = "Error: unauthorized access denied";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    return { content: [{ type: "text", text: execSync(cmd, { encoding: 'utf-8' }) }] };
});
'''
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.ts"
        p.write_text(source)
        from actenon_scan.detectors.typescript import analyze_typescript_file
        findings, errors = analyze_typescript_file(p)
        assert not errors, f"TS analysis errors: {errors}"
        exec_findings = [f for f in findings if "EXEC" in f.rule_id]
        assert len(exec_findings) >= 1, (
            f"String literal containing 'unauthorized' suppressed the sink. "
            f"Findings: {[(f.line, f.rule_id) for f in findings]}"
        )


def test_variable_name_with_guard_word_does_not_suppress() -> None:
    """A variable name like 'guardedHandler' must not suppress sinks below it."""
    source = '''import { execSync } from "child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const guardedHandler = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
guardedHandler.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    return { content: [{ type: "text", text: execSync(cmd, { encoding: 'utf-8' }) }] };
});
'''
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.ts"
        p.write_text(source)
        from actenon_scan.detectors.typescript import analyze_typescript_file
        findings, errors = analyze_typescript_file(p)
        assert not errors, f"TS analysis errors: {errors}"
        exec_findings = [f for f in findings if "EXEC" in f.rule_id]
        assert len(exec_findings) >= 1, (
            f"Variable name 'guardedHandler' suppressed the sink. "
            f"Findings: {[(f.line, f.rule_id) for f in findings]}"
        )
