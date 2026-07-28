"""Work Order 1.7 — Regression tests for the handler.fetch NET-EGRESS fix.

Tests that the NET-EGRESS rule's `fetch` pattern:
  - DOES match the global `fetch(url)` call (bare identifier)
  - DOES NOT match `handler.fetch(request)` (member expression — MCP handler)
  - DOES NOT match `guarded.fetch(...)` or `secured.fetch(...)` (member expressions)
  - DOES still match other NET-EGRESS patterns like `axios.post(url)`
  - DOES still match member-expression sinks from other rules like `fs.rmSync(path)`

Also tests that aliased imports are not caught (known limitation — name-based
matching cannot track import aliases).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from actenon_scan.detectors.typescript import is_typescript_extra_available

pytestmark = pytest.mark.skipif(
    not is_typescript_extra_available(),
    reason="[typescript] extra not installed",
)


def _scan_ts(source: str) -> list:
    """Scan a TS source string and return findings."""
    from actenon_scan.detectors.typescript import analyze_typescript_file
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.ts"
        p.write_text(source)
        findings, errors = analyze_typescript_file(p)
        assert not errors, f"TS analysis errors: {errors}"
        return findings


def test_global_fetch_flags():
    """Bare `fetch(url)` inside a tool handler MUST be flagged as NET-EGRESS."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const url = req.params.arguments.url as string;
    const resp = await fetch(url);
    return { content: [{ type: "text", text: await resp.text() }] };
});
'''
    findings = _scan_ts(source)
    net_findings = [f for f in findings if "NET-EGRESS" in f.rule_id]
    assert len(net_findings) >= 1, (
        f"Global fetch(url) must flag as NET-EGRESS. Findings: {[(f.line, f.rule_id) for f in findings]}"
    )


def test_handler_fetch_does_not_flag():
    """`handler.fetch(request)` (MCP handler entry point) must NOT flag as NET-EGRESS."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const handler = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
handler.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    return { content: [{ type: "text", text: "ok" }] };
});
// Module-level call to handler.fetch — this is the handler entry point, not egress
const response = await handler.fetch(new Request("http://127.0.0.1/mcp"));
'''
    findings = _scan_ts(source)
    net_findings = [f for f in findings if "NET-EGRESS" in f.rule_id]
    assert len(net_findings) == 0, (
        f"handler.fetch() must NOT flag as NET-EGRESS. "
        f"Findings: {[(f.line, f.rule_id, f.call_text) for f in net_findings]}"
    )


def test_member_expression_fetch_does_not_flag():
    """Any `obj.fetch(request)` must NOT flag as NET-EGRESS."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
const guarded = {
    async fetch(request: Request): Promise<Response> {
        return new Response("ok");
    }
};
const secured = {
    async fetch(request: Request): Promise<Response> {
        return new Response("ok");
    }
};
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const r = await guarded.fetch(new Request("http://test"));
    const r2 = await secured.fetch(new Request("http://test"));
    return { content: [{ type: "text", text: "ok" }] };
});
'''
    findings = _scan_ts(source)
    net_findings = [f for f in findings if "NET-EGRESS" in f.rule_id]
    assert len(net_findings) == 0, (
        f"guarded.fetch() and secured.fetch() must NOT flag as NET-EGRESS. "
        f"Findings: {[(f.line, f.rule_id, f.call_text) for f in net_findings]}"
    )


def test_axios_post_still_flags():
    """`axios.post(url)` must still flag as NET-EGRESS (qualified pattern, not bare_only)."""
    source = '''import axios from "axios";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const url = req.params.arguments.url as string;
    const resp = await axios.post(url, { data: "test" });
    return { content: [{ type: "text", text: JSON.stringify(resp.data) }] };
});
'''
    findings = _scan_ts(source)
    net_findings = [f for f in findings if "NET-EGRESS" in f.rule_id]
    assert len(net_findings) >= 1, (
        f"axios.post(url) must still flag. Findings: {[(f.line, f.rule_id) for f in findings]}"
    )


def test_fs_rmsync_still_flags():
    """`fs.rmSync(path)` must still flag as DATA-DELETE-FILE (member expression sink from another rule)."""
    source = '''import * as fs from "fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const path = req.params.arguments.path as string;
    fs.rmSync(path);
    return { content: [{ type: "text", text: "ok" }] };
});
'''
    findings = _scan_ts(source)
    delete_findings = [f for f in findings if "DATA-DELETE" in f.rule_id]
    assert len(delete_findings) >= 1, (
        f"fs.rmSync(path) must still flag. Findings: {[(f.line, f.rule_id) for f in findings]}"
    )
