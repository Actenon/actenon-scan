"""Work Order 1.8 — Regression tests for exec/spawn bare_only + global receivers.

Tests that the EXEC-SHELL rule:
  - DOES match `child_process.exec(cmd)`, `child_process.spawn(cmd, args)`
  - DOES match `cp.exec(cmd)` (common alias import)
  - DOES match bare `exec(cmd)` when imported from "child_process"
  - DOES match `execSync(cmd)`, `spawnSync(cmd)` (separate patterns, unaffected)
  - DOES NOT match `SAFE.exec(name)` (RegExp.prototype.exec)
  - DOES NOT match `pool.spawn(n)` (unrelated method)
  - DOES NOT match `regex.exec(str)`

Tests that NET-EGRESS:
  - DOES match `window.fetch(url)`, `globalThis.fetch(url)`, `self.fetch(url)`
  - DOES NOT match `handler.fetch(request)`, `guarded.fetch(req)`
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


# ---------------------------------------------------------------------------
# Item 1: exec/spawn bare_only with import resolution
# ---------------------------------------------------------------------------

def test_child_process_exec_flags():
    """child_process.exec(cmd) must flag as EXEC-SHELL."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import * as child_process from "child_process";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    const out = child_process.exec(cmd);
    return { content: [{ type: "text", text: "ok" }] };
});
'''
    findings = _scan_ts(source)
    exec_findings = [f for f in findings if "EXEC-SHELL" in f.rule_id]
    assert len(exec_findings) >= 1, (
        f"child_process.exec must flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in findings]}"
    )


def test_child_process_spawn_flags():
    """child_process.spawn(cmd, args) must flag as EXEC-SHELL."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import * as child_process from "child_process";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    const child = child_process.spawn(cmd, []);
    return { content: [{ type: "text", text: "ok" }] };
});
'''
    findings = _scan_ts(source)
    exec_findings = [f for f in findings if "EXEC-SHELL" in f.rule_id]
    assert len(exec_findings) >= 1, (
        f"child_process.spawn must flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in findings]}"
    )


def test_cp_alias_exec_flags():
    """cp.exec(cmd) (common alias import) must flag as EXEC-SHELL."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import * as cp from "child_process";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    const out = cp.exec(cmd);
    return { content: [{ type: "text", text: "ok" }] };
});
'''
    findings = _scan_ts(source)
    exec_findings = [f for f in findings if "EXEC-SHELL" in f.rule_id]
    assert len(exec_findings) >= 1, (
        f"cp.exec (alias import) must flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in findings]}"
    )


def test_bare_exec_imported_from_child_process_flags():
    """Bare `exec(cmd)` where exec is imported from child_process must flag."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { exec } from "child_process";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    const out = exec(cmd);
    return { content: [{ type: "text", text: "ok" }] };
});
'''
    findings = _scan_ts(source)
    exec_findings = [f for f in findings if "EXEC-SHELL" in f.rule_id]
    assert len(exec_findings) >= 1, (
        f"Bare exec() imported from child_process must flag. "
        f"Findings: {[(f.line, f.rule_id, f.call_text) for f in findings]}"
    )


def test_bare_spawn_imported_from_child_process_flags():
    """Bare `spawn(cmd)` where spawn is imported from child_process must flag."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { spawn } from "child_process";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    const child = spawn(cmd, []);
    return { content: [{ type: "text", text: "ok" }] };
});
'''
    findings = _scan_ts(source)
    exec_findings = [f for f in findings if "EXEC-SHELL" in f.rule_id]
    assert len(exec_findings) >= 1, (
        f"Bare spawn() imported from child_process must flag. "
        f"Findings: {[(f.line, f.rule_id, f.call_text) for f in findings]}"
    )


def test_execSync_still_flags():
    """execSync(cmd) must still flag (separate pattern, not bare_only)."""
    source = '''import { execSync } from "child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    return { content: [{ type: "text", text: execSync(cmd, { encoding: 'utf-8' }) }] };
});
'''
    findings = _scan_ts(source)
    exec_findings = [f for f in findings if "EXEC-SHELL" in f.rule_id]
    assert len(exec_findings) >= 1, (
        f"execSync must still flag. Findings: {[(f.line, f.rule_id) for f in findings]}"
    )


def test_regex_exec_does_not_flag():
    """SAFE.exec(name) (RegExp.prototype.exec) must NOT flag as EXEC-SHELL."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const SAFE = /^[a-z0-9_-]+$/;
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.arguments.name as string;
    const m = SAFE.exec(name);
    if (!m) return { content: [], isError: true };
    return { content: [{ type: "text", text: "ok" }] };
});
'''
    findings = _scan_ts(source)
    exec_findings = [f for f in findings if "EXEC-SHELL" in f.rule_id]
    assert len(exec_findings) == 0, (
        f"SAFE.exec (RegExp) must NOT flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in exec_findings]}"
    )


def test_inline_regex_exec_does_not_flag():
    """/re/.exec(str) must NOT flag as EXEC-SHELL."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.arguments.name as string;
    const m = /^[a-z]+$/.exec(name);
    if (!m) return { content: [], isError: true };
    return { content: [{ type: "text", text: "ok" }] };
});
'''
    findings = _scan_ts(source)
    exec_findings = [f for f in findings if "EXEC-SHELL" in f.rule_id]
    assert len(exec_findings) == 0, (
        f"/re/.exec must NOT flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in exec_findings]}"
    )


def test_pool_spawn_does_not_flag():
    """pool.spawn(n) (unrelated method named spawn) must NOT flag as EXEC-SHELL."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
class Pool { spawn(n: string) { return n; } }
const pool = new Pool();
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const n = req.params.arguments.n as string;
    const r = pool.spawn(n);
    return { content: [{ type: "text", text: "ok" }] };
});
'''
    findings = _scan_ts(source)
    exec_findings = [f for f in findings if "EXEC-SHELL" in f.rule_id]
    assert len(exec_findings) == 0, (
        f"pool.spawn must NOT flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in exec_findings]}"
    )


def test_arbitrary_member_exec_does_not_flag():
    """myThing.exec(x) must NOT flag as EXEC-SHELL."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const myThing = { exec: (x: string) => x.toUpperCase() };
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const x = req.params.arguments.x as string;
    const r = myThing.exec(x);
    return { content: [{ type: "text", text: r }] };
});
'''
    findings = _scan_ts(source)
    exec_findings = [f for f in findings if "EXEC-SHELL" in f.rule_id]
    assert len(exec_findings) == 0, (
        f"myThing.exec must NOT flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in exec_findings]}"
    )


def test_require_child_process_exec_flags():
    """const cp = require("child_process"); cp.exec(cmd) must flag."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const cp = require("child_process");
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    const out = cp.exec(cmd);
    return { content: [{ type: "text", text: "ok" }] };
});
'''
    findings = _scan_ts(source)
    exec_findings = [f for f in findings if "EXEC-SHELL" in f.rule_id]
    assert len(exec_findings) >= 1, (
        f"require('child_process').exec must flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in findings]}"
    )


# ---------------------------------------------------------------------------
# Item 2: global-receiver allowlist for fetch
# ---------------------------------------------------------------------------

def test_window_fetch_flags():
    """window.fetch(url) must flag as NET-EGRESS (global receiver)."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const url = req.params.arguments.url as string;
    const resp = await window.fetch(url);
    return { content: [{ type: "text", text: await resp.text() }] };
});
'''
    findings = _scan_ts(source)
    net_findings = [f for f in findings if "NET-EGRESS" in f.rule_id]
    assert len(net_findings) >= 1, (
        f"window.fetch must flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in findings]}"
    )


def test_globalThis_fetch_flags():
    """globalThis.fetch(url) must flag as NET-EGRESS (global receiver)."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const url = req.params.arguments.url as string;
    const resp = await globalThis.fetch(url);
    return { content: [{ type: "text", text: await resp.text() }] };
});
'''
    findings = _scan_ts(source)
    net_findings = [f for f in findings if "NET-EGRESS" in f.rule_id]
    assert len(net_findings) >= 1, (
        f"globalThis.fetch must flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in findings]}"
    )


def test_self_fetch_flags():
    """self.fetch(url) must flag as NET-EGRESS (global receiver, web worker)."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const url = req.params.arguments.url as string;
    const resp = await self.fetch(url);
    return { content: [{ type: "text", text: await resp.text() }] };
});
'''
    findings = _scan_ts(source)
    net_findings = [f for f in findings if "NET-EGRESS" in f.rule_id]
    assert len(net_findings) >= 1, (
        f"self.fetch must flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in findings]}"
    )


def test_handler_fetch_still_does_not_flag():
    """handler.fetch(request) must still NOT flag (regression check after Item 2)."""
    source = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
const handler = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
handler.setRequestHandler(async () => { return { content: [] }; });
const response = await handler.fetch(new Request("http://127.0.0.1/mcp"));
'''
    findings = _scan_ts(source)
    net_findings = [f for f in findings if "NET-EGRESS" in f.rule_id]
    assert len(net_findings) == 0, (
        f"handler.fetch must NOT flag. Findings: {[(f.line, f.rule_id, f.call_text) for f in net_findings]}"
    )
