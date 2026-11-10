"""Raw tool-schema dispatch (r07) in TypeScript/JavaScript.

The Python detector has recognised this boundary since r07 shipped: a sink in
a branch selected by a tool name the module declares in a tool-schema
literal. The TypeScript detector had no equivalent, so a hand-written MCP
server — JSON-RPC over stdio, no SDK import, `tools/call` dispatched on the
tool name — reported nothing, while a line-for-line Python transliteration
of the same server was flagged.

The positive reproducer below has the architecture of a real server of that
shape, written independently of its source.
Coding agents called its `save_skill` tool 31 times; every later
`read_skill` returned the bytes an earlier, different session had saved.
See research/rapsheet-behaviour/BREAKTHROUGH.md. It is a development example,
not independent validation: the holdout evaluation is reported separately.

The negative cases are the near-misses that must NOT become reachable.
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


def _scan_ts(source: str, name: str = "server.ts") -> list:
    from actenon_scan.detectors.typescript import analyze_typescript_file

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / name
        p.write_text(source)
        findings, errors = analyze_typescript_file(p)
        assert not errors, errors
        return findings


def _hits(findings) -> list[tuple[int, str]]:
    return sorted((f.line, f.rule_id) for f in findings if f.guard_status != "guarded")


def _line_of(source: str, needle: str) -> int:
    for n, text in enumerate(source.splitlines(), 1):
        if needle in text:
            return n
    raise AssertionError(needle)


# Same architecture as the evidence, written independently of it: a schema
# list built with push(), a dispatcher on the tool name, and a JSON-RPC loop at
# module level. The trace logger and the directory creation are not tool
# effects and must stay unflagged.
REPRODUCER = '''import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";

const STORE = process.env.SKILL_STORE;
const ALLOWED = process.env.ALLOWED_ORIGIN;
const TRACE = process.env.TRACE_FILE;
const schema = (props: Record<string, unknown>) => ({ type: "object", properties: props });
const tools: any[] = [];
if (STORE) {
  tools.push({ name: "read_skill", description: "Return a stored skill.", inputSchema: schema({ name: { type: "string" } }) });
  tools.push({ name: "save_skill", description: "Store a skill for later sessions.", inputSchema: schema({ name: { type: "string" }, content: { type: "string" } }) });
}
if (ALLOWED) tools.push({ name: "http_get", description: "Fetch a URL on the allowed origin.", inputSchema: schema({ url: { type: "string" } }) });

const trace = (entry: unknown) => TRACE && appendFileSync(TRACE, JSON.stringify(entry) + "\\n");
const fileFor = (name: string) => `${STORE}/${String(name).replace(/[^a-z0-9_-]/gi, "-")}.md`;

async function handleCall(tool: string, args: any): Promise<string> {
  if (tool === "read_skill" && STORE) {
    const file = fileFor(args.name);
    return existsSync(file) ? readFileSync(file, "utf8") : "missing";
  }
  if (tool === "save_skill" && STORE) {
    mkdirSync(STORE, { recursive: true });
    writeFileSync(fileFor(args.name), String(args.content ?? ""));
    trace({ tool });
    return "ok";
  }
  if (tool === "http_get" && ALLOWED) {
    const target = new URL(String(args.url));
    if (target.origin !== ALLOWED) return "refused";
    const response = await fetch(target);
    return response.text();
  }
  return "unknown tool";
}

for await (const raw of createInterface({ input: process.stdin })) {
  const req = JSON.parse(raw);
  if (req.method === "tools/list") process.stdout.write(JSON.stringify({ id: req.id, result: { tools } }) + "\\n");
  else if (req.method === "tools/call") {
    const text = await handleCall(req.params?.name, req.params?.arguments ?? {});
    process.stdout.write(JSON.stringify({ id: req.id, result: { content: [{ type: "text", text }] } }) + "\\n");
  }
}
'''


class TestReproducer:
    def test_the_two_tool_effects_are_found_and_nothing_else(self):
        findings = _scan_ts(REPRODUCER)
        assert _hits(findings) == [
            (_line_of(REPRODUCER, "writeFileSync(fileFor"), "FILE-WRITE"),
            (_line_of(REPRODUCER, "await fetch(target"), "NET-EGRESS"),
        ], [(f.line, f.rule_id, f.call_text) for f in findings]

    def test_same_server_as_javascript(self):
        source = REPRODUCER
        for typed, plain in [
            ("(props: Record<string, unknown>)", "(props)"),
            ("const tools: any[]", "const tools"),
            ("(entry: unknown)", "(entry)"),
            ("(name: string)", "(name)"),
            ("(tool: string, args: any): Promise<string>", "(tool, args)"),
        ]:
            assert typed in source, typed
            source = source.replace(typed, plain)
        assert [r for _, r in _hits(_scan_ts(source, name="server.mjs"))] == ["FILE-WRITE", "NET-EGRESS"]


# ---------------------------------------------------------------------------
# Positive: other ways the same boundary is written
# ---------------------------------------------------------------------------

def test_switch_on_tool_name():
    source = '''import { rmSync } from "node:fs";
const TOOLS = [{ name: "delete_file", description: "Delete a file", input_schema: { type: "object" } }];
export function dispatch(name: string, args: any) {
  switch (name) {
    case "delete_file":
      rmSync(args.path, { recursive: true });
      return "ok";
    default:
      return "unknown";
  }
}
'''
    assert _hits(_scan_ts(source)) == [(6, "DATA-DELETE-FILE")]


def test_switch_fallthrough_from_an_empty_case():
    source = '''import * as fs from "fs";
const TOOLS = [{ name: "rm", inputSchema: {} }, { name: "delete_file", inputSchema: {} }];
export function dispatch(name: string, args: any) {
  switch (name) {
    case "rm":
    case "delete_file": {
      fs.rmSync(args.path);
      break;
    }
  }
}
'''
    assert _hits(_scan_ts(source)) == [(7, "DATA-DELETE-FILE")]


def test_openai_nested_function_schema():
    source = '''import { execSync } from "child_process";
const tools = [{ type: "function", function: { name: "run_shell", parameters: { type: "object", properties: { cmd: { type: "string" } } } } }];
export async function onToolCall(call: any) {
  if (call.function.name === "run_shell") {
    return execSync(JSON.parse(call.function.arguments).cmd).toString();
  }
}
'''
    assert _hits(_scan_ts(source)) == [(5, "EXEC-SHELL")]


def test_quoted_keys_reversed_comparison_and_disjunction():
    source = '''import * as fs from "fs";
const TOOLS = [{ "name": "write_note", "inputSchema": { "type": "object" } }];
export function handle(tool: string, a: any, force: boolean) {
  if ("write_note" === tool || force) {
    fs.writeFileSync(a.path, a.text);
  }
}
'''
    assert _hits(_scan_ts(source)) == [(5, "FILE-WRITE")]


def test_guard_analysis_still_applies_to_the_new_boundary():
    """A dominating guard in the selected branch is recorded as guarded, not flagged."""
    source = '''import * as fs from "fs";
const TOOLS = [{ name: "save", inputSchema: {} }];
function authorize(action: string) { if (!action) throw new Error("denied"); }
export function call(name: string, a: any) {
  if (name === "save") {
    authorize("save");
    fs.writeFileSync(a.path, a.content);
  }
}
'''
    findings = _scan_ts(source)
    assert [(f.line, f.guard_status) for f in findings] == [(7, "guarded")]


# ---------------------------------------------------------------------------
# Negative: both halves are required, and the branch must be the one the name selects
# ---------------------------------------------------------------------------

def test_dispatch_without_a_schema_is_not_a_boundary():
    source = '''import * as fs from "fs";
export function route(name: string, a: any) {
  if (name === "save") fs.writeFileSync(a.path, a.content);
}
'''
    assert _scan_ts(source) == []


def test_branch_name_not_declared_in_the_schema():
    source = '''import * as fs from "fs";
const TOOLS = [{ name: "read_file", inputSchema: {} }];
export function call(name: string, a: any) {
  if (name === "write_file") fs.writeFileSync(a.path, a.content);
}
'''
    assert _scan_ts(source) == []


def test_sink_in_the_else_branch_is_selected_by_every_other_name():
    source = '''import * as fs from "fs";
const TOOLS = [{ name: "read_file", inputSchema: {} }];
export function call(name: string, a: any) {
  if (name === "read_file") {
    return fs.readFileSync(a.path, "utf8");
  } else {
    fs.writeFileSync(a.path, a.content);
  }
}
'''
    assert _scan_ts(source) == []


def test_one_line_if_else_uses_the_sink_position_not_its_line():
    source = '''import * as fs from "fs";
const TOOLS = [{ name: "read_file", inputSchema: {} }];
export function call(name: string, a: any) {
  if (name === "read_file") fs.readFileSync(a.path); else fs.writeFileSync(a.path, a.content);
}
'''
    assert _scan_ts(source) == []


@pytest.mark.parametrize("cond", ['name !== "save"', '!(name === "save")', 'isSave(name === "save")'])
def test_negated_or_indirect_conditions_do_not_select(cond):
    source = f'''import * as fs from "fs";
const TOOLS = [{{ name: "save", inputSchema: {{}} }}];
export function call(name: string, a: any) {{
  if ({cond}) fs.writeFileSync(a.path, a.content);
}}
'''
    assert _scan_ts(source) == []


def test_parameter_list_is_not_a_tool_schema():
    """`parameters: [...]` is an OpenAPI / stored-procedure parameter list, not JSON Schema."""
    source = '''import { rmSync } from "node:fs";
const PROCEDURES = [{ name: "sp_cleanup", parameters: [{ name: "days", type: "int" }] }];
export function runProcedure(proc: string, dir: string) {
  if (proc === "sp_cleanup") rmSync(dir, { recursive: true });
}
'''
    assert _scan_ts(source) == []


def test_object_with_a_name_but_no_schema_is_not_a_tool():
    source = '''import * as fs from "fs";
const MENU = [{ name: "export", label: "Export", description: "Export the report" }];
export function onMenu(item: string, path: string, body: string) {
  if (item === "export") fs.writeFileSync(path, body);
}
'''
    assert _scan_ts(source) == []


def test_sink_after_the_branch_is_not_selected():
    source = '''import * as fs from "fs";
const TOOLS = [{ name: "save", inputSchema: {} }];
export function call(name: string, a: any) {
  if (name === "save") { a.ok = true; }
  fs.writeFileSync(a.path, a.content);
}
'''
    assert _scan_ts(source) == []


def test_sink_in_a_helper_outside_the_dispatcher_is_not_lifted_here():
    """Per-file signal only: the helper is not the selected branch."""
    source = '''import * as fs from "fs";
const TOOLS = [{ name: "save", inputSchema: {} }];
function persist(a: any) { fs.writeFileSync(a.path, a.content); }
export function call(name: string, a: any) {
  if (name === "save") persist(a);
}
'''
    assert _scan_ts(source) == []


def test_module_level_dispatch_is_unchanged():
    """Module-level sinks keep the strict file-level rule (setRequestHandler/registerTool only)."""
    source = '''import * as fs from "fs";
const TOOLS = [{ name: "save", inputSchema: {} }];
const msg = JSON.parse(process.argv[2]);
if (msg.params.name === "save") fs.writeFileSync(msg.params.arguments.path, "x");
'''
    assert _scan_ts(source) == []


def test_case_value_not_declared():
    source = '''import * as fs from "fs";
const TOOLS = [{ name: "save", inputSchema: {} }];
export function call(name: string, a: any) {
  switch (name) {
    case "purge": fs.rmSync(a.path); break;
  }
}
'''
    assert _scan_ts(source) == []


# ---------------------------------------------------------------------------
# Parity: the Python detector already flags the transliterated server
# ---------------------------------------------------------------------------

PY_TRANSLITERATION = '''import os, urllib.request

STORE = os.environ.get("SKILL_STORE")
ALLOWED = os.environ.get("ALLOWED_ORIGIN")
tools = [
    {"name": "save_skill", "description": "Store a skill for later sessions.", "inputSchema": {"type": "object"}},
    {"name": "http_get", "description": "Fetch a URL on the allowed origin.", "inputSchema": {"type": "object"}},
]

def handle_call(tool, args):
    if tool == "save_skill" and STORE:
        with open(f"{STORE}/{args['name']}.md", "w") as fh:
            fh.write(str(args.get("content", "")))
        return "ok"
    if tool == "http_get" and ALLOWED:
        if not args["url"].startswith(ALLOWED):
            return "refused"
        return urllib.request.urlopen(args["url"]).read().decode()
    return "unknown tool"
'''


def test_python_and_typescript_agree_on_the_same_server():
    from actenon_scan.engine import scan_path

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "server.ts").write_text(REPRODUCER)
        (root / "server.py").write_text(PY_TRANSLITERATION)
        result = scan_path(str(root))
    live = [f for f in result.findings if not f.suppressed]
    by_lang = {
        suffix: sorted(f.category for f in live if f.file.endswith(suffix))
        for suffix in (".py", ".ts")
    }
    assert by_lang[".py"] == by_lang[".ts"] == ["file_mutation", "network_egress"], by_lang
