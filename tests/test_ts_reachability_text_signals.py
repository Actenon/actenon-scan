"""The `tool(` and `execute:` text signals must mean a registration, not a word.

Two of the TypeScript reachability signals are substrings. Matching named
`fs` imports (test_ts_fs_named_imports.py) made sinks visible in code that
those substrings had wrongly marked agent-reachable all along:

  - `tool(` matched MCP *client* calls (`client.tool("name", args)`), so a
    benchmark harness driving a tool server was read as a tool handler. It
    also matched `registry.tool(id)`, a lookup, which made a demo's constant
    `execSync(...)` a HIGH finding in the baseline.
  - `execute:` matched any object key named execute, e.g. an authority
    config `{ read: programs, execute: programs }`, which made the
    logging arrow on the next line an "inline tool handler".

Each signal now requires the syntax of an actual registration: the bare
`tool(...)` factory, and an `execute:` that introduces a function. Real
handler shapes keep being found; the positive cases below pin that.
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
    from actenon_scan.detectors.typescript import analyze_typescript_file

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "mod.ts"
        p.write_text(source)
        findings, errors = analyze_typescript_file(p)
        assert not errors, errors
        return [(f.line, f.rule_id) for f in findings]


# ---------------------------------------------------------------------------
# Negative: words that are not registrations
# ---------------------------------------------------------------------------

def test_mcp_client_tool_call_does_not_make_the_caller_a_handler():
    source = '''import * as fs from "fs";
export async function runBenchmark(client: any, out: string) {
  const learned = await client.tool("summarise", { sources: ["a", "b"] });
  fs.writeFileSync(out, JSON.stringify(learned));
}
'''
    assert _scan_ts(source) == []


def test_lookup_method_named_tool_is_not_a_registration():
    source = '''import { execSync } from "node:child_process";
export async function demo(registry: any) {
  const collector = registry.tool("collector");
  const snapshot = execSync("uptime", { encoding: "utf8" });
  return [collector, snapshot];
}
'''
    assert _scan_ts(source) == []


def test_config_key_named_execute_is_not_an_inline_handler():
    source = '''import * as fs from "fs";
const policy = {
  permissions: { read: ["/usr/bin/gzip"], execute: ["/usr/bin/gzip"] },
};
const log = (row: unknown) => fs.appendFileSync("trace.jsonl", JSON.stringify(row) + "\\n");
'''
    assert _scan_ts(source) == []


def test_execute_bound_to_a_value_inside_a_function_is_not_a_handler():
    source = '''import * as fs from "fs";
export function configure(out: string, programs: string[]) {
  const authority = { execute: programs, publish: "verified" };
  fs.writeFileSync(out, JSON.stringify(authority));
}
'''
    assert _scan_ts(source) == []


# ---------------------------------------------------------------------------
# Positive: the registrations these signals exist for
# ---------------------------------------------------------------------------

def test_langchain_tool_factory_handler():
    source = '''import { tool } from "@langchain/core/tools";
import * as fs from "fs";
export const deleteFile = tool(async ({ path }: any) => {
  fs.rmSync(path);
  return "deleted";
}, { name: "delete_file", description: "Delete a file" });
'''
    assert _scan_ts(source) == [(4, "DATA-DELETE-FILE")]


@pytest.mark.parametrize(
    "handler",
    [
        "execute: async ({ path }: any) => {",
        "execute: ({ path }: any) => {",
        "execute: async function ({ path }: any) {",
        "execute: (args: any) => { const path = args.path;",
    ],
)
def test_vercel_execute_handler_forms(handler):
    source = f'''import {{ tool }} from "ai";
import * as fs from "fs";
export const tools = {{
  remove: tool({{
    description: "Delete a file",
    {handler}
      fs.rmSync(path);
      return "ok";
    }},
  }}),
}};
'''
    assert _scan_ts(source) == [(7, "DATA-DELETE-FILE")]


def test_execute_value_on_the_next_line():
    source = '''import * as fs from "fs";
export const tools = {
  remove: {
    description: "Delete a file",
    execute:
      async ({ path }: any) => {
        fs.rmSync(path);
      },
  },
};
'''
    assert _scan_ts(source) == [(7, "DATA-DELETE-FILE")]


def test_member_registration_on_a_server_variable_is_unchanged():
    """`mcp.tool(name, schema, handler)` on an McpServer: the inline-handler check is not narrowed."""
    source = '''import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fs from "fs";
const mcp = new McpServer({ name: "x", version: "1" });
mcp.tool("remove", {}, async (args: any) => {
  fs.rmSync(args.path);
  return { content: [] };
});
'''
    assert _scan_ts(source) == [(5, "DATA-DELETE-FILE")]
