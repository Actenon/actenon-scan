"""Node fs calls made through an import binding, not through a name `fs`.

FILE-WRITE and DATA-DELETE-FILE are written as `fs.writeFileSync`,
`fs.promises.rm`, ... and used to match only code that calls through an
identifier literally named `fs`. The idiom most current Node code uses,

    import { writeFileSync } from "node:fs";
    writeFileSync(path, content);

matched no rule at all, even inside a recognised MCP tool handler. The
evidence that surfaced this: a hand-written MCP server whose `save_skill`
tool wrote model-supplied text with a named `writeFileSync` import; agents
called it 31 times and later sessions read the files back (see
research/rapsheet-behaviour/BREAKTHROUGH.md).

The fix resolves bindings from the import, never from the name. The negative
cases pin that: same function names from other modules, or defined locally,
stay unmatched.
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

HANDLER_HEAD = '''import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
'''


def _handler(imports: str, body: str) -> str:
    """A recognised SDK tool handler (r02 shape) with the given imports and body."""
    return (
        HANDLER_HEAD
        + imports
        + '''
const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a: any = req.params.arguments;
'''
        + body
        + '''
  return { content: [] };
});
'''
    )


def _scan_ts(source: str, name: str = "server.ts") -> list:
    from actenon_scan.detectors.typescript import analyze_typescript_file

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / name
        p.write_text(source)
        findings, errors = analyze_typescript_file(p)
        assert not errors, errors
        return findings


def _rules(findings) -> list[str]:
    return sorted(f.rule_id for f in findings)


# ---------------------------------------------------------------------------
# Positive: every import form Node publishes fs under
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "imports,body,rule",
    [
        ('import { writeFileSync } from "node:fs";', "writeFileSync(a.path, a.content);", "FILE-WRITE"),
        ('import { writeFileSync } from "fs";', "writeFileSync(a.path, a.content);", "FILE-WRITE"),
        ('import { appendFileSync as add } from "fs";', "add(a.path, a.content);", "FILE-WRITE"),
        ('import { writeFile as save } from "node:fs/promises";', "await save(a.path, a.content);", "FILE-WRITE"),
        ('import { rm } from "node:fs/promises";', "await rm(a.path, { recursive: true });", "DATA-DELETE-FILE"),
        ('import { rmSync, unlinkSync } from "node:fs";', "unlinkSync(a.path);", "DATA-DELETE-FILE"),
        ('import fsp from "node:fs/promises";', "await fsp.unlink(a.path);", "DATA-DELETE-FILE"),
        ('import * as nodefs from "fs";', "nodefs.rmSync(a.path);", "DATA-DELETE-FILE"),
        ('import { promises as p } from "fs";', "await p.writeFile(a.path, a.content);", "FILE-WRITE"),
        ('const { unlinkSync: u } = require("fs");', "u(a.path);", "DATA-DELETE-FILE"),
        ('const { writeFileSync } = require("node:fs");', "writeFileSync(a.path, a.content);", "FILE-WRITE"),
        ('const q = require("fs").promises;', "await q.appendFile(a.path, a.content);", "FILE-WRITE"),
        ('const nfs = require("node:fs");', "nfs.rmSync(a.path);", "DATA-DELETE-FILE"),
    ],
)
def test_fs_call_through_import_binding_matches(imports, body, rule):
    findings = _scan_ts(_handler(imports, body))
    assert _rules(findings) == [rule], [(f.line, f.rule_id, f.call_text) for f in findings]


def test_namespaced_form_is_unchanged():
    """`import * as fs` + `fs.writeFileSync` matched before and still matches once."""
    findings = _scan_ts(_handler('import * as fs from "fs";', "fs.writeFileSync(a.path, a.content);"))
    assert _rules(findings) == ["FILE-WRITE"]


def test_javascript_file_is_covered_too():
    source = _handler('import { rmSync } from "node:fs";', "rmSync(a.path, { recursive: true });")
    assert _rules(_scan_ts(source, name="server.mjs")) == ["DATA-DELETE-FILE"]


# ---------------------------------------------------------------------------
# Negative: the binding, not the name, decides
# ---------------------------------------------------------------------------

def test_same_name_from_another_module_is_not_fs():
    """memfs mirrors the fs API but writes to memory, not to disk."""
    findings = _scan_ts(_handler('import { writeFileSync } from "memfs";', "writeFileSync(a.path, a.content);"))
    assert findings == []


def test_same_name_from_a_local_module_is_not_fs():
    findings = _scan_ts(_handler('import { writeFileSync } from "./cache.ts";', "writeFileSync(a.path, a.content);"))
    assert findings == []


def test_locally_defined_function_with_an_fs_name_is_not_fs():
    source = _handler(
        "function writeFileSync(p: string, c: string) { return [p, c]; }",
        "writeFileSync(a.path, a.content);",
    )
    assert _scan_ts(source) == []


def test_reading_through_a_named_import_is_not_a_write():
    findings = _scan_ts(_handler('import { readFileSync, existsSync } from "node:fs";', "existsSync(a.path) && readFileSync(a.path);"))
    assert findings == []


def test_named_import_outside_any_agent_boundary_is_not_reachable():
    """Sink matching changed; reachability did not."""
    source = '''import { writeFileSync } from "node:fs";
export function writeReport(path: string, body: string) {
  writeFileSync(path, body);
}
'''
    assert _scan_ts(source) == []


def test_require_of_another_module_is_not_fs():
    findings = _scan_ts(_handler('const { writeFileSync } = require("./fs-shim");', "writeFileSync(a.path, a.content);"))
    assert findings == []


# ---------------------------------------------------------------------------
# The cross-file layer uses the same matching
# ---------------------------------------------------------------------------

def test_discover_all_ts_sinks_sees_named_imports():
    from actenon_scan.detectors.typescript import discover_all_ts_sinks

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "store.ts"
        p.write_text('import { writeFileSync } from "node:fs";\nexport function save(p: string, c: string) { writeFileSync(p, c); }\n')
        sinks = discover_all_ts_sinks(p)
    assert [(s["line"], s["rule_id"]) for s in sinks] == [(2, "FILE-WRITE")]


def test_helper_in_another_file_is_lifted_from_a_registered_handler():
    from actenon_scan.engine import scan_path

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "index.ts").write_text(
            'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
            'import { save } from "./store.ts";\n'
            'const server = new McpServer({ name: "x", version: "1" });\n'
            'server.registerTool("save", { inputSchema: {} }, async (args: any) => {\n'
            "  save(args.path, args.content);\n"
            "  return { content: [] };\n"
            "});\n"
        )
        (root / "store.ts").write_text(
            'import { writeFileSync } from "node:fs";\n'
            "export function save(p: string, c: string) {\n"
            "  writeFileSync(p, c);\n"
            "}\n"
        )
        result = scan_path(str(root))
    live = [f for f in result.findings if not f.suppressed]
    assert [(Path(f.file).name, f.line, f.rule_id) for f in live] == [("store.ts", 3, "FILE-WRITE")]
