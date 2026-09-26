"""Adversarial regression tests for cross-file resource reachability
in Go and TypeScript.

These tests pin the implementation of cross-language resource
reachability (Phase 2 of the cross-file reachability slice). The
pre-implementation predictions are frozen in this file: every test
asserts the POST-implementation expectation, and the suite is run
BEFORE implementation to produce red evidence (the tests fail today,
then pass after the implementation lands).

Scope
-----
The slice implements ONE capability:

    CROSS-FILE RESOURCE REACHABILITY FOR GO AND TYPESCRIPT

It does NOT implement:
  - argument taint across languages
  - validatePath / AuthorizeDML authority recognition
  - GitHub SDK sink modelling
  - additional sink rules

Honest reporting
----------------
Transitive findings emit ``reachability_reason`` describing the call
chain AND a clear disclosure that model-controlled argument provenance
is NOT established:

    Agent reachability: PROVEN
    Sink: PROVEN
    Model-controlled sink argument: NOT ESTABLISHED

The tests below pin BOTH the chain text AND the disclosure text.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path
from actenon_scan.detectors.go import is_go_extra_available
from actenon_scan.detectors.typescript import is_typescript_extra_available


def _write_repo(files: dict[str, str]) -> str:
    tmp = tempfile.mkdtemp()
    for rel, src in files.items():
        p = Path(tmp) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    return tmp


# ---------------------------------------------------------------------------
# Pre-implementation skip markers — these tests are expected to FAIL
# before implementation; running them before implementation produces the
# red evidence required by the brief.
# ---------------------------------------------------------------------------

_TS = is_typescript_extra_available()
_GO = is_go_extra_available()


# ---------------------------------------------------------------------------
# TEST A — TypeScript cross-file function reachability
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _TS, reason="[typescript] extra not installed")
class TestATypeScriptCrossFileFunction(unittest.TestCase):
    """entry.ts registers a model-callable handler that delegates to
    helper.ts. helper.ts contains an already-recognised filesystem sink
    (fs.writeFile). The handler itself contains no sink.

    Pre-implementation: 0 transitive findings.
    Post-implementation: 1 transitive capability with the chain
    handler → writeFileContent visible in the reachability_reason.
    """

    def test_write_file_in_helper_becomes_visible(self) -> None:
        root = _write_repo({
            "entry.ts": (
                "import { writeFileContent } from './lib.js';\n"
                "import { validatePath } from './validate.js';\n"
                "\n"
                "export const server = {\n"
                "  registerTool(name: string, schema: unknown, handler: (args: any) => Promise<unknown>): void {\n"
                "    void name; void schema; void handler;\n"
                "  },\n"
                "};\n"
                "\n"
                "server.registerTool(\n"
                "  'write_record',\n"
                "  { inputSchema: { path: 'string', content: 'string' } },\n"
                "  async (args: { path: string; content: string }) => {\n"
                "    const validPath = await validatePath(args.path);\n"
                "    await writeFileContent(validPath, args.content);\n"
                "    return { content: [{ type: 'text' as const, text: 'ok' }] };\n"
                "  }\n"
                ");\n"
            ),
            "lib.ts": (
                "import * as fs from 'node:fs';\n"
                "\n"
                "export async function writeFileContent(filePath: string, content: string): Promise<void> {\n"
                "  await fs.writeFile(filePath, content, 'utf-8');\n"
                "}\n"
            ),
            "validate.ts": (
                "export async function validatePath(path: string): Promise<string> {\n"
                "  return path;\n"
                "}\n"
            ),
        })

        result = scan_path(root, cache=None)

        # The transitive finding for fs.writeFile in lib.ts MUST appear.
        transitive = [
            f for f in result.findings
            if f.rule_id.startswith("FILE-WRITE") and "lib.ts" in f.file
        ]
        self.assertTrue(
            transitive,
            f"Cross-file TS reachability missed — fs.writeFile in lib.ts was not "
            f"reported as a transitive finding. Findings: {result.findings}",
        )
        # The chain MUST include both the handler name and the helper name.
        chain_text = transitive[0].reachability_reason or ""
        self.assertIn(
            "writeFileContent",
            chain_text,
            f"Transitive finding's reachability_reason does not mention the helper. "
            f"Got: {chain_text!r}",
        )
        # The disclosure text MUST say the model-controlled argument is
        # NOT established (we did not implement taint propagation).
        # The disclosure may appear in the description or the
        # reachability_reason — both are acceptable.
        full_text = (transitive[0].description or "") + " " + chain_text
        self.assertTrue(
            "NOT ESTABLISHED" in full_text,
            f"Transitive finding did not disclose that model-controlled argument "
            f"provenance is NOT ESTABLISHED. Full text: {full_text!r}",
        )

        # Repository analysis MUST be reported as enabled for the TS-only target.
        self.assertTrue(
            result.repository_analysis_enabled,
            "Repository analysis was not enabled for a TS-only target — the "
            "language gate at engine.py:1320 still suppresses the repo layer "
            "for non-Python targets.",
        )


# ---------------------------------------------------------------------------
# TEST B — Go cross-file method reachability
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _GO, reason="[go] extra not installed")
class TestBGoCrossFileMethod(unittest.TestCase):
    """entry.go registers a model-callable closure via mcp.AddTool that
    delegates to manager.Perform in helper.go. helper.go contains an
    already-recognised SQL sink (tx.Exec on receiver tx). entry.go
    imports the agent SDK; helper.go does NOT.

    Pre-implementation: 0 transitive findings.
    Post-implementation: 1 transitive capability with the chain
    handler closure → Manager.Perform visible.
    """

    def test_tx_exec_in_helper_becomes_visible(self) -> None:
        root = _write_repo({
            "entry.go": (
                "package server\n"
                "\n"
                "import (\n"
                "\t\"context\"\n"
                "\n"
                "\t\"github.com/modelcontextprotocol/go-sdk/mcp\"\n"
                ")\n"
                "\n"
                "func RegisterExecThing(server *mcp.Server) {\n"
                "\tmcp.AddTool(server, &mcp.Tool{\n"
                "\t\tName:        'exec_thing',\n"
                "\t\tDescription: 'Execute a thing statement',\n"
                "\t}, func(ctx context.Context, _ *mcp.CallToolRequest, in ThingInput) (*mcp.CallToolResult, ThingOutput, error) {\n"
                "\t\tout, err := manager.ExecThing(ctx, in.Database, in.SQL)\n"
                "\t\treturn nil, out, err\n"
                "\t})\n"
                "}\n"
                "\n"
                "type ThingInput struct {\n"
                "\tDatabase string `json:\"database\"`\n"
                "\tSQL      string `json:\"sql\"`\n"
                "}\n"
                "\n"
                "type ThingOutput struct {\n"
                "\tRowsAffected int64 `json:\"rows_affected\"`\n"
                "}\n"
            ),
            "helper.go": (
                "package server\n"
                "\n"
                "import (\n"
                "\t\"context\"\n"
                "\t\"time\"\n"
                ")\n"
                "\n"
                "type Manager struct{}\n"
                "\n"
                "func (m *Manager) ExecThing(ctx context.Context, database, sql string, timeout time.Duration) (ThingOutput, error) {\n"
                "\tpool, err := acquirePool(ctx, database)\n"
                "\tif err != nil {\n"
                "\t\treturn ThingOutput{}, err\n"
                "\t}\n"
                "\tconn, err := pool.Acquire(ctx)\n"
                "\tif err != nil {\n"
                "\t\treturn ThingOutput{}, err\n"
                "\t}\n"
                "\tdefer conn.Release()\n"
                "\ttx, err := conn.BeginTx(ctx)\n"
                "\tif err != nil {\n"
                "\t\treturn ThingOutput{}, err\n"
                "\t}\n"
                "\tcommandTag, execErr := tx.Exec(ctx, sql)\n"
                "\tif execErr != nil {\n"
                "\t\t_ = tx.Rollback(ctx)\n"
                "\t\treturn ThingOutput{}, execErr\n"
                "\t}\n"
                "\tif err := tx.Commit(ctx); err != nil {\n"
                "\t\t_ = tx.Rollback(ctx)\n"
                "\t\treturn ThingOutput{}, err\n"
                "\t}\n"
                "\treturn ThingOutput{RowsAffected: commandTag.RowsAffected()}, nil\n"
                "}\n"
                "\n"
                "type pool struct{}\n"
                "type conn struct{ tx *tx }\n"
                "type tx struct{}\n"
                "type commandTag struct{}\n"
                "\n"
                "func (c *conn) BeginTx(ctx context.Context) (*tx, error)        { return &tx{}, nil }\n"
                "func (t *tx) Exec(ctx context.Context, sql string, args ...any) (commandTag, error) { return commandTag{}, nil }\n"
                "func (t *tx) Commit(ctx context.Context) error                    { return nil }\n"
                "func (t *tx) Rollback(ctx context.Context) error                   { return nil }\n"
                "func (c commandTag) RowsAffected() int64                          { return 0 }\n"
                "func (c *conn) Release()                                          {}\n"
                "func acquirePool(ctx context.Context, database string) (*conn, error) { return &conn{}, nil }\n"
            ),
        })

        result = scan_path(root, cache=None)

        # The transitive finding for tx.Exec in helper.go MUST appear.
        transitive = [
            f for f in result.findings
            if "DATA-DELETE-SQL-GO" in f.rule_id and "helper.go" in f.file
        ]
        self.assertTrue(
            transitive,
            f"Cross-file Go reachability missed — tx.Exec in helper.go was not "
            f"reported as a transitive finding. Findings: {result.findings}",
        )
        chain_text = transitive[0].reachability_reason or ""
        self.assertIn(
            "ExecThing",
            chain_text,
            f"Transitive finding's reachability_reason does not mention Manager.ExecThing. "
            f"Got: {chain_text!r}",
        )
        full_text = (transitive[0].description or "") + " " + chain_text
        self.assertTrue(
            "NOT ESTABLISHED" in full_text,
            f"Transitive finding did not disclose that model-controlled argument "
            f"provenance is NOT ESTABLISHED. Full text: {full_text!r}",
        )
        self.assertTrue(
            result.repository_analysis_enabled,
            "Repository analysis was not enabled for a Go-only target.",
        )


# ---------------------------------------------------------------------------
# TEST C — Negative control (unreachable sink-bearing helper)
# ---------------------------------------------------------------------------

class TestCNegativeControlUnreachableHelper(unittest.TestCase):
    """A sink-bearing helper exists in another file but is NOT reachable
    from any registered model handler. The sink MUST NOT be reported
    as a transitive finding.

    Pre-implementation: 0 findings (per-file scan skips the helper
    because it doesn't import the agent SDK).
    Post-implementation: 0 findings (the repo layer must NOT promote
    an unreachable helper to reachable just because it shares a name
    with something in the index).
    """

    @pytest.mark.skipif(not _TS, reason="[typescript] extra not installed")
    def test_ts_unreachable_helper_still_zero(self) -> None:
        root = _write_repo({
            "entry.ts": (
                "export const server = {\n"
                "  registerTool(name: string, schema: unknown, handler: (args: any) => Promise<unknown>): void {\n"
                "    void name; void schema; void handler;\n"
                "  },\n"
                "};\n"
                "\n"
                "server.registerTool(\n"
                "  'noop_tool',\n"
                "  { inputSchema: { x: 'string' } },\n"
                "  async (args: { x: string }) => {\n"
                "    return { content: [{ type: 'text' as const, text: 'ok' }] };\n"
                "  }\n"
                ");\n"
            ),
            "unused.ts": (
                "import * as fs from 'node:fs';\n"
                "\n"
                "// This helper is never called from the registered handler.\n"
                "// It MUST NOT be flagged as agent-reachable.\n"
                "export async function unusedHelper(filePath: string): Promise<void> {\n"
                "  await fs.writeFile(filePath, 'x', 'utf-8');\n"
                "}\n"
            ),
        })

        result = scan_path(root, cache=None)
        findings_in_unused = [
            f for f in result.findings if "unused.ts" in f.file
        ]
        self.assertEqual(
            findings_in_unused,
            [],
            f"Negative control failed — the unreachable sink in unused.ts was "
            f"reported as a finding. The repo layer must NOT promote an "
            f"unreachable helper. Findings: {findings_in_unused}",
        )

    @pytest.mark.skipif(not _GO, reason="[go] extra not installed")
    def test_go_unreachable_helper_still_zero(self) -> None:
        root = _write_repo({
            "entry.go": (
                "package server\n"
                "\n"
                "import (\n"
                "\t\"context\"\n"
                "\n"
                "\t\"github.com/modelcontextprotocol/go-sdk/mcp\"\n"
                ")\n"
                "\n"
                "func RegisterNoop(server *mcp.Server) {\n"
                "\tmcp.AddTool(server, &mcp.Tool{\n"
                "\t\tName: 'noop',\n"
                "\t}, func(ctx context.Context, _ *mcp.CallToolRequest, in NoopInput) (*mcp.CallToolResult, NoopOutput, error) {\n"
                "\t\treturn &mcp.CallToolResult{}, NoopOutput{}, nil\n"
                "\t})\n"
                "}\n"
                "\n"
                "type NoopInput struct{ X string }\n"
                "type NoopOutput struct{}\n"
            ),
            "unused.go": (
                "package server\n"
                "\n"
                "import (\n"
                "\t\"context\"\n"
                ")\n"
                "\n"
                "type UnusedManager struct{}\n"
                "\n"
                "// Never called from the registered handler.\n"
                "func (m *UnusedManager) Unused(ctx context.Context, database, sql string) (int64, error) {\n"
                "\tvar tx *TxStub\n"
                "\tcommandTag, _ := tx.Exec(ctx, sql)\n"
                "\treturn commandTag.RowsAffected(), nil\n"
                "}\n"
                "\n"
                "type TxStub struct{}\n"
                "type CommandTag struct{ n int64 }\n"
                "func (t *TxStub) Exec(ctx context.Context, sql string, args ...any) (CommandTag, error) { return CommandTag{}, nil }\n"
                "func (c CommandTag) RowsAffected() int64 { return c.n }\n"
            ),
        })

        result = scan_path(root, cache=None)
        findings_in_unused = [
            f for f in result.findings if "unused.go" in f.file
        ]
        self.assertEqual(
            findings_in_unused,
            [],
            f"Negative control failed — the unreachable sink in unused.go was "
            f"reported as a finding. Findings: {findings_in_unused}",
        )


# ---------------------------------------------------------------------------
# TEST D — Multi-hop (handler → helperA → helperB → sink)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _TS, reason="[typescript] extra not installed")
class TestDMultiHop(unittest.TestCase):
    """A registered handler calls helperA; helperA calls helperB;
    helperB contains the sink. The transitive finding MUST show BOTH
    hops in the chain.
    """

    def test_two_hop_chain_visible_in_reason(self) -> None:
        root = _write_repo({
            "entry.ts": (
                "import { helperA } from './a.js';\n"
                "\n"
                "export const server = {\n"
                "  registerTool(name: string, schema: unknown, handler: (args: any) => Promise<unknown>): void {\n"
                "    void name; void schema; void handler;\n"
                "  },\n"
                "};\n"
                "\n"
                "server.registerTool(\n"
                "  'multi_hop',\n"
                "  { inputSchema: { x: 'string' } },\n"
                "  async (args: { x: string }) => {\n"
                "    await helperA(args.x);\n"
                "    return { content: [{ type: 'text' as const, text: 'ok' }] };\n"
                "  }\n"
                ");\n"
            ),
            "a.ts": (
                "import { helperB } from './b.js';\n"
                "\n"
                "export async function helperA(value: string): Promise<void> {\n"
                "  await helperB(value);\n"
                "}\n"
            ),
            "b.ts": (
                "import * as fs from 'node:fs';\n"
                "\n"
                "export async function helperB(filePath: string): Promise<void> {\n"
                "  await fs.writeFile(filePath, 'data', 'utf-8');\n"
                "}\n"
            ),
        })

        result = scan_path(root, cache=None)
        transitive = [
            f for f in result.findings
            if f.rule_id.startswith("FILE-WRITE") and "b.ts" in f.file
        ]
        self.assertTrue(
            transitive,
            f"Two-hop chain missed — fs.writeFile in b.ts was not reported. "
            f"Findings: {result.findings}",
        )
        chain_text = transitive[0].reachability_reason or ""
        self.assertIn("helperA", chain_text, f"Chain missing helperA: {chain_text!r}")
        self.assertIn("helperB", chain_text, f"Chain missing helperB: {chain_text!r}")


# ---------------------------------------------------------------------------
# TEST E — Existing direct finding remains unchanged
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _TS, reason="[typescript] extra not installed")
class TestEExistingDirectFindingUnchanged(unittest.TestCase):
    """A registered handler contains a recognised sink DIRECTLY in its
    body. The per-file scan already reports it. The repo layer MUST
    NOT introduce a duplicate transitive finding for the same sink.

    Pre-implementation: 1 direct finding.
    Post-implementation: still exactly 1 finding (no duplicate).
    """

    def test_direct_finding_not_duplicated(self) -> None:
        root = _write_repo({
            "entry.ts": (
                "import * as fs from 'node:fs';\n"
                "\n"
                "export const server = {\n"
                "  registerTool(name: string, schema: unknown, handler: (args: any) => Promise<unknown>): void {\n"
                "    void name; void schema; void handler;\n"
                "  },\n"
                "};\n"
                "\n"
                "server.registerTool(\n"
                "  'direct_sink',\n"
                "  { inputSchema: { path: 'string' } },\n"
                "  async (args: { path: string }) => {\n"
                "    await fs.writeFile(args.path, 'x', 'utf-8');\n"
                "    return { content: [{ type: 'text' as const, text: 'ok' }] };\n"
                "  }\n"
                ");\n"
            ),
        })

        result = scan_path(root, cache=None)
        write_findings = [
            f for f in result.findings
            if f.rule_id.startswith("FILE-WRITE") and "entry.ts" in f.file
        ]
        self.assertEqual(
            len(write_findings),
            1,
            f"Direct finding was duplicated or suppressed. Expected exactly 1 "
            f"FILE-WRITE finding in entry.ts; got {len(write_findings)}: "
            f"{write_findings}",
        )
