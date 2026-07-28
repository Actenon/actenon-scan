"""Work Order 2.1, Item 1 — Test that capabilities are structurally possible.

A scan whose fixtures contain known guarded sinks must report
guard_found_count > 0 for that language. A count of zero when guarded
sinks are known to exist is structurally impossible — it means the
detector is suppressing guarded findings internally rather than
returning them to the engine.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path


def _go_fixture_with_guarded_sink() -> bytes:
    """A Go fixture with one guarded sink and one unguarded sink."""
    return b'''package tools

import (
    "context"
    "os"
    "os/exec"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func runCommand(ctx context.Context, req *mcp.CallToolRequest, args struct {
    Command string
}) (*mcp.CallToolResult, struct{}, error) {
    out, _ := exec.Command("bash", "-c", args.Command).Output()
    return mcp.NewToolResultText(string(out)), struct{}{}, nil
}

func safeDelete(ctx context.Context, req *mcp.CallToolRequest, args struct {
    Path string
}) (*mcp.CallToolResult, struct{}, error) {
    authorize(args.Path)
    os.Remove(args.Path)
    return mcp.NewToolResultText("ok"), struct{}{}, nil
}

func authorize(path string) {
    if path == "" {
        panic("unauthorized")
    }
}

func main() {
    server := mcp.NewServer("test", "1.0")
    mcp.AddTool(server, &mcp.Tool{Name: "run_command"}, runCommand)
    mcp.AddTool(server, &mcp.Tool{Name: "safe_delete"}, safeDelete)
}
'''


def _ts_fixture_with_guarded_sink() -> str:
    """A TS fixture with one guarded sink and one unguarded sink."""
    return '''import { execSync } from 'child_process';
import * as fs from 'fs';
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });

server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    return { content: [{ type: "text", text: execSync(cmd, { encoding: 'utf-8' }) }] };
});

server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const path = req.params.arguments.path as string;
    if (isAuthorized(path)) { fs.rmSync(path); }
    return { content: [{ type: "text", text: "ok" }] };
});

function isAuthorized(path: string): boolean { return path.startsWith('/tmp/'); }
'''


def _py_fixture_with_guarded_sink() -> str:
    """A Python fixture with one guarded sink and one unguarded sink."""
    return '''import subprocess, os
from mcp import tool

@tool
def unguarded(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()

@tool
def guarded(path: str) -> None:
    authorize(path)
    os.remove(path)

def authorize(path: str) -> None:
    if not path.startswith("/tmp/"):
        raise PermissionError(path)
'''


def test_go_guarded_sink_produces_guard_found_capability():
    """A Go fixture with a known guarded sink must report guard_found > 0."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.go"
        p.write_bytes(_go_fixture_with_guarded_sink())
        result = scan_path(Path(td))
        go_caps = [c for c in result.capabilities if c.language == "go"]
        gf = [c for c in go_caps if c.state == "GUARD_FOUND"]
        assert len(gf) > 0, (
            f"Go fixture has a guarded sink but guard_found_count is 0. "
            f"The detector may be suppressing guarded findings internally. "
            f"Caps: {[(c.line, c.state, c.guard_status) for c in go_caps]}"
        )


def test_ts_guarded_sink_produces_guard_found_capability():
    """A TS fixture with a known guarded sink must report guard_found > 0."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.ts"
        p.write_text(_ts_fixture_with_guarded_sink())
        config = {"guard_patterns": ["isAuthorized"]}
        (Path(td) / ".actenon-scan.json").write_text(json.dumps(config))
        result = scan_path(Path(td), config=Path(td) / ".actenon-scan.json")
        ts_caps = [c for c in result.capabilities if c.language == "typescript"]
        gf = [c for c in ts_caps if c.state == "GUARD_FOUND"]
        assert len(gf) > 0, (
            f"TS fixture has a guarded sink but guard_found_count is 0. "
            f"The detector may be suppressing guarded findings internally. "
            f"Caps: {[(c.line, c.state, c.guard_status) for c in ts_caps]}"
        )


def test_python_guarded_sink_produces_guard_found_capability():
    """A Python fixture with a known guarded sink must report guard_found > 0."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.py"
        p.write_text(_py_fixture_with_guarded_sink())
        config = {"guard_patterns": ["authorize"]}
        (Path(td) / ".actenon-scan.json").write_text(json.dumps(config))
        result = scan_path(Path(td), config=Path(td) / ".actenon-scan.json")
        py_caps = [c for c in result.capabilities if c.language == "python"]
        gf = [c for c in py_caps if c.state == "GUARD_FOUND"]
        assert len(gf) > 0, (
            f"Python fixture has a guarded sink but guard_found_count is 0. "
            f"Caps: {[(c.line, c.state, c.guard_status) for c in py_caps]}"
        )
