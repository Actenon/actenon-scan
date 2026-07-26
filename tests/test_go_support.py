"""Tests for Go language support.

Tests that:
- Go files are scanned when the [go] extra is installed
- exec.Command in an MCP tool handler produces a finding
- exec.Command in a non-agent function does NOT produce a finding
- Go test files (_test.go) are skipped by default
- The blast-radius summary shows Go findings
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_BIN = str(ROOT / "actenon_scan" / "__main__.py")


class GoSupportTests(unittest.TestCase):

    def setUp(self) -> None:
        from actenon_scan.detectors.go import is_go_extra_available
        if not is_go_extra_available():
            self.skipTest("[go] extra is not installed")
        self.tmpdir = tempfile.mkdtemp()

    def _scan(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, SCAN_BIN, "scan", *args, "--fail-on", "none", "--format", "json"],
            capture_output=True, text=True, cwd=self.tmpdir,
        )

    def test_go_file_with_exec_in_mcp_tool_produces_finding(self) -> None:
        """exec.Command in an MCP tool handler should produce a finding."""
        go_file = Path(self.tmpdir) / "tool.go"
        go_file.write_text("""package main

import (
    "context"
    "os/exec"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func runCommand(ctx context.Context, req *mcp.CallToolRequest, args struct{ Command string }) (*mcp.CallToolResult, struct{}, error) {
    out, err := exec.Command("bash", "-c", args.Command).Output()
    if err != nil {
        return mcp.NewToolResultError(err.Error()), struct{}{}, nil
    }
    return mcp.NewToolResultText(string(out)), struct{}{}, nil
}

func main() {
    server := mcp.NewServer("test", "1.0")
    mcp.AddTool(server, &mcp.Tool{Name: "run_command"}, runCommand)
}
""")
        result = self._scan(str(go_file))
        import json
        d = json.loads(result.stdout)
        findings = [f for f in d.get("findings", []) if not f.get("suppressed")]
        self.assertGreater(len(findings), 0, "Expected at least 1 finding from exec.Command in MCP tool")
        self.assertEqual(findings[0]["rule_id"], "EXEC-SHELL-GO")

    def test_go_file_without_mcp_import_no_finding(self) -> None:
        """exec.Command in a non-agent function should NOT produce a finding."""
        go_file = Path(self.tmpdir) / "main.go"
        go_file.write_text("""package main

import (
    "os/exec"
)

func buildBinary() error {
    cmd := exec.Command("go", "build", "-o", "binary")
    return cmd.Run()
}
""")
        result = self._scan(str(go_file))
        import json
        d = json.loads(result.stdout)
        findings = [f for f in d.get("findings", []) if not f.get("suppressed")]
        self.assertEqual(len(findings), 0, "Non-agent Go function should not produce findings")

    def test_go_test_files_are_skipped(self) -> None:
        """Go test files (_test.go) should be skipped by default."""
        test_file = Path(self.tmpdir) / "main_test.go"
        test_file.write_text("""package main

import (
    "os/exec"
    "testing"
)

func TestExec(t *testing.T) {
    out, err := exec.Command("echo", "hello").Output()
    if err != nil {
        t.Fatal(err)
    }
    _ = out
}
""")
        result = self._scan(str(self.tmpdir))
        import json
        d = json.loads(result.stdout)
        findings = [f for f in d.get("findings", []) if not f.get("suppressed")]
        self.assertEqual(len(findings), 0, "Test files should be skipped")

    def test_go_file_with_os_remove_in_mcp_tool_produces_finding(self) -> None:
        """os.Remove in an MCP tool handler should produce a finding."""
        go_file = Path(self.tmpdir) / "delete.go"
        go_file.write_text("""package main

import (
    "context"
    "os"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func deleteFile(ctx context.Context, req *mcp.CallToolRequest, args struct{ Path string }) (*mcp.CallToolResult, struct{}, error) {
    err := os.Remove(args.Path)
    if err != nil {
        return mcp.NewToolResultError(err.Error()), struct{}{}, nil
    }
    return mcp.NewToolResultText("deleted"), struct{}{}, nil
}

func main() {
    server := mcp.NewServer("test", "1.0")
    mcp.AddTool(server, &mcp.Tool{Name: "delete_file"}, deleteFile)
}
""")
        result = self._scan(str(go_file))
        import json
        d = json.loads(result.stdout)
        findings = [f for f in d.get("findings", []) if not f.get("suppressed")]
        self.assertGreater(len(findings), 0, "Expected at least 1 finding from os.Remove in MCP tool")
        self.assertEqual(findings[0]["rule_id"], "DATA-DELETE-OS-GO")

    def test_go_file_with_http_post_in_mcp_tool_produces_finding(self) -> None:
        """http.NewRequest in an MCP tool handler should produce a finding."""
        go_file = Path(self.tmpdir) / "http.go"
        go_file.write_text("""package main

import (
    "context"
    "net/http"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func sendRequest(ctx context.Context, req *mcp.CallToolRequest, args struct{ URL string }) (*mcp.CallToolResult, struct{}, error) {
    httpReq, err := http.NewRequest("POST", args.URL, nil)
    if err != nil {
        return mcp.NewToolResultError(err.Error()), struct{}{}, nil
    }
    client := &http.Client{}
    resp, err := client.Do(httpReq)
    _ = resp
    return mcp.NewToolResultText("sent"), struct{}{}, nil
}

func main() {
    server := mcp.NewServer("test", "1.0")
    mcp.AddTool(server, &mcp.Tool{Name: "send_request"}, sendRequest)
}
""")
        result = self._scan(str(go_file))
        import json
        d = json.loads(result.stdout)
        findings = [f for f in d.get("findings", []) if not f.get("suppressed")]
        self.assertGreater(len(findings), 0, "Expected at least 1 finding from http.NewRequest in MCP tool")


if __name__ == "__main__":
    unittest.main()
