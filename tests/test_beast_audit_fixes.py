"""Comprehensive regression suite for the rigorous audit & engine/detector transformation."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from actenon_scan.baseline import is_in_baseline, load_baseline, write_baseline
from actenon_scan.brief import build_brief
from actenon_scan.cli import main as cli_main
from actenon_scan.detectors.go import is_go_extra_available
from actenon_scan.detectors.typescript import is_typescript_extra_available as is_typescript_available
from actenon_scan.engine import scan_path, scan_path_parallel
from actenon_scan.explain import format_explain
from actenon_scan.fix import generate_fix, generate_fix_all
from actenon_scan.report.pretty import format_pretty
from actenon_scan.suppress import collect_suppressions_from_target, is_suppressed


# ---------------------------------------------------------------------------
# Phase 1: Same-file caller guard bypass, baseline keying, suppressions, parallel parity
# ---------------------------------------------------------------------------


def test_same_file_helper_flagged_when_second_tool_calls_unguarded(tmp_path: Path) -> None:
    """G2: Guarding helper in tool_a must NOT suppress helper when tool_b calls it unguarded."""
    (tmp_path / "tools.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        class OpsToolkit:
            @tool()
            def safe_ops(self, cmd: str) -> None:
                authorize(cmd)
                self._exec(cmd)

            @tool()
            def unsafe_ops(self, cmd: str) -> None:
                self._exec(cmd)

            def _exec(self, cmd: str) -> None:
                subprocess.run(cmd, shell=True)
    """))
    res = scan_path(tmp_path)
    active = [f for f in res.findings if not f.suppressed]
    assert any(f.rule_id == "EXEC-SHELL" for f in active), (
        "Helper _exec is reachable unguarded from unsafe_ops and MUST be flagged."
    )


def test_same_file_helper_not_suppressed_by_authentication_only_caller(tmp_path: Path) -> None:
    """G2: authenticate(user) in caller checks identity, NOT action authorization."""
    (tmp_path / "tools.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        def authenticate(user: str) -> None:
            if not user:
                raise PermissionError("unauthenticated")

        @tool()
        def run_for_user(user: str, cmd: str) -> None:
            authenticate(user)
            _helper_exec(cmd)

        def _helper_exec(cmd: str) -> None:
            subprocess.run(cmd, shell=True)
    """))
    res = scan_path(tmp_path)
    active = [f for f in res.findings if not f.suppressed]
    assert any("EXEC-SHELL" in f.rule_id for f in active), (
        "Authentication in caller must never suppress a consequential sink in a helper."
    )


def test_same_file_helper_guarded_when_all_callers_authorize(tmp_path: Path) -> None:
    """G2 precision: When EVERY caller dominates the helper call with authorize(), 0 findings."""
    (tmp_path / "tools.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        class OpsToolkit:
            @tool()
            def ops_one(self, cmd: str) -> None:
                authorize(cmd)
                self._exec(cmd)

            @tool()
            def ops_two(self, cmd: str) -> None:
                authorize(cmd)
                self._exec(cmd)

            def _exec(self, cmd: str) -> None:
                subprocess.run(cmd, shell=True)
    """))
    res = scan_path(tmp_path)
    active = [f for f in res.findings if not f.suppressed]
    assert len(active) == 0
    assert any(c.state == "GUARD_FOUND" for c in res.capabilities)


def test_declarative_guarded_basetool_subclass(tmp_path: Path) -> None:
    """G3: @requires_permission on a BaseTool subclass marks its _run method guarded."""
    (tmp_path / "basetool_guarded.py").write_text(textwrap.dedent("""\
        import subprocess
        from langchain.tools import BaseTool

        @requires_permission("shell.exec")
        class AdminShellTool(BaseTool):
            name = "admin_shell"
            description = "Run admin command"

            def _run(self, cmd: str) -> str:
                return subprocess.check_output(cmd, shell=True).decode()
    """))
    res = scan_path(tmp_path)
    active = [f for f in res.findings if not f.suppressed]
    assert len(active) == 0
    assert any(c.state == "GUARD_FOUND" for c in res.capabilities)


def test_baseline_keyed_by_rule_id_and_snippet_hash(tmp_path: Path) -> None:
    """G5: Baseline entry for RULE_A must NOT suppress RULE_B at the same snippet hash."""
    bpath = tmp_path / "baseline.json"
    write_baseline(
        [{"file": "app.py", "rule_id": "NET-HTTP-POST", "snippet_hash": "deadbeef12345678"}],
        bpath,
    )
    loaded = load_baseline(bpath)

    assert is_in_baseline(loaded, "app.py", "NET-HTTP-POST", "deadbeef12345678")
    assert not is_in_baseline(loaded, "app.py", "EXEC-SHELL", "deadbeef12345678")


def test_cli_guard_flag_preserves_existing_config_excludes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """G6: Passing --guard must merge with .actenon-scan.json rather than dropping its excludes."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".actenon-scan.json").write_text(json.dumps({
        "exclude": ["ignored_dir/**"],
    }))
    ignored = tmp_path / "ignored_dir"
    ignored.mkdir()
    (ignored / "bad.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool()
        def bad(cmd: str) -> None:
            subprocess.run(cmd, shell=True)
    """))
    (tmp_path / "good.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool()
        def guarded(cmd: str) -> None:
            acme_custom_gate(cmd)
            subprocess.run(cmd, shell=True)
    """))
    rc = cli_main(["scan", ".", "--guard", "acme_custom_gate", "--fail-on", "low"])
    assert rc == 0


def test_parallel_scan_full_parity_with_serial(tmp_path: Path) -> None:
    """G1: scan_path_parallel matches scan_path across Python transitive, TS, Go, and suppressions."""
    (tmp_path / "entry.py").write_text(textwrap.dedent("""\
        from mcp import tool
        from helper import run_shell

        @tool()
        def entry(cmd: str) -> None:
            run_shell(cmd)
    """))
    (tmp_path / "helper.py").write_text(textwrap.dedent("""\
        import subprocess

        def run_shell(cmd: str) -> None:
            subprocess.run(cmd, shell=True)
    """))
    (tmp_path / "suppressed.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        @tool()
        def suppressed_tool(cmd: str) -> None:
            subprocess.run(cmd, shell=True)  # actenon-scan: ignore[EXEC-SHELL]
    """))
    if is_typescript_available():
        (tmp_path / "agent.ts").write_text(textwrap.dedent("""\
            import { execSync } from "node:child_process";
            server.tool("run", {}, async ({ cmd }) => {
              execSync(cmd);
            });
        """))

    suppressions = collect_suppressions_from_target(tmp_path)
    serial = scan_path(tmp_path, suppressions=suppressions)
    with patch("actenon_scan.engine.MIN_FILES_FOR_AUTO_PARALLEL", 1):
        parallel = scan_path_parallel(tmp_path, jobs=2, suppressions=suppressions)

    serial_active = sorted((f.file, f.line, f.rule_id, bool(f.snippet_hash), f.tier) for f in serial.findings if not f.suppressed)
    parallel_active = sorted((f.file, f.line, f.rule_id, bool(f.snippet_hash), f.tier) for f in parallel.findings if not f.suppressed)
    assert parallel_active == serial_active
    assert all(f.snippet_hash for f in parallel.findings)


# ---------------------------------------------------------------------------
# Phase 2: Python/TS/Go detector parity, cross-file entrypoints, r07 precision
# ---------------------------------------------------------------------------


def test_python_tool_from_function_cross_file_transitive_reachability(tmp_path: Path) -> None:
    """G4: Tool.from_function(fn) in entry.py discovers cross-file sink in worker.py."""
    (tmp_path / "entry.py").write_text(textwrap.dedent("""\
        from langchain.tools import Tool
        from worker import wipe_dir

        def clean_handler(path: str) -> None:
            wipe_dir(path)

        clean_tool = Tool.from_function(clean_handler, name="clean", description="clean")
    """))
    (tmp_path / "worker.py").write_text(textwrap.dedent("""\
        import os

        def wipe_dir(path: str) -> None:
            os.remove(path)
    """))
    res = scan_path(tmp_path)
    active = [f for f in res.findings if not f.suppressed]
    assert any(f.file == "worker.py" and f.rule_id == "DATA-DELETE-OS" for f in active)


def test_python_cross_file_wrong_action_guard_emits_unbound(tmp_path: Path) -> None:
    """G4: authorize_read(x) in cross-file callee cannot authorize a refund/delete sink."""
    cfg_file = tmp_path / ".actenon-scan.json"
    cfg_file.write_text(json.dumps({"guard_patterns": ["authorize_read"]}))
    (tmp_path / "entry.py").write_text(textwrap.dedent("""\
        from mcp import tool
        from billing import issue_refund

        @tool()
        def refund_customer(payment_id: str) -> None:
            issue_refund(payment_id)
    """))
    (tmp_path / "billing.py").write_text(textwrap.dedent("""\
        import stripe

        def authorize_read(payment_id: str) -> None:
            if not payment_id:
                raise PermissionError("denied")

        def issue_refund(payment_id: str) -> None:
            authorize_read(payment_id)
            stripe.Refund.create(payment_intent=payment_id)
    """))
    res = scan_path(tmp_path, config=cfg_file)
    active = [f for f in res.findings if not f.suppressed]
    assert any(f.file == "billing.py" and f.rule_id.endswith("-UNBOUND") for f in active)


def test_raw_tool_schema_else_fallback_not_flagged(tmp_path: Path) -> None:
    """G11: Plain else: fallback in a raw JSON-schema tool dispatcher is not selected by tool name."""
    (tmp_path / "dispatch.py").write_text(textwrap.dedent("""\
        import requests

        TOOLS = [
            {
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Read weather",
                    "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
                },
            }
        ]

        def dispatch(tool_name: str, args: dict) -> str:
            if tool_name == "get_weather":
                return "sunny"
            else:
                requests.post("https://internal.telemetry.local/unknown-tool", json={"name": tool_name})
                return "unknown tool"
    """))
    res = scan_path(tmp_path)
    active = [f for f in res.findings if not f.suppressed]
    assert len(active) == 0


@pytest.mark.skipif(not is_typescript_available(), reason="tree-sitter-typescript not installed")
def test_typescript_new_expression_sinks_and_cross_file_subdirs(tmp_path: Path) -> None:
    """G7/G8/G9/G13: TS new_expression AWS SDK v3 commands, subdirectory imports, named handlers, and // suppressions."""
    sub = tmp_path / "tools" / "sub"
    sub.mkdir(parents=True)
    (sub / "aws_ops.ts").write_text(textwrap.dedent("""\
        import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
        import { execSync } from "node:child_process";

        const client = new SecretsManagerClient({});

        export async function fetchSecret(secretId: string) {
          return await client.send(new GetSecretValueCommand({ SecretId: secretId }));
        }

        export function suppressedExec(cmd: string) {
          // actenon-scan: ignore[EXEC-SHELL]
          return execSync(cmd);
        }
    """))
    (tmp_path / "tools" / "index.ts").write_text(textwrap.dedent("""\
        import { createTool } from "@mastra/core/tools";
        import { fetchSecret, suppressedExec } from "./sub/aws_ops";

        async function handleSecret({ secretId }: { secretId: string }) {
          return await fetchSecret(secretId);
        }

        export const secretTool = createTool({
          id: "read-secret",
          execute: handleSecret,
        });

        export const supTool = createTool({
          id: "sup",
          execute: async ({ cmd }: { cmd: string }) => suppressedExec(cmd),
        });
    """))
    suppressions = collect_suppressions_from_target(tmp_path)
    assert is_suppressed(suppressions, "tools/sub/aws_ops.ts", "EXEC-SHELL", 12)

    res = scan_path(tmp_path, suppressions=suppressions)
    active = [f for f in res.findings if not f.suppressed]
    rule_ids = {f.rule_id for f in active}
    assert "SECRET-READ" in rule_ids
    assert "EXEC-SHELL" not in rule_ids
    assert res.transitive_followed_count == len([f for f in res.findings if "transitive:" in (f.reachability_reason or "")])


@pytest.mark.skipif(not is_go_extra_available(), reason="tree-sitter-go not installed")
def test_go_communication_send_and_named_handler_cross_file(tmp_path: Path) -> None:
    """G10: Go smtp.SendMail sink + named handler function reference across files in package."""
    (tmp_path / "server.go").write_text(textwrap.dedent("""\
        package agent

        import "github.com/mark3labs/mcp-go/server"

        func Register(s *server.MCPServer) {
            s.AddTool(emailTool, handleSendEmail)
        }
    """))
    (tmp_path / "handlers.go").write_text(textwrap.dedent("""\
        package agent

        import "net/smtp"

        func handleSendEmail(to string, body []byte) error {
            return smtp.SendMail("smtp.example.com:587", nil, "bot@example.com", []string{to}, body)
        }
    """))
    res = scan_path(tmp_path)
    active = [f for f in res.findings if not f.suppressed]
    assert any(f.file == "handlers.go" and f.rule_id == "COMMUNICATION-SEND-GO" for f in active)


# ---------------------------------------------------------------------------
# Phase 3: Cross-file explain/brief/fix, TypeScript brief, pretty guard evidence
# ---------------------------------------------------------------------------


def test_explain_and_fix_work_on_cross_file_transitive_finding(tmp_path: Path) -> None:
    """G14/G15: explain, brief, fix, and fix-all work on cross-file helper findings."""
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.1.0"\n')
    (tmp_path / "agent.py").write_text(textwrap.dedent("""\
        from mcp import tool
        from helpers import run_deploy

        @tool()
        def deploy_service(cmd: str) -> None:
            run_deploy(cmd)
    """))
    helper_file = tmp_path / "helpers.py"
    helper_file.write_text(textwrap.dedent("""\
        import subprocess

        def run_deploy(cmd: str) -> None:
            subprocess.run(cmd, shell=True)
    """))

    brief = build_brief(helper_file, 4)
    assert brief is not None
    assert brief.identity.rule_id == "EXEC-SHELL"
    assert "->" in brief.data_flow.handler_step or "→" in brief.data_flow.handler_step

    explanation = format_explain(brief)
    assert "-> agent.deploy_service()" in explanation
    assert "-> helpers.run_deploy()" in explanation

    fix_res = generate_fix(helper_file, 4, mode="guard")
    assert fix_res is not None
    assert "authorize(" in fix_res.diff
    assert "scaffold" in fix_res.note

    all_fixes = generate_fix_all(tmp_path, mode="guard", apply=False)
    assert len(all_fixes) == 1
    assert "authorize(" in all_fixes[0].diff


@pytest.mark.skipif(not is_typescript_available(), reason="tree-sitter-typescript not installed")
def test_typescript_brief_extracts_function_and_params(tmp_path: Path) -> None:
    """G14: build_brief & explain_finding support TypeScript files via tree-sitter."""
    ts_file = tmp_path / "mailer.ts"
    ts_file.write_text(textwrap.dedent("""\
        import nodemailer from "nodemailer";
        const transporter = nodemailer.createTransport({});

        server.tool("send_mail", {}, async function sendNotification({ recipient, subject }) {
          await transporter.sendMail({ to: recipient, subject });
        });
    """))
    brief = build_brief(ts_file, 5)
    assert brief is not None
    assert brief.identity.rule_id == "COMMUNICATION-SEND"
    assert brief.agent_entry_point.function_name == "sendNotification"
    param_names = {p.name for p in brief.caller_controlled_parameters}
    assert "recipient" in param_names
    assert "subject" in param_names


def test_pretty_spotlight_surfaces_weak_and_non_authorizing_guards(tmp_path: Path) -> None:
    """G16: format_pretty reports -WEAK and non-authorizing guards accurately."""
    (tmp_path / "weak_tool.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp import tool

        def is_allowed(cmd: str) -> bool:
            return cmd == "ls"

        @tool()
        def run_cmd(cmd: str) -> None:
            is_allowed(cmd)
            subprocess.run(cmd, shell=True)
    """))
    res = scan_path(tmp_path)
    out = format_pretty(res)
    assert "return value is discarded (-WEAK)" in out
