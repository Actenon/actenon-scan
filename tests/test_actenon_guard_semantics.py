"""Actenon's own guard idioms must be read by what they enforce.

Cross-repo E2E finding F20:
  (a) the kernel's ``@protected_mcp_tool`` decorator verifies the proof
      before the tool body runs, but was not recognised — the kernel's
      own hero MCP example was flagged HIGH;
  (b) merely constructing an Actenon client (``Actenon.local()``,
      ``Broker(...)``, ``ProtectedExecutor(...)``) counted as a dominating
      guard — a decoy client that is never consulted produced 0 findings;
  (c) a side effect inside a handler closure that only a ProtectedExecutor
      (or ``ActenonGate.protect``) invokes was flagged.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from actenon_scan.engine import scan_path

HEADER = """\
import os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
"""


def _findings(tmp_path: Path, body: str) -> list:
    (tmp_path / "agent.py").write_text(HEADER + textwrap.dedent(body))
    result = scan_path(tmp_path)
    return [f for f in result.findings if not f.suppressed and "remove" in f.call_text]


def test_kernel_protected_mcp_tool_decorator_is_a_guard(tmp_path: Path) -> None:
    assert _findings(tmp_path, """
        from actenon.adapters.mcp import protected_mcp_tool
        gate = None

        @mcp.tool()
        @protected_mcp_tool(gate, audience="svc", action_builder=lambda a: a)
        def delete_path(path: str) -> str:
            os.remove(path)
            return "ok"
    """) == []


def test_constructing_an_actenon_client_is_not_a_guard(tmp_path: Path) -> None:
    found = _findings(tmp_path, """
        from actenon_permit import Actenon

        @mcp.tool()
        def delete_path(path: str) -> str:
            client = Actenon.local(agent_id="a")   # never consulted
            os.remove(path)
            return "ok"
    """)
    assert [f.rule_id for f in found] == ["DATA-DELETE-OS"], found


def test_constructing_a_protected_executor_is_not_a_guard(tmp_path: Path) -> None:
    found = _findings(tmp_path, """
        from actenon import ProtectedExecutor, PCCBVerifier

        @mcp.tool()
        def delete_path(path: str) -> str:
            executor = ProtectedExecutor(proof_verifier=PCCBVerifier(None))
            os.remove(path)
            return "ok"
    """)
    assert [f.rule_id for f in found] == ["DATA-DELETE-OS"], found


def test_handler_closure_run_by_protected_executor_is_guarded(tmp_path: Path) -> None:
    assert _findings(tmp_path, """
        from actenon import ProtectedExecutor
        executor = ProtectedExecutor()

        @mcp.tool()
        def delete_path(path: str, request: dict) -> dict:
            def handler(req, cred):
                os.remove(path)
                return {}
            return executor.execute(request, handler)
    """) == []


def test_handler_closure_via_factory_with_return_annotation(tmp_path: Path) -> None:
    assert _findings(tmp_path, """
        from actenon import ProtectedExecutor

        def build_executor() -> ProtectedExecutor:
            return ProtectedExecutor()

        @mcp.tool()
        def delete_path(path: str, request: dict) -> dict:
            protected = build_executor()

            def handler(req, cred):
                os.remove(path)
                return {}

            return protected.execute(request, handler)
    """) == []


def test_side_effect_lambda_run_by_actenon_gate_protect_is_guarded(tmp_path: Path) -> None:
    assert _findings(tmp_path, """
        from actenon import ActenonGate
        gate = ActenonGate.local_dev(audience="svc")

        @mcp.tool()
        def delete_path(path: str, proof: dict) -> dict:
            return gate.protect({"name": "fs.delete"}, proof, lambda: os.remove(path))
    """) == []


def test_handler_also_called_directly_is_not_guarded(tmp_path: Path) -> None:
    found = _findings(tmp_path, """
        from actenon import ProtectedExecutor
        executor = ProtectedExecutor()

        @mcp.tool()
        def delete_path(path: str, request: dict) -> dict:
            def handler(req, cred):
                os.remove(path)
                return {}
            handler(request, None)              # bypasses the executor
            return executor.execute(request, handler)
    """)
    assert len(found) == 1, found


def test_handler_passed_to_an_unknown_execute_is_not_guarded(tmp_path: Path) -> None:
    # No evidence the receiver is an Actenon executor: `execute` is also
    # cursor.execute, pool.execute, ... Silence must not imply safety.
    found = _findings(tmp_path, """
        @mcp.tool()
        def delete_path(path: str, request: dict, runner) -> dict:
            def handler(req, cred):
                os.remove(path)
                return {}
            return runner.execute(request, handler)
    """)
    assert len(found) == 1, found


def test_verification_after_the_side_effect_is_still_flagged(tmp_path: Path) -> None:
    found = _findings(tmp_path, """
        from actenon.proof import PCCBVerifier
        verifier = PCCBVerifier(signer=None)

        @mcp.tool()
        def delete_path(path: str, intent: dict, pccb: dict, ctx: dict) -> str:
            os.remove(path)
            verifier.verify(intent, pccb, ctx)
            return "ok"
    """)
    assert len(found) == 1, found


def test_inline_verification_before_the_side_effect_is_a_guard(tmp_path: Path) -> None:
    assert _findings(tmp_path, """
        from actenon.proof import PCCBVerifier
        verifier = PCCBVerifier(signer=None)

        @mcp.tool()
        def delete_path(path: str, intent: dict, pccb: dict, ctx: dict) -> str:
            verifier.verify(intent, pccb, ctx)
            os.remove(path)
            return "ok"
    """) == []
