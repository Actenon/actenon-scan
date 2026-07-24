"""Tests for unsupported-file reporting (Part 1 safety fix).

A scanner that stays silent about files it cannot parse is dangerous —
a user reads "No findings" as clean when nothing was examined.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path
from actenon_scan.report.json_out import format_json
from actenon_scan.report.pretty import format_pretty


@pytest.fixture
def ts_only_dir(tmp_path):
    """A directory containing only .ts files."""
    (tmp_path / "server.ts").write_text(
        'import Stripe from "stripe";\n'
        'const stripe = new Stripe(process.env.KEY!);\n'
        'server.setRequestHandler(CallToolRequestSchema, async (req) => {\n'
        '  await stripe.refunds.create({ payment_intent: req.params.arguments.pi });\n'
        '});\n'
    )
    (tmp_path / "utils.ts").write_text('export function foo() { return 1; }\n')
    return tmp_path


@pytest.fixture
def mixed_dir(tmp_path):
    """A directory with both .py and .ts files."""
    (tmp_path / "agent.py").write_text(
        'from mcp.server.fastmcp import FastMCP\n'
        'mcp = FastMCP("x")\n'
        '@mcp.tool()\n'
        'def refund(pi: str):\n'
        '    import stripe; stripe.Refund.create(payment_intent=pi)\n'
    )
    (tmp_path / "server.ts").write_text(
        'import Stripe from "stripe";\n'
        'const stripe = new Stripe(process.env.KEY!);\n'
    )
    return tmp_path


class TestUnsupportedFileReporting:
    """Scanning a directory of only-.ts files with the extra absent
    produces a non-zero unsupported count and the install hint in stdout."""

    def test_ts_only_dir_reports_unsupported(self, ts_only_dir):
        result = scan_path(ts_only_dir)
        assert len(result.unsupported_files) >= 2
        langs = {lang for _, lang in result.unsupported_files}
        assert any("TypeScript" in l for l in langs)

    def test_ts_only_dir_pretty_output_has_install_hint(self, ts_only_dir):
        result = scan_path(ts_only_dir)
        output = format_pretty(result)
        assert "NOT scanned" in output
        assert "typescript" in output
        assert 'pip install' in output

    def test_ts_only_dir_json_has_unsupported_key(self, ts_only_dir):
        result = scan_path(ts_only_dir)
        data = json.loads(format_json(result))
        assert data["unsupported"]["count"] >= 2
        assert "TypeScript" in data["unsupported"]["by_language"]
        assert len(data["unsupported"]["files"]) >= 2

    def test_mixed_dir_reports_both_scanned_and_unsupported(self, mixed_dir):
        result = scan_path(mixed_dir)
        assert result.files_scanned >= 1  # the .py file
        assert len(result.unsupported_files) >= 1  # the .ts file

    def test_pretty_output_when_findings_plus_unsupported(self, mixed_dir):
        """When findings exist AND unsupported files exist, both are reported."""
        result = scan_path(mixed_dir)
        output = format_pretty(result)
        # The Python file should produce a finding
        if result.findings:
            assert "finding" in output.lower()
        # The .ts file should still be reported as unsupported
        assert "unsupported" in output.lower() or "NOT scanned" in output

    def test_no_unsupported_for_py_only_dir(self, tmp_path):
        """A .py-only directory has zero unsupported files."""
        (tmp_path / "agent.py").write_text("x = 1\n")
        result = scan_path(tmp_path)
        assert len(result.unsupported_files) == 0

    def test_exit_code_zero_for_unsupported_only(self, ts_only_dir, capsys):
        """Unsupported files alone must NOT fail the build (default)."""
        from actenon_scan.cli import main
        rc = main(["scan", str(ts_only_dir)])
        assert rc == 0

    def test_exit_code_nonzero_with_fail_on_unsupported(self, ts_only_dir, capsys):
        """--fail-on-unsupported opts into failing the build."""
        from actenon_scan.cli import main
        rc = main(["scan", str(ts_only_dir), "--fail-on-unsupported"])
        assert rc == 1

    def test_errored_files_tracked_separately(self, tmp_path):
        """A .py file that fails to parse is tracked as errored, not unsupported."""
        (tmp_path / "bad.py").write_text("def broken(:\n")
        result = scan_path(tmp_path)
        assert len(result.analysis_errors) >= 1
        assert len(result.unsupported_files) == 0
