"""Tests for expanded guard vocabulary and config UX."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path
from actenon_scan.rules.loader import load_rules, ConfigError


def _scan_source(source: str) -> list:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(source)
        f.flush()
        result = scan_path(f.name)
    Path(f.name).unlink()
    return [f for f in result.findings if not f.suppressed]


class TestExpandedGuardVocabulary:
    """Guard vocabulary must cover common naming conventions beyond the
    original ~12 hardcoded names.

    The finding: teams using assert_can, policy_gate, audit_and_allow,
    can_user, enforce_policy, ctx.elicit — all plausible guard names —
    got 100% HIGH false positives and uninstalled.
    """

    def test_assert_can(self):
        source = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def refund(pi: str):
    assert_can("user", "refund")
    import stripe; stripe.Refund.create(payment_intent=pi)
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"assert_can should be a guard: {findings}"

    def test_policy_gate(self):
        source = '''import shutil
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def delete(path: str):
    policy_gate("delete", path)
    shutil.rmtree(path)
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"policy_gate should be a guard: {findings}"

    def test_audit_and_allow(self):
        source = '''import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def execute(cmd: str):
    audit_and_allow("exec", cmd)
    subprocess.run(cmd)
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"audit_and_allow should be a guard: {findings}"

    def test_can_user(self):
        source = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def refund(pi: str):
    can_user("user", "refund")
    import stripe; stripe.Refund.create(payment_intent=pi)
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"can_user should be a guard: {findings}"

    def test_enforce_policy(self):
        source = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def refund(pi: str):
    enforce_policy("refund", pi)
    import stripe; stripe.Refund.create(payment_intent=pi)
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"enforce_policy should be a guard: {findings}"

    def test_guard_action(self):
        source = '''import shutil
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def delete(path: str):
    guard_action("delete", path)
    shutil.rmtree(path)
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"guard_action should be a guard: {findings}"

    def test_ctx_elicit_mcp_native(self):
        """ctx.elicit is MCP's own human-approval primitive."""
        source = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
async def refund(pi: str):
    await ctx.elicit("Approve refund?")
    import stripe; stripe.Refund.create(payment_intent=pi)
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"ctx.elicit (MCP native) should be a guard: {findings}"

    def test_human_approval(self):
        source = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def refund(pi: str):
    human_approval("refund")
    import stripe; stripe.Refund.create(payment_intent=pi)
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"human_approval should be a guard: {findings}"

    def test_confirm_action(self):
        source = '''import shutil
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def delete(path: str):
    confirm_action("delete")
    shutil.rmtree(path)
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"confirm_action should be a guard: {findings}"

    def test_original_guards_still_work(self):
        """Original guard names (authorize, check_permission) still work.

        authorize("refund") is assert-style with a single literal -> guarded.
        check_permission("refund") is non-assert with discarded result -> WEAK (low).
        """
        source = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def refund(pi: str):
    authorize("refund")
    import stripe; stripe.Refund.create(payment_intent=pi)
@mcp.tool()
def refund2(pi: str):
    check_permission("refund")
    import stripe; stripe.Refund.create(payment_intent=pi)
'''
        findings = _scan_source(source)
        # authorize is assert-style with single literal -> guarded -> 0 findings for that function
        # check_permission with discarded result -> WEAK (low severity)
        assert len(findings) == 0 or all(
            f.severity == "low" for f in findings
        ), f"Should be clean or WEAK (low), got {[(f.rule_id, f.severity) for f in findings]}"

    def test_no_guard_still_finds(self):
        """Without a guard, findings still appear."""
        source = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def refund(pi: str):
    import stripe; stripe.Refund.create(payment_intent=pi)
'''
        findings = _scan_source(source)
        assert len(findings) >= 1


class TestConfigErrorHandling:
    """Config errors must produce helpful messages, not tracebacks."""

    def test_bad_json_does_not_crash(self, tmp_path):
        """Malformed JSON prints schema hint, not a traceback."""
        bad_config = tmp_path / "bad.json"
        bad_config.write_text('{invalid json')
        with pytest.raises(ConfigError) as exc_info:
            load_rules(str(bad_config))
        assert "could not parse" in str(exc_info.value)
        assert "guard_patterns" in str(exc_info.value)

    def test_guards_object_not_array_does_not_crash(self, tmp_path):
        """{"guards": {"patterns": [...]}} — a plausible mistake — works."""
        config = tmp_path / "config.json"
        config.write_text('{"guards": {"patterns": ["my_guard"]}}')
        # Should NOT crash — should parse the patterns from the object
        rules = load_rules(str(config))
        assert "my_guard" in rules.guard_patterns

    def test_toml_config_rejected_gracefully(self, tmp_path):
        """TOML config files are rejected with a clear message."""
        config = tmp_path / "config.toml"
        config.write_text('guard_patterns = ["test"]')
        with pytest.raises(ConfigError) as exc_info:
            load_rules(str(config))
        assert "TOML" in str(exc_info.value)
        assert "JSON" in str(exc_info.value)

    def test_unknown_suffix_rejected_gracefully(self, tmp_path):
        config = tmp_path / "config.txt"
        config.write_text('{"guard_patterns": ["test"]}')
        with pytest.raises(ConfigError) as exc_info:
            load_rules(str(config))
        assert "unsupported" in str(exc_info.value).lower()

    def test_missing_file_rejected_gracefully(self):
        with pytest.raises(ConfigError) as exc_info:
            load_rules("/nonexistent/config.json")
        assert "not found" in str(exc_info.value)

    def test_good_config_works(self, tmp_path):
        """{"guard_patterns": [...]} works correctly."""
        config = tmp_path / "config.json"
        config.write_text('{"guard_patterns": ["my_custom_guard"]}')
        rules = load_rules(str(config))
        assert "my_custom_guard" in rules.guard_patterns

    def test_cli_catches_config_error(self, tmp_path):
        """The CLI catches ConfigError and prints a clean message, not a traceback."""
        from actenon_scan.cli import main
        bad_config = tmp_path / "bad.json"
        bad_config.write_text('{invalid')
        py_file = tmp_path / "test.py"
        py_file.write_text("x = 1\n")
        rc = main(["scan", str(py_file), "--config", str(bad_config)])
        assert rc == 2  # exit code 2 = config error (not 1 = findings, not 0 = clean)
