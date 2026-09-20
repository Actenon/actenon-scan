"""Receiver-name matching for .execute()-family SQL sinks must be token-anchored.

The DATA-DELETE-SQL rule fires on `<receiver>.execute(<non-literal>)`, so the
receiver check is the only thing standing between "destructive SQL" and every
other `.execute()` in Python. agno's `step.execute()` was the first false
positive of this class; the receiver constraint added to fix it used an
UNANCHORED substring test, which merely narrowed the class:

    "sandbox"  contains "db"      -> san(db)ox
    "sandbox_backend"             -> same

so a sandbox shell executor was still reported as destructive SQL at HIGH.
These tests pin both directions of the anchored rule.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from actenon_scan.detectors.sinks import _identifier_tokens, _name_looks_db
from actenon_scan.engine import scan_path

TOOL = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n\n@mcp.tool()\n'


def _scan(source: str) -> list:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(source)
        f.flush()
        result = scan_path(f.name)
    Path(f.name).unlink()
    return [f for f in result.findings if not f.suppressed]


class TestIdentifierTokens:
    def test_snake_case(self):
        assert _identifier_tokens("self.db_session") == {"self", "db", "session"}

    def test_camel_case(self):
        assert _identifier_tokens("asyncSession") == {"async", "session"}

    def test_screaming_case(self):
        assert _identifier_tokens("DB_CONN") == {"db", "conn"}

    def test_substring_is_not_a_token(self):
        assert "db" not in _identifier_tokens("sandbox")


class TestReceiverNameMatching:
    def test_real_db_names_still_match(self):
        for name in ("conn", "cursor", "cur", "session", "engine", "db",
                     "database", "connection", "db_session", "asyncSession",
                     "self.conn", "DB_CONN"):
            assert _name_looks_db(name), name

    def test_substring_collisions_no_longer_match(self):
        """Identifiers that merely CONTAIN a DB name are not DB receivers."""
        for name in ("sandbox", "sandbox_backend", "endbox", "curses",
                     "recursion", "concurrent"):
            assert not _name_looks_db(name), name

    def test_unrelated_receivers_do_not_match(self):
        for name in ("step", "router", "condition", "loop", "executor",
                     "task", "workflow", "pipeline"):
            assert not _name_looks_db(name), name


class TestEndToEnd:
    def test_sandbox_execute_is_not_destructive_sql(self):
        """The defect this fix closes: a shell sandbox reported as SQL."""
        source = TOOL + '''def run_in_sandbox(cmd: str):
    sandbox = get_sandbox()
    sandbox.execute(cmd)
'''
        findings = _scan(source)
        assert not [f for f in findings if "SQL" in f.rule_id], findings

    def test_agno_step_execute_stays_clean(self):
        """The original regression (p11) must not come back."""
        source = TOOL + '''def run_step(step_name: str):
    step.execute(step_name)
'''
        assert _scan(source) == []

    def test_genuine_cursor_execute_still_flagged(self):
        """The fix must not cost recall on real SQL."""
        source = TOOL + '''def wipe(sql: str):
    cursor.execute(sql)
'''
        findings = _scan(source)
        assert [f for f in findings if "SQL" in f.rule_id], findings

    def test_genuine_session_execute_still_flagged(self):
        source = TOOL + '''def wipe(sql: str):
    db_session.execute(sql)
'''
        findings = _scan(source)
        assert [f for f in findings if "SQL" in f.rule_id], findings

    def test_cursor_by_origin_not_by_name_still_flagged(self):
        """`curr = conn.cursor()` has a non-DB name but a DB origin."""
        source = TOOL + '''def wipe(sql: str):
    curr = conn.cursor()
    curr.execute(sql)
'''
        findings = _scan(source)
        assert [f for f in findings if "SQL" in f.rule_id], findings
