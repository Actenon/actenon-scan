"""Regression tests for DATA-DELETE-SQL sink detection fix and boto3 gaps.

Part 4: fix the SQL detection to match the SINK (.execute) rather than
the statement text, and close boto3 destructive surface gaps.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from actenon_scan.engine import scan_path


def _scan_source(source: str) -> list:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(source)
        f.flush()
        result = scan_path(f.name)
    Path(f.name).unlink()
    return [f for f in result.findings if not f.suppressed]


class TestSqlSinkDetection:
    """The SINK is .execute/.executemany/.executescript, not the literal text."""

    def test_literal_drop_caught(self):
        """Literal DROP TABLE in execute() is caught."""
        source = '''import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def drop():
    sqlite3.connect("p.db").execute("DROP TABLE customers")
'''
        findings = _scan_source(source)
        sql_findings = [f for f in findings if f.rule_id == "DATA-DELETE-SQL"]
        assert len(sql_findings) == 1

    def test_variable_sql_now_caught(self):
        """Variable SQL (caller-controlled) is now caught — the missed case.

        This is strictly more dangerous than literal SQL because the agent
        controls the statement.
        """
        source = '''import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def run_query(sql: str):
    sqlite3.connect("p.db").execute(sql)
'''
        findings = _scan_source(source)
        sql_findings = [f for f in findings if f.rule_id == "DATA-DELETE-SQL"]
        assert len(sql_findings) == 1, f"Variable SQL should be caught, got {findings}"

    def test_fstring_sql_caught(self):
        """f-string SQL (caller-influenced) is caught."""
        source = '''import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def run_query(table: str):
    sqlite3.connect("p.db").execute(f"DELETE FROM {table}")
'''
        findings = _scan_source(source)
        sql_findings = [f for f in findings if f.rule_id == "DATA-DELETE-SQL"]
        assert len(sql_findings) >= 1

    def test_literal_select_not_reported(self):
        """Literal SELECT-only is not reported."""
        source = '''import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def query(user_id: str):
    return sqlite3.connect("p.db").execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
'''
        findings = _scan_source(source)
        sql_findings = [f for f in findings if f.rule_id == "DATA-DELETE-SQL"]
        assert len(sql_findings) == 0, f"SELECT should not be reported, got {sql_findings}"

    def test_executemany_caught(self):
        """executemany with variable SQL is caught."""
        source = '''import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def bulk(sql: str, params: list):
    sqlite3.connect("p.db").executemany(sql, params)
'''
        findings = _scan_source(source)
        sql_findings = [f for f in findings if f.rule_id == "DATA-DELETE-SQL"]
        assert len(sql_findings) == 1

    def test_executescript_caught(self):
        """executescript with variable SQL is caught."""
        source = '''import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def run_script(script: str):
    sqlite3.connect("p.db").executescript(script)
'''
        findings = _scan_source(source)
        sql_findings = [f for f in findings if f.rule_id == "DATA-DELETE-SQL"]
        assert len(sql_findings) == 1


class TestBoto3DestructiveGaps:
    """Close the boto3 destructive surface gaps."""

    def test_s3_delete_objects_caught(self):
        """s3.delete_objects (bulk deletion) is now caught."""
        source = '''import boto3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def wipe(bucket: str, keys: list):
    boto3.client("s3").delete_objects(Bucket=bucket, Delete={"Objects": keys})
'''
        findings = _scan_source(source)
        sdk_findings = [f for f in findings if f.rule_id == "PROVIDER-SDK-CALL"]
        assert len(sdk_findings) >= 1, f"s3.delete_objects should be caught, got {findings}"

    def test_ec2_terminate_instances_caught(self):
        """ec2.terminate_instances is caught (was already present)."""
        source = '''import boto3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def terminate(instance_ids: list):
    boto3.client("ec2").terminate_instances(InstanceIds=instance_ids)
'''
        findings = _scan_source(source)
        sdk_findings = [f for f in findings if f.rule_id == "PROVIDER-SDK-CALL"]
        assert len(sdk_findings) >= 1

    def test_dynamodb_delete_table_caught(self):
        """dynamodb delete_table is caught."""
        source = '''import boto3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def delete_table(table_name: str):
    boto3.client("dynamodb").delete_table(TableName=table_name)
'''
        findings = _scan_source(source)
        sdk_findings = [f for f in findings if f.rule_id == "PROVIDER-SDK-CALL"]
        assert len(sdk_findings) >= 1

    def test_rds_delete_db_instance_caught(self):
        """rds delete_db_instance is caught."""
        source = '''import boto3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def delete_db(db_id: str):
    boto3.client("rds").delete_db_instance(DBInstanceIdentifier=db_id)
'''
        findings = _scan_source(source)
        sdk_findings = [f for f in findings if f.rule_id == "PROVIDER-SDK-CALL"]
        assert len(sdk_findings) >= 1
