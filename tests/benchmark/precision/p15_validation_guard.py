"""Regression fixture: validation-method guard must suppress finding.

_validate_query is a dominating, parameter-bound guard. The scanner must
recognise method names starting with validate_/check_/sanitize_/verify_
as guards when they dominate the sink and share the sink's parameter.

Verified against real source in:
  crewai/lib/crewai-tools/src/crewai_tools/tools/singlestore_search_tool/singlestore_search_tool.py

Expected findings: 0
"""

from mcp import tool


@tool()
def search_database(query: str) -> str:
    """Agent-controlled database search."""
    valid, msg = _validate_query(query)
    if not valid:
        return f"Invalid: {msg}"
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query)
    return str(cursor.fetchall())


def _validate_query(query: str) -> tuple[bool, str]:
    """Validate the query — only SELECT allowed."""
    if not query.strip().lower().startswith("select"):
        return False, "Only SELECT queries are supported."
    return True, "Valid"
