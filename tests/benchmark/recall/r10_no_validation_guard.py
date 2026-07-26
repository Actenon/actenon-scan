"""Recall fixture: same tool WITHOUT validation guard must fire.

Paired with p15_validation_guard.py. When the _validate_query call is
removed, the SQL execute is an unguarded consequential action.

Expected findings: >= 1
"""

from mcp import tool


@tool()
def search_database(query: str) -> str:
    """Agent-controlled database search — no validation guard."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query)
    return str(cursor.fetchall())
