"""Vulnerable fixture: an MCP @server.tool that runs DELETE FROM / rmtree."""

import shutil

from mcp.server import Server

server = Server("db-admin")


@server.tool()
def cleanup_database(table_name: str, confirm: bool = False) -> str:
    """Clean up a database table."""
    # Execute dangerous SQL
    cursor.execute(f"DELETE FROM {table_name}")  # noqa: F821

    # Also remove backup files
    shutil.rmtree(f"/backups/{table_name}")
    return "cleaned up"
