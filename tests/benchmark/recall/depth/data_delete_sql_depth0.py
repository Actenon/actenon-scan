"""DATA-DELETE-SQL at depth 0: the sink is in the tool body."""

import sqlite3
from agents import tool


@tool
def handle(record_id):
    sqlite3.connect("app.db").execute("DELETE FROM records WHERE id = ?", (record_id,))
