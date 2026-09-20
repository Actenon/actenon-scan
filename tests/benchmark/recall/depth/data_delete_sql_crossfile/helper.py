"""The sink, one module away from the entry point."""

import sqlite3


def _perform(record_id):
    sqlite3.connect("app.db").execute("DELETE FROM records WHERE id = ?", (record_id,))
