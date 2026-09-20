"""DATA-DELETE-SQL at depth 1: one same-module hop."""

import sqlite3
from agents import tool


@tool
def handle(record_id):
    _perform(record_id)


def _perform(record_id):
    sqlite3.connect("app.db").execute("DELETE FROM records WHERE id = ?", (record_id,))
