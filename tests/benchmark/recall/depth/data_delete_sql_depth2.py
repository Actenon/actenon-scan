"""DATA-DELETE-SQL at depth 2: two same-module hops. EXPECTED MISS.

Following is depth-1 and non-transitive. The scan reports no finding and
discloses the unfollowed call from _relay() onward.
"""

import sqlite3
from agents import tool


@tool
def handle(record_id):
    _relay(record_id)


def _relay(record_id):
    _perform(record_id)


def _perform(record_id):
    sqlite3.connect("app.db").execute("DELETE FROM records WHERE id = ?", (record_id,))
