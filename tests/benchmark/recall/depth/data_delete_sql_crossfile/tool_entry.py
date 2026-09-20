"""DATA-DELETE-SQL across files. EXPECTED MISS.

There is no cross-file analysis. The call is disclosed as unfollowed with
reason `cross_file`.
"""

from agents import tool

from .helper import _perform


@tool
def handle(record_id):
    _perform(record_id)
