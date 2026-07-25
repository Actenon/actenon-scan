"""Regression fixture (Work Order 1, Part 2.9): non-DB .execute() must NOT fire.

Pairs with vulnerable/04_chained_psycopg2.py. The receiver-origin
resolution must NOT classify a non-DB object's .execute() as a DB
sink. `step.execute(cmd)` where `step` is a domain object (not a DB
connection/cursor) must produce zero findings.

This is the false-positive case the original _is_db_receiver was
designed to prevent. The rewritten version preserves that protection.
"""

from mcp import tool


class Step:
    """A non-DB domain object that happens to have an .execute() method."""

    def execute(self, cmd: str) -> None:
        pass


@tool()
def run_step(cmd: str) -> None:
    """Not a database call — must not fire DATA-DELETE-SQL."""
    step = Step()
    step.execute(cmd)
