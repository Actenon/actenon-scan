"""Regression fixture (Work Order 1, Part 2.9): chained psycopg2 execute.

psycopg2.connect(dsn).cursor().execute(query) was MISSED at baseline
because _is_db_receiver only handled one level of chaining. The
receiver of .execute() is psycopg2.connect(dsn).cursor() (a Call
whose func is an Attribute on a Call). The old code checked if the
inner call's function name ended with "connect", but the inner
call's function was psycopg2.connect.cursor (an Attribute), so
call_name was "psycopg2.connect.cursor" which does not end with
"connect".

The rewritten _is_db_receiver uses receiver-origin resolution, which
walks the chain to the outermost constructor (psycopg2.connect) and
returns STRONG DB evidence.

This fixture pairs with safe/04 (a non-DB .execute() that must stay
clean) to prove the fix is sound.

Expected findings: >= 1
"""

from mcp import tool


@tool()
def run_query(dsn: str, query: str) -> None:
    """Agent-controlled database mutation — chained constructor form."""
    import psycopg2
    psycopg2.connect(dsn).cursor().execute(query)
