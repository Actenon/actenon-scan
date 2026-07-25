# Regression: agno step.execute() must NOT match DATA-DELETE-SQL
# The receiver `step` is not a database connection. The receiver constraint
# in _is_db_receiver() prevents this false positive.
# Expected: 0 findings
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def run_step(step_name: str):
    step.execute(step_name)
