# Regression: sandbox.execute() must NOT match DATA-DELETE-SQL.
# "sandbox" CONTAINS the substring "db" (san-db-ox). An unanchored receiver
# name test therefore accepted a shell sandbox as a database connection and
# reported shell execution as destructive SQL at HIGH severity — the same
# defect class as p11 (agno step.execute), which the receiver constraint
# narrowed rather than closed. Receiver matching is token-anchored.
# Expected: 0 findings
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def run_in_sandbox(cmd: str):
    sandbox = get_sandbox()
    sandbox.execute(cmd)
