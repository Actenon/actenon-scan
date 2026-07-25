# p08: casbin_enforce with multiple literal args — must produce 0 findings
# This is the case a previous fix broke: the literal-arity rule flagged it
# because it has 0 Name args and >1 literal. The constant-origin rule does
# NOT flag it because condition 1 (guard must have >=1 variable) is not met.
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def delete_record(record_id: str):
    casbin_enforce("user", "record", "delete")
    db.delete(record_id)
