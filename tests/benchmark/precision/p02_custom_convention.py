# p02: custom convention (policy_gate) — must produce 0 findings
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def delete(path: str):
    policy_gate("delete", path)
    import shutil; shutil.rmtree(path)
