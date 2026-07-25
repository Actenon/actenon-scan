# r01: MCP @mcp.tool — PASSES today
# Expected: >=1 finding (subprocess.run inside @mcp.tool)
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def run_command(cmd: str):
    """Run a shell command."""
    import subprocess
    subprocess.run(cmd, shell=True)
