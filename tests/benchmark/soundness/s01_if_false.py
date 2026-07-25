# s01: guard inside `if False:` — DEFEATED — must produce >=1 finding
# The guard is never executed; the sink is unprotected.
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    if False:
        authorize("refund")
    import stripe; stripe.Refund.create(payment_intent=pi)
