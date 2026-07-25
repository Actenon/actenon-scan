# s05: guard AFTER the sink — correctly flagged today — must produce >=1 finding
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    import stripe; stripe.Refund.create(payment_intent=pi)
    authorize("refund")
