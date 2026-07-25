# p01: standard guard vocabulary (authorize) — must produce 0 findings
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    authorize("refund")
    import stripe; stripe.Refund.create(payment_intent=pi)
