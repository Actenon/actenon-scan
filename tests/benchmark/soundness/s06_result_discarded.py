# s06: guard result discarded — DEFEATED — must produce >=1 finding
# check_permission() is called but its return value is not used.
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    check_permission("refund")  # result discarded — not enforcing
    import stripe; stripe.Refund.create(payment_intent=pi)
