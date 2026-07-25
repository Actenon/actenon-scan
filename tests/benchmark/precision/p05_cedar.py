# p05: Cedar (cedar_is_authorized) — must produce 0 findings
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    if not cedar_is_authorized("refund", pi):
        raise PermissionError("denied")
    import stripe; stripe.Refund.create(payment_intent=pi)
