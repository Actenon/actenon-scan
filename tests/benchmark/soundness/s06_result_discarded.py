# s06: guard result discarded — DEFEATED — must produce >=1 finding
# check_permission() is called but its return value is not used.
# With v3 local resolution, check_permission defined as bool-returning
# is classified as boolean-style -> WEAK when result discarded.
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

def check_permission(action: str) -> bool:
    return False

@mcp.tool()
def refund(pi: str):
    check_permission("refund")  # result discarded — not enforcing
    import stripe; stripe.Refund.create(payment_intent=pi)
