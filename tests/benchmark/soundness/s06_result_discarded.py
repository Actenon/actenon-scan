# s06: guard result discarded — DEFEATED — must produce >=1 finding
# A guard function whose return value is discarded and whose name does not
# imply raising (no assert/require/enforce prefix, not in the assert_exact set).
# The guard call exists on the path but does nothing — its result is unused.
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    has_permission("refund")  # returns bool, result discarded — not enforcing
    import stripe; stripe.Refund.create(payment_intent=pi)
