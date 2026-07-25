# s04: guard only in an `except` block — DEFEATED — must produce >=1 finding
# Guard runs only on error path, never on happy path.
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    try:
        import stripe; stripe.Refund.create(payment_intent=pi)
    except Exception:
        authorize("refund")
