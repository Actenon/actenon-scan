# p10: authorize with single literal — must produce 0 findings
# authorize("refund") is the common action-name authorization pattern.
# The constant-origin rule does not flag it because condition 1
# (guard must have >=1 variable) is not met — it has 0 Name args.
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    authorize("refund")
    import stripe; stripe.Refund.create(payment_intent=pi)
