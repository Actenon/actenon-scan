# s02: guard bound to a different target — DEFEATED — must produce >=1 finding
# The guard is called with only literal arguments (no variables) — it checks
# constant values, not the sink's parameters. Under the narrower binding rule:
# assert-style guard with >1 literal arg and 0 Name args = UNBOUND.
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    verify_proof(action="refund", target="unrelated", amount=1)
    import stripe; stripe.Refund.create(payment_intent=pi)
