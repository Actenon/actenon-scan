# p09: verify_pccb with parameter-passing guard — must produce 0 findings
# The guard passes three function parameters (proof, intent, action).
# These are genuine data — not constants — so the constant-origin rule
# does not flag them.
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    verify_pccb(proof, intent, action)
    import stripe; stripe.Refund.create(payment_intent=pi)
