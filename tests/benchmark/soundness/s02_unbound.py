# s02: guard bound to a different target — DEFEATED — must produce >=1 finding
# authorize(attacker) does not protect refund(victim).
#
# `attacker` is not a parameter and is assigned only from a string literal, so
# the guard's apparent data-dependence is counterfeit: it inspects a constant
# while the sink acts on `pi`. Restored to its original form — an earlier
# revision replaced this with an all-literal guard call, which is not
# separable from casbin_enforce("user", "record", "delete").
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    attacker = "evil_intent"
    authorize(attacker)
    import stripe; stripe.Refund.create(payment_intent=pi)
