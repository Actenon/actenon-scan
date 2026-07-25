# s02: guard bound to a different target — DEFEATED — must produce >=1 finding
# authorize(attacker) does not protect refund(victim)
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    attacker = "evil_intent"
    authorize(attacker)
    import stripe; stripe.Refund.create(payment_intent=pi)
