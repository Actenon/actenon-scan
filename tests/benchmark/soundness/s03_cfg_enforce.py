# s03: guard behind `if cfg.enforce:` — DEFEATED — must produce >=1 finding
# Guard only runs if config flag is set; disabled in production.
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def refund(pi: str):
    if cfg.enforce:
        authorize("refund")
    import stripe; stripe.Refund.create(payment_intent=pi)
