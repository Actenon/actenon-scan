# p03: MCP ctx.elicit human approval — must produce 0 findings
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
async def refund(pi: str):
    await ctx.elicit("Approve refund?")
    import stripe; stripe.Refund.create(payment_intent=pi)
