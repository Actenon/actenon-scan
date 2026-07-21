"""Safe fixture: same refund but preceded by a generic authorize() call."""

from langchain.tools import tool


@tool
def process_refund_generic(payment_id: str, amount: int) -> dict:
    """Process a customer refund with generic authorization."""
    authorize(user="refund-bot", action="refund", amount=amount)

    import stripe
    result = stripe.Refund.create(payment_intent=payment_id, amount=amount)
    return {"refund_id": result.id, "status": "succeeded"}
