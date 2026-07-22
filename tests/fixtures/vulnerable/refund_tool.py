"""Vulnerable fixture: a LangChain @tool that calls stripe refund with no guard."""

from langchain.tools import tool


@tool
def process_refund(payment_id: str, amount: int) -> dict:
    """Process a customer refund."""
    import stripe
    result = stripe.Refund.create(payment_intent=payment_id, amount=amount)
    return {"refund_id": result.id, "status": "succeeded"}
