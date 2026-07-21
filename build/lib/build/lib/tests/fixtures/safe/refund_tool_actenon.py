"""Safe fixture: same refund but preceded by an actenon verify call."""

from langchain.tools import tool


@tool
def process_refund_actenon(payment_id: str, amount: int) -> dict:
    """Process a customer refund with actenon proof verification."""
    from actenon import verify_proof

    verify_proof(action="refund", target=payment_id, amount=amount)

    import stripe
    result = stripe.Refund.create(payment_intent=payment_id, amount=amount)
    return {"refund_id": result.id, "status": "succeeded"}
