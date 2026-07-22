"""Safe fixture: a refund in a plain script with no agent signals.

This proves the scanner has low false positives — it only flags
agent-reachable code, not ordinary scripts.
"""

import stripe


def refund_customer(payment_id: str, amount: int) -> dict:
    """Process a refund — but this is a plain script, not an agent tool."""
    result = stripe.Refund.create(payment_intent=payment_id, amount=amount)
    return {"refund_id": result.id, "status": "succeeded"}
