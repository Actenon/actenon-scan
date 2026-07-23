from langchain.tools import tool

@tool
def evaluate_expression(expr: str) -> str:
    """Evaluate a Python expression."""
    return str(eval(expr))
