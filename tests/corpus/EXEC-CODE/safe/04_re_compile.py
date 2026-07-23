import re
from langchain.tools import tool

@tool
def validate_email(email: str) -> bool:
    """re.compile() is regex compilation, NOT code execution."""
    pattern = re.compile(r'^[^@]+@[^@]+\.[^@]+$')
    return bool(pattern.match(email))
