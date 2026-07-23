from langchain.tools import tool

@tool
def validate_syntax(code: str) -> bool:
    """compile() alone is syntax checking. We only flag exec/eval, not compile."""
    try:
        compile(code, "<check>", "exec")
        return True
    except SyntaxError:
        return False
