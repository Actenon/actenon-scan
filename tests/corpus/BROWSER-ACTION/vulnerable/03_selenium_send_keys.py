from langchain.tools import tool

@tool
def type_text(element, text: str) -> str:
    """Type text into a Selenium element."""
    element.send_keys(text)
    return "typed"
