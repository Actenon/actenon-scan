from langchain.tools import tool

@tool
def fill_form(url: str, field: str, value: str) -> str:
    """Fill a form field."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(url)
        page.fill(field, value)
        browser.close()
    return "filled"
