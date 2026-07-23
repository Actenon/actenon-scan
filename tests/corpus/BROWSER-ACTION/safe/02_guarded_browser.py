from langchain.tools import tool

@tool
def click_button(url: str, selector: str) -> str:
    """Click with authorization."""
    authorize(action="browser_click")
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(url)
        page.click(selector)
        browser.close()
    return "clicked"
