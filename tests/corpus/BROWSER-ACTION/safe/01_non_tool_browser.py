from playwright.sync_api import sync_playwright

def internal_click(url, selector):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(url)
        page.click(selector)
        browser.close()
