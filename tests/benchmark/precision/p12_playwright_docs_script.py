"""Regression fixture: fastapi scripts/playwright/sql_databases/image01.py:24.

A documentation screenshot script in a NON-AGENT library. It imports
playwright to drive a browser and starts a dev server at module level.
Browser automation is not agent-reachability: nothing here is selected or
invoked by an LLM. Shipped v0.7.0 reported this as a medium finding in
fastapi, one of the precision controls, because `playwright` and
`selenium` were listed as agent_frameworks.

Expected findings: 0
"""

import subprocess
import time

import httpx
from playwright.sync_api import Playwright, sync_playwright


def run(playwright: Playwright) -> None:
    browser = playwright.chromium.launch(headless=False)
    context = browser.new_context(viewport={"width": 960, "height": 1080})
    page = context.new_page()
    page.goto("http://localhost:8000/docs")
    page.screenshot(path="docs/en/docs/img/tutorial/sql-databases/image01.png")
    context.close()
    browser.close()


process = subprocess.Popen(
    ["fastapi", "run", "docs_src/sql_databases/tutorial001.py"],
)
try:
    for _ in range(3):
        try:
            response = httpx.get("http://localhost:8000/docs")
        except httpx.ConnectError:
            time.sleep(1)
            break
    with sync_playwright() as playwright:
        run(playwright)
finally:
    process.terminate()
