"""Audit fixture (Work Order 1, Part 1.3): non-browser .click() must NOT fire.

BROWSER-ACTION matches qualified patterns like `page.click`, `frame.click`,
`element.click`, `locator.click`, `driver.click`. A non-browser object
calling `.click()` (e.g., a UI Button model in a non-agent context) must
NOT match — the receiver name does not equal any qualified pattern.

This fixture pairs with vulnerable/01_page_click.py to prove the
narrowing is SAFE: false-positive case stays clean, legitimate case
still fires.
"""


class Button:
    """A non-browser domain object that happens to have a .click() method."""

    def click(self) -> None:
        pass


def press_domain_button(label: str) -> None:
    """Not an agent tool, not a browser action — must not fire BROWSER-ACTION."""
    btn = Button()
    btn.click()
