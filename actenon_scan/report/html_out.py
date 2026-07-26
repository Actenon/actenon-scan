"""HTML report formatter — self-contained shareable report.

Work Order 2, Part 6.1: the HTML report is self-contained, usable
offline, free of external scripts/fonts/assets, and safe to open locally.
"""

from __future__ import annotations

import html
from collections import Counter

from actenon_scan.engine import ScanResult
from actenon_scan.report.blast_radius import (
    CLEAN_SCAN_LIMITATIONS,
    CLEAN_SCAN_STATEMENT,
    consequence_label,
    group_by_consequence,
    select_most_exposed,
)


def format_html(result: ScanResult, *, elapsed: float | None = None) -> str:
    """Format scan results as a self-contained HTML report."""
    unsuppressed = [f for f in result.findings if not f.suppressed]
    timing = f" ({elapsed:.2f}s)" if elapsed is not None else ""

    groups = group_by_consequence(unsuppressed) if unsuppressed else {}
    most_exposed = select_most_exposed(unsuppressed) if unsuppressed else None

    # Build sections
    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f"<title>Actenon Scan Report</title>")
    parts.append("<style>")
    parts.append(_CSS)
    parts.append("</style>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append('<main class="container">')

    # Header
    parts.append('<header>')
    parts.append('<h1>Actenon Scan Report</h1>')
    parts.append(
        f'<p class="meta">Files scanned: {result.files_scanned} &middot; '
        f"Findings: {len(unsuppressed)}{html.escape(timing)}</p>"
    )
    parts.append("</header>")

    if not unsuppressed:
        # Clean scan
        parts.append('<section class="clean">')
        parts.append(f"<p>{html.escape(CLEAN_SCAN_STATEMENT)}</p>")
        parts.append("</section>")
        parts.append('<section class="honesty">')
        parts.append("<h2>What this scan verified</h2>")
        parts.append("<p>Supported source files were parsed and analysed for agent-reachable consequential actions without a dominating authority check.</p>")
        parts.append("<h2>What this scan did not verify</h2>")
        parts.append("<p>Unsupported languages, files outside the scan target, guards outside the analysed path, external reachability, or practical exploitability.</p>")
        parts.append('<p>See the <code>docs/COVERAGE.md</code> file in the actenon-scan repository for supported architectures and analysis limits.</p>')
        parts.append("</section>")
        parts.append("</main>")
        parts.append("</body>")
        parts.append("</html>")
        return "\n".join(parts)

    # Blast-radius summary
    has_weak = any(f.confidence in ("low", "medium") for f in unsuppressed)
    header_text = (
        f"Your agent can reach {len(unsuppressed)} consequential actions. "
        "No dominating authorization check was identified in the analysed path."
        if has_weak
        else f"Your agent can reach {len(unsuppressed)} consequential actions "
        "without a dominating authorization check."
    )
    parts.append('<section class="blast-radius">')
    parts.append(f"<p class=\"lead\">{html.escape(header_text)}</p>")
    parts.append("<table>")
    parts.append("<tr><th>Consequence</th><th>Count</th><th>Methods</th></tr>")
    for label, group in groups.items():
        parts.append(
            f"<tr><td>{html.escape(label)}</td><td>{group.count}</td>"
            f"<td>{html.escape(group.method_summary)}</td></tr>"
        )
    parts.append("</table>")
    parts.append("</section>")

    # Most-exposed spotlight
    if most_exposed is not None:
        parts.append('<section class="spotlight">')
        parts.append("<h2>Most exposed</h2>")
        parts.append(
            f'<p class="loc">{html.escape(most_exposed.file)}:{most_exposed.line}</p>'
        )
        parts.append(
            f'<p class="call"><code>{html.escape(most_exposed.call_text)}</code></p>'
        )
        parts.append("<table>")
        parts.append(f"<tr><th>Consequence</th><td>{html.escape(consequence_label(most_exposed.category))}</td></tr>")
        parts.append(f"<tr><th>Rule</th><td><code>{html.escape(most_exposed.rule_id)}</code></td></tr>")
        parts.append(f"<tr><th>Severity</th><td>{html.escape(most_exposed.severity)} (confidence: {html.escape(most_exposed.confidence)})</td></tr>")
        parts.append("<tr><th>Guard evidence</th><td>none found on the analysed path</td></tr>")
        parts.append("</table>")
        loc = f"{most_exposed.file}:{most_exposed.line}"
        parts.append(
            f'<p class="next">Next: <code>actenon-scan explain {html.escape(loc)}</code> '
            f'&middot; <code>actenon-scan fix {html.escape(loc)}</code></p>'
        )
        parts.append("</section>")

    # Findings by consequence
    parts.append('<section class="findings">')
    parts.append("<h2>Findings by consequence</h2>")
    for label, group in groups.items():
        parts.append(f"<h3>{html.escape(label)} ({group.count})</h3>")
        parts.append("<ul>")
        for f in group.findings:
            parts.append(
                f"<li><strong>{html.escape(f.file)}:{f.line}</strong> "
                f'<code>{html.escape(f.rule_id)}</code> &mdash; '
                f'<code>{html.escape(f.call_text)}</code>'
                f"<br><small>severity: {html.escape(f.severity)}, "
                f"confidence: {html.escape(f.confidence)}</small></li>"
            )
        parts.append("</ul>")
    parts.append("</section>")

    # Honesty statement (Part 6.2 — visible, not hidden in footer)
    parts.append('<section class="honesty">')
    parts.append("<h2>What this scan verified / did not verify</h2>")
    parts.append("<p><strong>Verified:</strong> supported source files were parsed and analysed for agent-reachable consequential actions without a dominating authority check.</p>")
    parts.append("<p><strong>Not verified:</strong> unsupported languages, files outside the scan target, guards outside the analysed path, external reachability, or practical exploitability.</p>")
    parts.append('<p>See the <code>docs/COVERAGE.md</code> file in the actenon-scan repository for supported architectures and analysis limits.</p>')
    parts.append("</section>")

    # Unsupported files
    if result.unsupported_files:
        lang_counts = Counter(lang for _, lang in result.unsupported_files)
        parts.append('<section class="unsupported">')
        parts.append(
            f"<p><strong>Note:</strong> {len(result.unsupported_files)} file(s) NOT scanned &mdash; "
            f"unsupported: {html.escape(str(dict(lang_counts)))}</p>"
        )
        parts.append("</section>")

    parts.append("</main>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts)


_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 0; background: #f6f8fa; color: #1f2328; }
.container { max-width: 900px; margin: 0 auto; padding: 2rem 1rem; }
header h1 { margin: 0 0 0.5rem 0; font-size: 1.8rem; }
.meta { color: #656d76; font-size: 0.9rem; margin: 0 0 2rem 0; }
section { background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
.blast-radius .lead { font-size: 1.15rem; font-weight: 600; margin: 0 0 1rem 0; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; }
th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #eaeef2; }
th { background: #f6f8fa; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.03em; }
.spotlight .loc { font-weight: 600; font-size: 1.1rem; margin: 0.5rem 0 0.25rem 0; }
.spotlight .call, code { background: #f6f8fa; padding: 0.15rem 0.35rem; border-radius: 4px; font-family: 'SF Mono', Consolas, monospace; font-size: 0.9em; }
.spotlight .call { display: inline-block; margin: 0.25rem 0; padding: 0.4rem 0.6rem; }
.next { margin-top: 1rem; font-size: 0.9rem; color: #656d76; }
.findings h3 { margin: 1.5rem 0 0.5rem 0; font-size: 1.05rem; }
.findings li { margin-bottom: 0.5rem; line-height: 1.5; }
.findings small { color: #656d76; }
.honesty { background: #fff8c5; border-color: #d4a72c; }
.honesty h2 { margin-top: 0; }
.clean p { font-size: 1.1rem; font-weight: 600; }
.unsupported { background: #ffebe9; border-color: #ffcecb; }
"""
