"""Pretty (human-readable) report formatter."""

from __future__ import annotations

from actenon_scan.engine import ScanResult, Finding


def format_pretty(result: ScanResult) -> str:
    """Format scan results as a human-readable report grouped by file."""
    if not result.findings:
        return f"No findings. Scanned {result.files_scanned} file(s).\n"

    # Group by file
    by_file: dict[str, list[Finding]] = {}
    for f in result.findings:
        if f.suppressed:
            continue
        by_file.setdefault(f.file, []).append(f)

    lines: list[str] = []
    lines.append(f"actenon-scan: {sum(1 for f in result.findings if not f.suppressed)} finding(s) in {len(by_file)} file(s) (scanned {result.files_scanned} file(s))")
    lines.append("")

    for filepath in sorted(by_file):
        lines.append(f"  {filepath}")
        for f in sorted(by_file[filepath], key=lambda x: (x.line, x.rule_id)):
            lines.append(f"    {f.line}:{f.col}  [{f.severity.upper()}] {f.rule_id} ({f.category})")
            lines.append(f"            {f.call_text}")
            lines.append(f"            confidence: {f.confidence}")
            lines.append(f"            {f.remediation}")
            lines.append("")

    # Surface any per-file analysis errors so the user knows the scan was
    # partial. Empty list = clean run; non-empty = something was skipped.
    if result.analysis_errors:
        lines.append(f"analysis errors: {len(result.analysis_errors)} file(s) skipped")
        for rel, err in result.analysis_errors[:20]:
            lines.append(f"  {rel}: {err}")
        if len(result.analysis_errors) > 20:
            lines.append(f"  ... and {len(result.analysis_errors) - 20} more")
        lines.append("")
    return "\n".join(lines) + "\n"
