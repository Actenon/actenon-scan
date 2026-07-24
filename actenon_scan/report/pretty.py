"""Pretty (human-readable) report formatter."""

from __future__ import annotations

from collections import Counter

from actenon_scan.engine import ScanResult, Finding


def format_pretty(result: ScanResult) -> str:
    """Format scan results as a human-readable report grouped by file."""
    unsuppressed = [f for f in result.findings if not f.suppressed]

    if not unsuppressed:
        lines: list[str] = []
        lines.append(f"actenon-scan: no findings in {result.files_scanned} file(s) scanned.")
        # Never end with a bare "no findings" when files were not examined.
        if result.unsupported_files:
            lang_counts = Counter(lang for _, lang in result.unsupported_files)
            lines.append(f"  {len(result.unsupported_files)} file(s) NOT scanned — unsupported language(s): {dict(lang_counts)}.")
            # Determine which extra to suggest
            extras = set()
            for _, lang in result.unsupported_files:
                if "TypeScript" in lang or "JavaScript" in lang:
                    extras.add("typescript")
            if extras:
                install_hint = " or ".join(f'"actenon-scan[{e}]"' for e in sorted(extras))
                lines.append(f"  Install with:  pip install {install_hint}")
        if result.analysis_errors:
            lines.append(f"  {len(result.analysis_errors)} file(s) errored during analysis.")
            for rel, err in result.analysis_errors[:10]:
                lines.append(f"    {rel}: {err}")
            if len(result.analysis_errors) > 10:
                lines.append(f"    ... and {len(result.analysis_errors) - 10} more")
        return "\n".join(lines) + "\n"

    # Group by file
    by_file: dict[str, list[Finding]] = {}
    for f in unsuppressed:
        by_file.setdefault(f.file, []).append(f)

    lines = []
    lines.append(f"actenon-scan: {len(unsuppressed)} finding(s) in {len(by_file)} file(s) (scanned {result.files_scanned} file(s))")
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

    # Surface unsupported files even when findings exist — a finding in
    # Python does not mean the TypeScript files are clean.
    if result.unsupported_files:
        lang_counts = Counter(lang for _, lang in result.unsupported_files)
        lines.append(f"unsupported: {len(result.unsupported_files)} file(s) NOT scanned — {dict(lang_counts)}")
        extras = set()
        for _, lang in result.unsupported_files:
            if "TypeScript" in lang or "JavaScript" in lang:
                extras.add("typescript")
        if extras:
            install_hint = " or ".join(f'"actenon-scan[{e}]"' for e in sorted(extras))
            lines.append(f"  Install with:  pip install {install_hint}")
        lines.append("")

    return "\n".join(lines) + "\n"
