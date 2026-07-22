"""Scan engine — orchestrates AST parsing, sink detection, reachability, and guard checks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from actenon_scan.detectors.guards import is_guarded
from actenon_scan.detectors.reachability import detect_reachability
from actenon_scan.detectors.sinks import detect_sinks
from actenon_scan.rules.loader import Ruleset, load_rules


@dataclass
class Finding:
    file: str
    line: int
    col: int
    rule_id: str
    category: str
    severity: str
    confidence: str
    description: str
    call_text: str
    remediation: str
    suppressed: bool = False
    snippet_hash: str = ""

    @property
    def effective_severity(self) -> str:
        """Downgrade severity one notch if confidence is MEDIUM."""
        if self.confidence == "medium":
            return _downgrade_severity(self.severity)
        return self.severity


def _downgrade_severity(severity: str) -> str:
    mapping = {"high": "medium", "medium": "low", "low": "low"}
    return mapping.get(severity, severity)


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    rules_used: Ruleset | None = None

    @property
    def finding_count(self) -> int:
        return len([f for f in self.findings if not f.suppressed])

    def has_findings_at_or_above(self, threshold: str) -> bool:
        threshold_level = SEVERITY_ORDER.get(threshold, 0)
        for f in self.findings:
            if f.suppressed:
                continue
            if SEVERITY_ORDER.get(f.effective_severity, 0) >= threshold_level:
                return True
        return False


def scan_path(
    target: str | Path,
    *,
    config: str | Path | None = None,
    include_globs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    suppressions: set[tuple[str, str]] | None = None,
    baseline_findings: dict[str, set[str]] | None = None,
) -> ScanResult:
    """Scan a file or directory for the execution gap."""
    rules = load_rules(config)
    target = Path(target)
    files = _collect_files(target, include_globs, exclude_globs)
    findings: list[Finding] = []

    for filepath in files:
        rel = str(filepath.relative_to(target) if target.is_dir() else filepath.name)
        try:
            source = filepath.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(filepath))
        except (SyntaxError, UnicodeDecodeError):
            continue

        sink_findings = detect_sinks(tree, str(filepath), rules.sinks)
        for sf in sink_findings:
            reach = detect_reachability(tree, sf.line, rules.reachability)
            if reach.confidence == "none":
                continue  # not agent-reachable — skip

            guarded = is_guarded(tree, sf.line, rules.guard_patterns)
            if guarded:
                continue  # guarded — no finding

            severity = sf.severity
            if reach.confidence == "medium":
                severity = _downgrade_severity(severity)

            snippet_hash = _compute_snippet_hash(source, sf.line)

            finding = Finding(
                file=rel,
                line=sf.line,
                col=sf.col,
                rule_id=sf.rule_id,
                category=sf.category,
                severity=severity,
                confidence=reach.confidence,
                description=sf.description,
                call_text=sf.call_text,
                remediation=_remediation_hint(sf.category),
                snippet_hash=snippet_hash,
            )

            # Check inline suppression
            if suppressions and (rel, sf.rule_id) in suppressions:
                finding.suppressed = True

            # Check baseline
            if baseline_findings:
                file_baselines = baseline_findings.get(rel, set())
                if snippet_hash in file_baselines:
                    finding.suppressed = True

            findings.append(finding)

    return ScanResult(findings=findings, files_scanned=len(files), rules_used=rules)


def _collect_files(
    target: Path,
    include_globs: list[str] | None,
    exclude_globs: list[str] | None,
) -> list[Path]:
    """Collect .py files to scan, respecting include/exclude globs.

    When no --include globs are specified, ALL .py files in the target
    directory are scanned. Test files are skipped by default (test_*.py,
    *_test.py, files in tests/ or test/ directories) to reduce noise —
    use --include to override or --exclude to add patterns.
    """

    if target.is_file():
        return [target] if target.suffix == ".py" else []

    # Collect all .py files recursively
    all_py_files = list(target.rglob("*.py"))

    # If no include globs specified, scan all .py files (minus excludes)
    if not include_globs:
        include_globs = ["**/*.py"]

    # Default excludes: test files (unless user explicitly includes them)
    # We exclude test_*.py and *_test.py files, and conftest.py, but NOT
    # directories named tests/ (they may contain agent tool fixtures)
    default_excludes = [
        "*/tests/test_*.py", "*/test/test_*.py",
        "*/tests/*_test.py", "*/test/*_test.py",
        "tests/test_*.py", "test/test_*.py",
        "tests/*_test.py", "test/*_test.py",
        "test_*.py", "*_test.py",
        "*conftest.py",
    ]
    exclude = list(exclude_globs or [])

    # Only add default test excludes if the user didn't explicitly include test files
    if not any("test" in g.lower() for g in (include_globs or [])):
        exclude.extend(default_excludes)

    files = []
    for filepath in all_py_files:
        rel = filepath.relative_to(target)
        rel_str = str(rel)

        # Check excludes
        excluded = False
        for pattern in exclude:
            if _glob_match(rel_str, pattern):
                excluded = True
                break
        if excluded:
            continue

        # Check includes — if any include matches, the file is included
        included = False
        for pattern in include_globs:
            if _glob_match(rel_str, pattern):
                included = True
                break
        if included:
            files.append(filepath)

    return files


def _glob_match(rel_path: str, pattern: str) -> bool:
    """Match a relative path against a glob pattern.

    Handles ** patterns (recursive) that fnmatch doesn't support natively.
    """
    import fnmatch as _fnmatch

    # Normalize: **/*.py matches everything ending in .py
    if pattern == "**/*.py":
        return rel_path.endswith(".py")
    # Convert ** to a wildcard that fnmatch can handle
    normalized_pattern = pattern.replace("**/", "")
    return _fnmatch.fnmatch(rel_path, normalized_pattern) or _fnmatch.fnmatch(rel_path, pattern)


def _compute_snippet_hash(source: str, line: int) -> str:
    """Compute a normalized hash of the code snippet for baseline matching.

    This is resilient to line-number drift — it hashes the line content
    + surrounding context, not the line number.
    """
    import hashlib
    lines = source.splitlines()
    # Use the target line + 1 line of context above (if available)
    start = max(0, line - 2)
    end = min(len(lines), line)
    snippet = "\n".join(lines[start:end])
    # Normalize whitespace
    normalized = re.sub(r"\s+", " ", snippet.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _remediation_hint(category: str) -> str:
    """Provide remediation guidance with MULTIPLE routes (not Actenon-only).

    Each finding offers several remediation routes:
      1. Add an existing internal guard (if one exists but isn't recognised)
      2. Register the guard with Scan (so it's recognised in future scans)
      3. Use Actenon Kernel (proof verification at the edge)
      4. Use brokered Actenon protection (Permit + broker + adapter)
      5. Redesign the boundary (if the action shouldn't be reachable)
    """
    hints = {
        "payments": (
            "Guard this payment call before execution. Options: "
            "(1) add an existing internal authorization check, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel proof verification, "
            "(4) use brokered Actenon protection (Permit + adapter), "
            "(5) redesign the boundary if this action should not be agent-reachable."
        ),
        "data_destruction": (
            "Guard this destructive call before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
        "deployment": (
            "Guard this deployment call before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
        "access_control": (
            "Guard this access-control mutation before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
        "communication": (
            "Guard this send-on-behalf call before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
        "provider_sdk": (
            "Guard this provider SDK call before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection (adapter wraps the SDK), "
            "(5) redesign the boundary."
        ),
        "database_mutation": (
            "Guard this database mutation before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
        "identity_change": (
            "Guard this identity/IAM mutation before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
    }
    return hints.get(category, (
        "Guard this action before execution. Options: "
        "(1) add an existing internal guard, "
        "(2) register it with scan --config, "
        "(3) use Actenon Kernel, "
        "(4) use brokered Actenon protection, "
        "(5) redesign the boundary."
    ))
