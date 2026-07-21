"""Scan engine — orchestrates AST parsing, sink detection, reachability, and guard checks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    """Collect .py files to scan, respecting include/exclude globs."""
    import fnmatch

    if target.is_file():
        return [target] if target.suffix == ".py" else []

    include = include_globs or ["**/*.py"]
    exclude = exclude_globs or []
    files = []
    for filepath in target.rglob("*.py"):
        rel = filepath.relative_to(target)
        rel_str = str(rel)

        # Check excludes
        excluded = False
        for pattern in exclude:
            if fnmatch.fnmatch(rel_str, pattern):
                excluded = True
                break
        if excluded:
            continue

        # Check includes
        included = False
        for pattern in include:
            if fnmatch.fnmatch(rel_str, pattern):
                included = True
                break
        if included:
            files.append(filepath)

    return files


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
    hints = {
        "payments": "Guard this payment call with actenon proof verification before execution. See: https://github.com/Actenon/actenon-permit",
        "data_destruction": "Guard this destructive call with actenon proof verification. See: https://github.com/Actenon/actenon-permit",
        "deployment": "Guard this deployment call with actenon proof verification. See: https://github.com/Actenon/actenon-permit",
        "access_control": "Guard this access-control mutation with actenon proof verification. See: https://github.com/Actenon/actenon-permit",
        "communication": "Guard this send-on-behalf call with actenon proof verification. See: https://github.com/Actenon/actenon-permit",
    }
    return hints.get(category, "Guard this action with actenon proof verification. See: https://github.com/Actenon/actenon-kernel")
