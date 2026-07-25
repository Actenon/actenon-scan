"""Blast-radius summary helpers.

Work Order 2, Part 1: the default output leads with a map of the
consequential actions an agent can reach without a dominating authority
check. This module provides the reusable grouping, ranking, and
consequence-labelling helpers consumed by:

  - the default pretty formatter (blast-radius summary)
  - the list formatter (old linter-style output, via --format list)
  - HTML and Markdown reports
  - PR comments

Design constraints:
  - RULE 5: detection must not change. These helpers only GROUP and
    RANK existing findings; they do not filter, add, or reclassify.
  - RULE 7: wording must not overstate impact. Use "No dominating
    authorization check was identified in the analysed path" rather
    than absolute claims.
  - Part 1.4: the most-exposed ranking is deterministic and documented.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from actenon_scan.engine import Finding, ScanResult


# ---------------------------------------------------------------------------
# Consequence labelling.
#
# Maps internal category names to user-facing consequence labels. Multiple
# internal categories can map to the same user-facing label (e.g.,
# `code_execution` and `shell_execution` both map to EXECUTION).
# ---------------------------------------------------------------------------

_CATEGORY_TO_LABEL: dict[str, str] = {
    "repository_mutation": "REPOSITORY",
    "vcs_mutation": "REPOSITORY",
    "payments": "MONEY",
    "data_destruction": "DATA LOSS",
    "database_mutation": "DATABASE",
    "code_execution": "EXECUTION",
    "shell_execution": "EXECUTION",
    "network_egress": "EGRESS",
    "communication": "MESSAGING",
    "identity_change": "IDENTITY",
    "access_control": "IDENTITY",
    "credential_access": "SECRETS",
    "file_mutation": "FILE",
    "browser_action": "BROWSER",
    "deployment": "DEPLOYMENT",
    "provider_sdk": "PROVIDER",
}


def consequence_label(category: str) -> str:
    """Map an internal category to a user-facing consequence label.

    Unknown categories fall back to the category uppercased.
    """
    return _CATEGORY_TO_LABEL.get(category, category.upper().replace("_", " "))


# Display order for consequence groups in the blast-radius summary.
# Groups not in this list are appended alphabetically.
_DISPLAY_ORDER = [
    "REPOSITORY",
    "MONEY",
    "DATA LOSS",
    "EXECUTION",
    "DATABASE",
    "EGRESS",
    "MESSAGING",
    "IDENTITY",
    "SECRETS",
    "DEPLOYMENT",
    "FILE",
    "BROWSER",
    "PROVIDER",
]


def _display_order_key(label: str) -> tuple[int, str]:
    """Sort key for consequence labels: known order first, then alphabetical."""
    try:
        idx = _DISPLAY_ORDER.index(label)
    except ValueError:
        idx = len(_DISPLAY_ORDER)
    return (idx, label)


# ---------------------------------------------------------------------------
# Blast-radius grouping.
# ---------------------------------------------------------------------------


@dataclass
class ConsequenceGroup:
    """A group of findings sharing a user-facing consequence label."""

    label: str
    findings: list[Finding]
    rule_ids: set[str]

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def method_summary(self) -> str:
        """A short comma-separated summary of the methods involved.

        Uses the last segment of each finding's call_text (the method
        name) to give the reader a quick sense of what the agent can do.
        """
        methods: list[str] = []
        seen: set[str] = set()
        for f in self.findings:
            # Extract the method name from the call text.
            # e.g., "g.get_repo(repo).create_file(...)" -> "create_file"
            call = f.call_text
            if "(" in call:
                before_paren = call[: call.index("(")]
                if "." in before_paren:
                    method = before_paren.rsplit(".", 1)[-1].strip()
                else:
                    method = before_paren.strip()
            else:
                method = call.strip()
            if method and method not in seen:
                seen.add(method)
                methods.append(method)
        return ", ".join(methods[:6])  # cap at 6 for width


def group_by_consequence(findings: list[Finding]) -> "OrderedDict[str, ConsequenceGroup]":
    """Group findings by user-facing consequence label.

    Returns an OrderedDict sorted by display order (known labels first,
    then alphabetical). Each group's findings are sorted by the
    most-exposed ranking (see `_most_exposed_rank`).
    """
    groups: dict[str, ConsequenceGroup] = {}
    for f in findings:
        label = consequence_label(f.category)
        if label not in groups:
            groups[label] = ConsequenceGroup(
                label=label, findings=[], rule_ids=set()
            )
        groups[label].findings.append(f)
        groups[label].rule_ids.add(f.rule_id)

    # Sort findings within each group by most-exposed rank.
    for g in groups.values():
        g.findings.sort(key=_most_exposed_rank)

    # Sort groups by display order.
    sorted_groups = OrderedDict(
        sorted(groups.items(), key=lambda kv: _display_order_key(kv[0]))
    )
    return sorted_groups


# ---------------------------------------------------------------------------
# Most-exposed ranking (Part 1.4).
#
# Deterministic ranking. Considers:
#   1. severity (HIGH > MEDIUM > LOW)
#   2. confidence (high > medium > low)
#   3. destructive/irreversible consequence (DATA LOSS > others)
#   4. stable file/line ordering (final tie-break)
#
# Does NOT introduce arbitrary scoring. The ranking is purely ordinal.
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}
_DESTRUCTIVE_LABELS = {"DATA LOSS", "DATABASE", "REPOSITORY"}


def _most_exposed_rank(f: Finding) -> tuple[int, int, int, str, int]:
    """Sort key for the most-exposed ranking (lower = more exposed).

    1. severity (HIGH first)
    2. confidence (high first)
    3. destructive consequence (DATA LOSS/DATABASE/REPOSITORY first)
    4. file path (stable alphabetical)
    5. line number (stable ascending)
    """
    label = consequence_label(f.category)
    return (
        _SEVERITY_RANK.get(f.severity, 3),
        _CONFIDENCE_RANK.get(f.confidence, 3),
        0 if label in _DESTRUCTIVE_LABELS else 1,
        f.file,
        f.line,
    )


def select_most_exposed(findings: list[Finding]) -> Finding | None:
    """Select the single most-exposed finding for the summary spotlight.

    Returns ``None`` when there are no findings.
    """
    if not findings:
        return None
    return min(findings, key=_most_exposed_rank)


# ---------------------------------------------------------------------------
# Honesty statement for clean scans (Part 1.5).
# ---------------------------------------------------------------------------

CLEAN_SCAN_STATEMENT = (
    "No supported unguarded consequential-action paths were identified."
)

CLEAN_SCAN_LIMITATIONS = (
    "What this scan verified: supported source files were parsed and analysed "
    "for agent-reachable consequential actions without a dominating authority "
    "check.\n"
    "What this scan did not verify: unsupported languages, files outside the "
    "scan target, guards outside the analysed path, external reachability, or "
    "practical exploitability.\n"
    "See docs/COVERAGE.md for supported architectures and analysis limits."
)
