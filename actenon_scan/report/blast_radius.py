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

        Uses the final method name from each finding's call_text (the
        method actually being invoked) to give the reader a quick sense
        of what the agent can do. For chained calls like
        ``g.get_repo(repo).create_file(...)``, this extracts
        ``create_file`` rather than ``get_repo``.
        """
        methods: list[str] = []
        seen: set[str] = set()
        for f in self.findings:
            method = _extract_method_name(f.call_text)
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
#   1. has model-controlled inputs (findings WITH identified inputs rank
#      higher than those WITHOUT — a finding the model can actually
#      influence is more exposed than one with no model-controlled path)
#   2. severity (HIGH > MEDIUM > LOW)
#   3. confidence (high > medium > low)
#   4. destructive/irreversible consequence (DATA LOSS > others)
#   5. stable file/line ordering (final tie-break)
#
# Does NOT introduce arbitrary scoring. The ranking is purely ordinal.
#
# ITEM 1 (v1.1.3 audit): the "has model-controlled inputs" signal is
# computed from the same call-text parse that the pretty reporter's
# spotlight uses (_extract_params). The explain IR (build_brief) may
# find more parameters via AST analysis, but the ranking must agree
# with what the summary displays — not with a deeper analysis the user
# hasn't seen yet.
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}
_DESTRUCTIVE_LABELS = {"DATA LOSS", "DATABASE", "REPOSITORY"}


def _has_model_controlled_inputs(f: Finding) -> bool:
    """Check whether the finding has identified model-controlled inputs.

    Uses the same call-text parse as the pretty reporter's spotlight
    (_extract_params in pretty.py). This is intentionally the SAME source
    as what the user sees in the summary, not the deeper explain IR —
    the ranking must agree with the displayed information, not with an
    analysis the user hasn't seen yet.
    """
    # Inline the same logic as pretty._extract_params to avoid a circular
    # import (pretty imports from blast_radius).
    if "(" not in f.call_text:
        return False
    paren_start = f.call_text.index("(")
    depth = 0
    paren_end = len(f.call_text)
    for i in range(paren_start, len(f.call_text)):
        if f.call_text[i] == "(":
            depth += 1
        elif f.call_text[i] == ")":
            depth -= 1
            if depth == 0:
                paren_end = i
                break
    args_text = f.call_text[paren_start + 1 : paren_end]
    for arg in args_text.split(","):
        arg = arg.strip()
        if not arg:
            continue
        # Keyword arg with a name
        if "=" in arg:
            return True
        # Positional arg that's a simple identifier (not a literal)
        if arg.isidentifier():
            return True
    return False


def _most_exposed_rank(f: Finding) -> tuple[int, int, int, int, str, int]:
    """Sort key for the most-exposed ranking (lower = more exposed).

    1. has model-controlled inputs (findings WITH inputs first)
    2. severity (HIGH first)
    3. confidence (high first)
    4. destructive consequence (DATA LOSS/DATABASE/REPOSITORY first)
    5. file path (stable alphabetical)
    6. line number (stable ascending)
    """
    label = consequence_label(f.category)
    return (
        0 if _has_model_controlled_inputs(f) else 1,
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
    "See https://github.com/Actenon/actenon-scan/blob/main/docs/COVERAGE.md "
    "for supported architectures and analysis limits."
)


def _extract_method_name(call_text: str) -> str:
    """Extract the final method name from a call text.

    For chained calls, this returns the method actually being invoked
    (the one whose arguments are in the outermost parentheses), not an
    intermediate accessor.

    Examples:
        "g.get_repo(repo).create_file(...)"  -> "create_file"
        "smtp.sendmail(sender, recipients, body)" -> "sendmail"
        "requests.put(url, json=payload)"    -> "put"
        "WebClient('token').chat_postMessage(...)" -> "chat_postMessage"
        "subprocess.run(['kubectl', 'apply'])" -> "run"

    The algorithm finds the outermost opening paren (the last ``(`` at
    depth 0) and takes the last ``.``-separated segment before it. This
    correctly handles nested parens in chained accessor calls.
    """
    if not call_text:
        return ""
    # Find the outermost opening paren — the last ( at depth 0.
    depth = 0
    outer_paren_idx = -1
    for i, ch in enumerate(call_text):
        if ch == "(":
            if depth == 0:
                outer_paren_idx = i  # keep updating; we want the LAST at depth 0
            depth += 1
        elif ch == ")":
            depth -= 1
    if outer_paren_idx == -1:
        return call_text.strip()
    before = call_text[:outer_paren_idx]
    if "." in before:
        return before.rsplit(".", 1)[-1].strip()
    return before.strip()
