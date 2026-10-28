"""Authority diffing and AIRLOCK AUTHORITY DIFF formatting.

Compares two ``AuthorityReport`` instances (or directory paths) to show exact consequential powers added,
removed, or left unresolved, distinguishing ``RESOLVED`` paths from ``HEURISTIC`` evidence and never widening
dynamic unknowns to ``*``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from .model import AuthorityEvidence, AuthorityReport, ResourceState
from .python import extract_authority


def _evidence_tag(ev: AuthorityEvidence) -> str:
    """Classify evidence mode for human/CI review without ever widening unknowns."""
    is_heuristic = any(s.kind == "heuristic" for s in ev.sources) or ev.confidence == "low"
    if ev.resource_state is ResourceState.RESOLVED and ev.resource:
        return "HEURISTIC" if is_heuristic else "RESOLVED"
    if ev.resource_state is ResourceState.TEMPLATE and ev.resource:
        return "TEMPLATE"
    return "HEURISTIC" if is_heuristic else "UNRESOLVED"


def _diff_key(ev: AuthorityEvidence) -> tuple[str, str, str]:
    resource_key = ev.resource if ev.resource is not None else f"<unresolved:{ev.file}:{ev.line}>"
    return (ev.action, resource_key, ev.resource_state.value)


@dataclass
class AuthorityDiff:
    added: list[AuthorityEvidence] = field(default_factory=list)
    removed: list[AuthorityEvidence] = field(default_factory=list)
    unchanged: list[AuthorityEvidence] = field(default_factory=list)
    unresolved: list[AuthorityEvidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "actenon-scan/authority-diff/v1",
            "added": [
                {**ev.to_dict(), "evidence_mode": _evidence_tag(ev)}
                for ev in self.added
            ],
            "removed": [
                {**ev.to_dict(), "evidence_mode": _evidence_tag(ev)}
                for ev in self.removed
            ],
            "unchanged": [
                {**ev.to_dict(), "evidence_mode": _evidence_tag(ev)}
                for ev in self.unchanged
            ],
            "unresolved": [
                {**ev.to_dict(), "evidence_mode": _evidence_tag(ev)}
                for ev in self.unresolved
            ],
        }


def _coerce_report(
    source: AuthorityReport | str | os.PathLike[str] | None,
    *,
    env: dict[str, str] | None = None,
    include_tests: bool = False,
    read_env_files: bool = True,
) -> AuthorityReport:
    if source is None:
        return AuthorityReport(root="")
    if isinstance(source, AuthorityReport):
        return source
    return extract_authority(
        source,
        env=env,
        include_tests=include_tests,
        read_env_files=read_env_files,
    )


def diff_authority(
    before: AuthorityReport | str | os.PathLike[str] | None,
    after: AuthorityReport | str | os.PathLike[str],
    *,
    env: dict[str, str] | None = None,
    include_tests: bool = False,
    read_env_files: bool = True,
) -> AuthorityDiff:
    """Compute the authority diff between ``before`` and ``after``."""
    before_report = _coerce_report(
        before, env=env, include_tests=include_tests, read_env_files=read_env_files
    )
    after_report = _coerce_report(
        after, env=env, include_tests=include_tests, read_env_files=read_env_files
    )

    before_map: dict[tuple[str, str, str], AuthorityEvidence] = {}
    for ev in before_report.evidence:
        before_map.setdefault(_diff_key(ev), ev)

    after_map: dict[tuple[str, str, str], AuthorityEvidence] = {}
    for ev in after_report.evidence:
        after_map.setdefault(_diff_key(ev), ev)

    added_keys = sorted(after_map.keys() - before_map.keys())
    removed_keys = sorted(before_map.keys() - after_map.keys())
    unchanged_keys = sorted(after_map.keys() & before_map.keys())

    added = [after_map[k] for k in added_keys]
    removed = [before_map[k] for k in removed_keys]
    unchanged = [after_map[k] for k in unchanged_keys]
    unresolved = [
        ev
        for ev in after_report.evidence
        if ev.resource_state is ResourceState.UNRESOLVED or ev.resource is None
    ]

    return AuthorityDiff(
        added=added,
        removed=removed,
        unchanged=unchanged,
        unresolved=unresolved,
    )


def format_authority_diff(diff: AuthorityDiff) -> str:
    """Format an ``AuthorityDiff`` as an ``AIRLOCK AUTHORITY DIFF`` block."""
    lines = ["AIRLOCK AUTHORITY DIFF"]
    for ev in diff.added:
        tag = _evidence_tag(ev)
        if ev.resource is not None and ev.resource_state is not ResourceState.UNRESOLVED:
            lines.append(
                f"+ {ev.action} {ev.resource} [{tag}] ({ev.file}:{ev.line} via {ev.via})"
            )
        else:
            parts = ", ".join(ev.unresolved_parts) or "target"
            lines.append(
                f"! {ev.action} UNRESOLVED ({parts}) [{tag} — never widened to *] ({ev.file}:{ev.line} via {ev.via})"
            )
    for ev in diff.removed:
        tag = _evidence_tag(ev)
        where = ev.resource if ev.resource is not None else "UNRESOLVED (" + (", ".join(ev.unresolved_parts) or "target") + ")"
        lines.append(
            f"- {ev.action} {where} [{tag}] ({ev.file}:{ev.line} via {ev.via})"
        )
    if not diff.added and not diff.removed:
        lines.append("No authority changes.")
    return "\n".join(lines)
