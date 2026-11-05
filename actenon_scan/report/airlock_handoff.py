"""Scan -> Airlock handoff: the optional runtime alternative to a repository-native guard.

Scan's own remediation (``actenon-scan fix``, a repository-native guard) stays the default. For the
one consequence that has been exercised end to end with Actenon Airlock, a Python GitHub file
write (``github.contents.write``), Scan also says what Airlock would do with the finding and what
the developer would have to change first. Everything else gets no handoff.

The handoff is derived from :func:`actenon_scan.authority.extract_authority`: the structured
evidence Airlock compiles its runtime authority from. Scan never guesses a resource here, never
imports or installs Airlock, and never approves anything. Discovery and authorisation stay
separate: ``airlock init`` only proposes, and approval is a separate explicit step.

What the wording relies on (Airlock Local Mode, checked against the Airlock implementation):

* a RESOLVED ``github.contents.write`` power is shown by ``airlock init`` and stays blocked until
  ``airlock init --approve``; ``airlock run`` then denies calls outside the approved power (for
  example the same tool aimed at another repository) with a signed receipt;
* UNRESOLVED and TEMPLATE targets stay blocked even after approval;
* Local Mode enforces approval but does not verify the outcome on GitHub, and it is cooperative
  Python interception, not a sandbox. Independent readback exists only for Airlock's Protected
  Mode GitHub create-only profile, which needs Docker and a separately reviewed profile, so it is
  described in the guide rather than as a few commands.
"""

from __future__ import annotations

import ast
import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

#: The only Airlock power kinds this handoff may recommend. Extend only with end-to-end evidence
#: that Airlock holds, approves and refuses the action as the wording below says.
SUPPORTED_ACTIONS = frozenset({"github.contents.write"})

#: Scan finding categories that can map to a supported action. Used to skip authority extraction
#: for findings the handoff could never apply to.
SUPPORTED_FINDING_CATEGORIES = frozenset({"repository_mutation"})

#: Airlock is not published to a package registry yet. Keep this in step with the Airlock README.
AIRLOCK_INSTALL = 'pip install "git+https://github.com/Actenon/actenon-airlock.git"'
AIRLOCK_GUIDE = "https://github.com/Actenon/actenon-scan/blob/main/docs/AIRLOCK.md"

_ENTRY_PLACEHOLDER = "<entry>"


@dataclass(frozen=True)
class AirlockHandoff:
    """What Airlock would do with one finding, from Scan's authority evidence."""

    action: str
    resource: str | None
    state: str  # RESOLVED | TEMPLATE | UNRESOLVED
    unresolved_parts: tuple[str, ...]
    template_params: tuple[str, ...]
    #: How the unknown part of the target is chosen, e.g. "parameter `repo` of tool `publish`".
    target_origins: tuple[str, ...]
    #: True when at least one origin is a parameter of the agent tool itself (the model picks it).
    model_chooses_target: bool
    #: The script to hand to ``airlock init --command``, when the finding's file is runnable.
    entry_script: str | None

    @property
    def approvable(self) -> bool:
        return self.state == "RESOLVED" and self.resource is not None


def scan_command() -> str:
    """The command a user should type to run this scanner again.

    ``uvx actenon-scan`` runs from a throwaway environment in uv's cache. uvx puts that
    environment's ``bin`` on PATH only for the child process, so after Scan exits the user's shell
    has no ``actenon-scan`` (or an older one). The follow-up commands must also go through uvx.
    ``uv tool install`` and project virtualenvs live outside the cache and keep the plain command.
    """
    if os.environ.get("UV") and _in_uv_cache(sys.prefix):
        return "uvx actenon-scan"
    return "actenon-scan"


def _in_uv_cache(prefix: str) -> bool:
    if "archive-v0" in Path(prefix).parts:
        return True
    cache = os.environ.get("UV_CACHE_DIR")
    if not cache:
        return False
    try:
        Path(prefix).resolve().relative_to(Path(cache).resolve())
    except ValueError:
        return False
    return True


def find_airlock_handoff(
    root: str | os.PathLike[str], file: str, line: int, *, category: str | None = None
) -> AirlockHandoff | None:
    """The Airlock handoff for the finding at ``file:line`` under ``root``, or None.

    ``file`` is relative to ``root``, as Scan reports it. ``category`` is the finding's category;
    when given, findings outside :data:`SUPPORTED_FINDING_CATEGORIES` are rejected before any
    analysis runs. Never raises: any analysis failure means no handoff, and the rest of the report
    is unaffected.
    """
    if not file.endswith(".py"):
        return None
    if category is not None and category not in SUPPORTED_FINDING_CATEGORIES:
        return None
    try:
        from actenon_scan.authority import extract_authority

        report = extract_authority(root)
    except Exception:  # noqa: BLE001 - an optional hint must never break the scan report
        return None
    return handoff_from_evidence(report.evidence, root, file, line)


def handoff_from_evidence(
    evidence: Iterable, root: str | os.PathLike[str], file: str, line: int
) -> AirlockHandoff | None:
    """Build a handoff from already-extracted authority evidence (see :func:`find_airlock_handoff`)."""
    wanted = _normalise(file)
    candidates = [
        ev
        for ev in evidence
        if _normalise(ev.file) == wanted
        and ev.line <= line <= max(ev.line, ev.end_line)
        and ev.action in SUPPORTED_ACTIONS
    ]
    if not candidates:
        return None
    # Prefer the least-resolved evidence: if any part of this call's target is unknown, say so.
    order = {"UNRESOLVED": 0, "TEMPLATE": 1, "RESOLVED": 2}
    ev = min(candidates, key=lambda e: (order.get(str(e.resource_state), 0), e.col))
    state = str(ev.resource_state)

    origins: list[str] = []
    model_chooses = False
    if state != "RESOLVED":
        for src in ev.sources:
            if src.kind == "parameter" and src.name:
                owner = src.detail or ev.function
                if ev.tool_entry and owner == ev.function:
                    model_chooses = True
                    origins.append(f"parameter `{src.name}` of tool `{owner}`")
                else:
                    origins.append(f"parameter `{src.name}` of `{owner}`")
            elif src.kind in ("env", "config") and src.name:
                origins.append(f"{src.kind} value `{src.name}`")
        origins = list(dict.fromkeys(origins))

    return AirlockHandoff(
        action=ev.action,
        resource=ev.resource,
        state=state,
        unresolved_parts=tuple(ev.unresolved_parts),
        template_params=tuple(ev.template_params),
        target_origins=tuple(origins),
        model_chooses_target=model_chooses,
        entry_script=ev.file if _has_main_block(Path(root) / ev.file) else None,
    )


def target_line(h: AirlockHandoff) -> str:
    """One line naming the finding's target as far as Scan resolved it."""
    if h.approvable:
        return f"{h.resource}"
    what = ", ".join(h.unresolved_parts) or "target"
    if h.state == "TEMPLATE":
        segs = ", ".join(h.template_params) or "a path segment"
        return f"{h.resource} (varies with {segs})"
    if h.model_chooses_target:
        return f"{what} chosen by the model ({', '.join(h.target_origins)})"
    if h.target_origins:
        return f"{what} not fixed in code ({', '.join(h.target_origins)})"
    return f"{what} not known before the call runs"


def format_handoff(h: AirlockHandoff, *, indent: str = "  ") -> list[str]:
    """Render the optional Airlock remediation as report lines (no trailing blank line)."""
    script = h.entry_script or _ENTRY_PLACEHOLDER
    part = h.unresolved_parts[0] if h.unresolved_parts else "target"
    lines = ["Optional: enforce it at runtime with Actenon Airlock (pre-release; Python; Local Mode)"]
    if h.approvable:
        lines += [
            f"{indent}Airlock power:  {h.action} on {h.resource}",
            f"{indent}Finding this approves nothing. Airlock blocks the write until you approve",
            f"{indent}that exact power, then refuses calls outside it with a signed receipt.",
        ]
        commands = [
            (AIRLOCK_INSTALL, ""),
            (f"airlock init --command {script}", "review: proposes, grants nothing"),
            (f"airlock init --approve --command {script}", "you approve the shown power"),
            (f"airlock run -- {script}", "run with approved powers only"),
        ]
    else:
        if h.state == "TEMPLATE":
            reason = f"{indent}Not yet: Airlock keeps a write with a variable target blocked, even after approval."
        elif h.model_chooses_target:
            reason = (
                f"{indent}Not yet: the model chooses the {part}, and Airlock will not approve a write\n"
                f"{indent}whose target the model chooses. It keeps this call blocked, even after approval."
            )
        else:
            reason = f"{indent}Not yet: Airlock keeps a write with an unresolved {part} blocked, even after approval."
        lines += reason.split("\n")
        lines += [
            f"{indent}Use the repository-native guard above, or fix the {part} in code or project",
            f"{indent}configuration (.env) and review the exact power Airlock would then grant:",
        ]
        commands = [(AIRLOCK_INSTALL, ""), (f"airlock init --command {script}", "review only; approves nothing")]
    if h.entry_script is None:
        lines.append(f"{indent}(Replace {_ENTRY_PLACEHOLDER} with the script that starts your agent.)")
    lines.append(f"{indent}In your agent's Python environment:")
    width = max(len(cmd) for cmd, note in commands if note)
    for cmd, note in commands:
        lines.append(f"{indent}  {cmd.ljust(width)}  # {note}" if note else f"{indent}  {cmd}")
    if h.approvable:
        lines.append(f"{indent}Keep GITHUB_TOKEN in the shell that runs airlock: the agent gets an opaque handle.")
    lines += [
        f"{indent}Local Mode enforces approval; it does not verify the outcome on GitHub, and it is",
        f"{indent}cooperative Python interception, not a sandbox. Verified GitHub file creation",
        f"{indent}(Protected Mode, Docker, reviewed profile) and current limits: {AIRLOCK_GUIDE}",
    ]
    return lines


def _normalise(path: str) -> str:
    return Path(path).as_posix().removeprefix("./") if path else ""


def _has_main_block(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError, UnicodeDecodeError):
        return False
    return any(isinstance(node, ast.If) and _is_main_guard(node.test) for node in ast.walk(tree))


def _is_main_guard(test: ast.expr) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
        return False
    sides = [test.left, *test.comparators]
    names = [s for s in sides if isinstance(s, ast.Name) and s.id == "__name__"]
    consts = [s for s in sides if isinstance(s, ast.Constant) and s.value == "__main__"]
    return bool(names and consts)
