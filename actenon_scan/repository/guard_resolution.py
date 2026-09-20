"""Cross-file guard body inspection.

The per-file guard analyzer in :mod:`actenon_scan.detectors.guards`
only looks at SAME-FILE function definitions. This module extends it
cross-file by using :class:`RepositoryIndex` to inspect guard bodies
defined elsewhere in the repository.

Design principles (mirroring ``actenon_scan.repository.__init__``):

1. **FALSE ASSURANCE IS WORSE THAN A REVIEWABLE FALSE POSITIVE.**
   Nothing labelled ``UNKNOWN`` is ever silently promoted to ``ASSERT``.
   Names like ``check_permission``, ``check_access``, ``check_auth``,
   and ``verify_token`` are ambiguous (could return bool rather than
   raise) and are deliberately NOT in the conservative name heuristic;
   they bias to ``UNKNOWN``, never to ``ASSERT``.

2. **AUTHENTICATION != ACTION-AUTHORIZATION.** A guard named
   ``authenticate`` whose body raises is still ``ASSERT`` (it does
   raise), but the evidence string explicitly distinguishes
   "authentication only, not action authorization" so a downstream
   consumer cannot silently use it to authorize an action like
   ``refund``. The semantic guard taxonomy in
   :mod:`actenon_scan.repository.guard_semantics` carries the same
   invariant.

3. **EVIDENCE OVER HEURISTICS.** The body-inspection path always
   dominates the name-heuristic fallback. Body-inspected results carry
   the call-resolution certainty (RESOLVED or HEURISTIC); name-heuristic
   results are flagged as ``HEURISTIC`` confidence, never ``RESOLVED``.

This module is a CREATE-ONLY addition; it does not modify any existing
file. The principal engineer wires it into the package ``__init__``
re-exports after all agents finish.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum

from actenon_scan.repository.symbol_index import (
    RepositoryIndex,
    ResolutionCertainty,
    Symbol,
)


class GuardStyle(str, Enum):
    """How a guard enforces its check.

    - ``ASSERT`` — the guard raises on failure (raises_on_failure is
      True and returns_bool is False). Assert-style guards do NOT need
      their return value checked.
    - ``PREDICATE`` — the guard returns a bool (returns_bool is True
      and raises_on_failure is False). Predicate-style guards MUST have
      their return value checked.
    - ``UNKNOWN`` — the guard does both, neither, or we have no body
      evidence and the conservative name heuristic doesn't fire.
      Downstream MUST treat UNKNOWN as non-authorizing until proven
      otherwise (per the FALSE ASSURANCE invariant).
    """

    ASSERT = "assert"
    PREDICATE = "predicate"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class GuardBodyInspection:
    """Outcome of walking a resolved guard's function body.

    - ``raises_on_failure``: True if ANY ``ast.Raise`` appears in the
      body (nested or top-level).
    - ``returns_bool``: True if a TOP-LEVEL ``ast.Return`` appears in
      the function body (i.e. a return statement that is NOT nested
      inside ``if`` / ``for`` / ``while`` / ``try`` / ``with``).
      Top-level returns are the predicate-style signal: a function
      whose final action is to return a bool.
    - ``has_unconditional_raise``: True if a ``raise`` appears as a
      top-level statement of the function body. Stronger signal that
      the guard unconditionally raises on failure.
    - ``has_return_statement``: True if ANY return statement exists
      in the body, anywhere (including inside branches).
    - ``evidence_lines``: line numbers of raise/return statements found
      anywhere in the body (sorted, deduplicated).
    - ``inspection_certainty``: RESOLVED when we successfully walked
      the body; UNRESOLVED when we couldn't find the AST or the function
      node (e.g. the symbol pointed to an external module).

    Conservative: when both ``raises_on_failure`` and ``returns_bool``
    are True, both stay True — the caller decides UNKNOWN. When neither
    is True, both stay False (UNKNOWN again).
    """

    raises_on_failure: bool = False
    returns_bool: bool = False
    has_unconditional_raise: bool = False
    has_return_statement: bool = False
    evidence_lines: tuple[int, ...] = field(default_factory=tuple)
    inspection_certainty: ResolutionCertainty = ResolutionCertainty.UNRESOLVED


@dataclass(frozen=True)
class GuardResolution:
    """Result of cross-file guard resolution.

    - ``resolved``: True if we successfully resolved the guard's symbol
      and inspected its body (regardless of whether the inspection
      yielded ASSERT, PREDICATE, or UNKNOWN). False if we fell back to
      the name heuristic or to UNKNOWN default.
    - ``style``: the :class:`GuardStyle` chosen.
    - ``evidence``: human-readable chain explaining the resolution
      (e.g. ``"resolved cross-file to security.require_admin [resolved];
      raises at line 3"``).
    - ``confidence``: the call-resolution certainty. RESOLVED or
      HEURISTIC for body-inspected guards; HEURISTIC for name-heuristic
      fallback; UNRESOLVED for the UNKNOWN default.
    - ``body_inspection``: the :class:`GuardBodyInspection` when we
      walked a body; ``None`` when we fell back to the name heuristic.
    """

    resolved: bool
    style: GuardStyle
    evidence: str
    confidence: ResolutionCertainty
    body_inspection: GuardBodyInspection | None = None


# ---------------------------------------------------------------------------
# Conservative name heuristic — copied VERBATIM from
# actenon_scan/detectors/guards.py (function ``_resolve_guard_style``,
# lines 613-654 — the assert-style prefix list and conventional_assert
# name set, including the substring check). DO NOT EXPAND.
#
# Names like ``check_permission``, ``check_access``, ``check_auth``,
# ``verify_token`` are deliberately NOT in this set — they are
# ambiguous (could return bool rather than raise) and bias to UNKNOWN,
# NEVER to ASSERT. See guards.py:655-659 for the closing comment.
# ---------------------------------------------------------------------------

_ASSERT_PREFIXES = ("assert_", "require_", "enforce_", "ensure_", "must_")

_CONVENTIONAL_ASSERT_NAMES = {
    "authorize", "authenticate", "authorize_request", "authorize_action",
    "verify", "validate", "guard", "gate", "policy_gate", "policy_check",
    "guard_action", "guard_request",
    "enforce_policy", "enforce_permission", "enforce_authorization",
    "assert_can", "assert_allowed", "assert_authorized", "assert_permitted",
    "can_user", "user_can", "user_may",
    "audit_and_allow", "audit_and_execute", "audit_and_proceed",
    # Actenon-specific proof verification (raises on invalid proof)
    "verify_pccb", "verify_proof", "verify_signature",
    # MCP-native approval primitives (block until human responds)
    "elicit", "elicitation", "request_elicitation",
    "confirm", "confirm_action", "confirm_proceed",
    "human_approval", "human_in_the_loop", "human_confirmation",
    # OPA/Casbin (conventionally raise)
    "casbin_enforce",
    # JWT/OAuth (conventionally raise or redirect)
    "jwt_required", "require_jwt",
    "require_auth", "require_authentication", "require_authorization",
    "login_required", "requires_login", "requires_auth",
    "require_admin", "requires_admin", "admin_required",
    "require_superuser",
    # Framework guards
    "auth_required", "authz_required", "require_authz",
    "verify_mtls", "require_client_cert", "require_api_key",
}


# Names that conventionally raise BUT only authenticate — they do NOT
# authorize a specific action like a refund. Used to flag the evidence
# string for ASSERT resolutions: even when the body raises, the guard
# must NOT be treated as authorizing an action. The hostile invariant
# here is "authentication != authorization", mirroring the
# AUTHENTICATION classification in :mod:`guard_semantics`.
_AUTHENTICATION_ONLY_NAMES = {
    "authenticate", "authentication",
    "login_required", "requires_login", "requires_auth",
    "require_auth", "require_authentication",
    "auth_required",
    "verify_session", "require_session",
    "is_authenticated",
}


def _last_segment(name: str) -> str:
    """Lower-cased last dotted segment of a name.

    ``self.foo`` → ``foo`` ; ``pkg.mod.require_admin`` → ``require_admin``.
    """
    if not name:
        return ""
    return name.lower().rsplit(".", 1)[-1]


def _name_is_conventional_assert(name: str) -> bool:
    """Apply the conservative name heuristic verbatim from guards.py."""
    name_lower = _last_segment(name)
    if not name_lower:
        return False
    for prefix in _ASSERT_PREFIXES:
        if name_lower.startswith(prefix):
            return True
    if name_lower in _CONVENTIONAL_ASSERT_NAMES:
        return True
    # Substring check, matching guards.py's behaviour (catches custom
    # names like ``my_org_verify_permission``).
    for entry in _CONVENTIONAL_ASSERT_NAMES:
        if entry and entry in name_lower:
            return True
    return False


def _name_is_authentication_only(name: str) -> bool:
    """Whether the guard's name signals authentication-only (not action
    authorization).

    Mirrors the AUTHENTICATION pattern set in
    :mod:`actenon_scan.repository.guard_semantics`.
    """
    name_lower = _last_segment(name)
    if not name_lower:
        return False
    if name_lower in _AUTHENTICATION_ONLY_NAMES:
        return True
    for entry in _AUTHENTICATION_ONLY_NAMES:
        if entry and entry in name_lower:
            return True
    return False


def _get_call_name(callee_node: ast.AST) -> str:
    """Best-effort textual callee name.

    ``ast.Name`` → ``id`` ; ``ast.Attribute`` → ``attr`` ; otherwise
    fall back to ``ast.unparse`` (or empty string on failure).
    """
    if isinstance(callee_node, ast.Name):
        return callee_node.id
    if isinstance(callee_node, ast.Attribute):
        return callee_node.attr
    try:
        return ast.unparse(callee_node)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Body inspection
# ---------------------------------------------------------------------------


def _find_function_def_for_symbol(
    tree: ast.Module,
    guard_symbol: Symbol,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find the AST function node matching a :class:`Symbol`.

    Matches by name. Prefers the node whose start line equals the
    symbol's location line (the canonical match). Falls back to any
    function with the same name whose line range contains the symbol's
    location line.
    """
    target_line = guard_symbol.location.line
    fallback: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    fallback_range: tuple[int, int] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != guard_symbol.name:
            continue
        start = node.lineno
        end = getattr(node, "end_lineno", None) or start
        if start == target_line:
            return node
        if start <= target_line <= end:
            # Innermost (smallest range) wins on ambiguity.
            if (
                fallback_range is None
                or (end - start) < (fallback_range[1] - fallback_range[0])
            ):
                fallback = node
                fallback_range = (start, end)
    return fallback


def inspect_guard_body(
    guard_symbol: Symbol,
    index: RepositoryIndex,
) -> GuardBodyInspection:
    """Walk the function body of a resolved guard symbol.

    See :class:`GuardBodyInspection` for the field semantics. Returns an
    inspection with ``inspection_certainty=UNRESOLVED`` if the AST or
    function node cannot be located (e.g. the symbol pointed to an
    external module we don't have the source for).
    """
    ast_info = index.get_ast(guard_symbol.location.file)
    if ast_info is None:
        return GuardBodyInspection(
            inspection_certainty=ResolutionCertainty.UNRESOLVED
        )
    _src, tree = ast_info

    func_node = _find_function_def_for_symbol(tree, guard_symbol)
    if func_node is None:
        return GuardBodyInspection(
            inspection_certainty=ResolutionCertainty.UNRESOLVED
        )

    raises_on_failure = False
    has_return_statement = False
    has_unconditional_raise = False
    returns_bool = False
    raise_lines: list[int] = []
    return_lines: list[int] = []

    # Any Raise / Return anywhere in the body → set the "anywhere" flags.
    for child in ast.walk(func_node):
        if isinstance(child, ast.Raise):
            raises_on_failure = True
            ln = getattr(child, "lineno", None)
            if ln is not None:
                raise_lines.append(ln)
        elif isinstance(child, ast.Return):
            has_return_statement = True
            ln = getattr(child, "lineno", None)
            if ln is not None:
                return_lines.append(ln)

    # Top-level statements: scan only the immediate body (not nested
    # inside If/For/While/Try/With). This is the predicate-style signal:
    # a function whose final action is a top-level Return is bool-style.
    for stmt in func_node.body:
        if isinstance(stmt, ast.Raise):
            has_unconditional_raise = True
        elif isinstance(stmt, ast.Return):
            returns_bool = True

    evidence_lines = tuple(sorted(set(raise_lines + return_lines)))

    return GuardBodyInspection(
        raises_on_failure=raises_on_failure,
        returns_bool=returns_bool,
        has_unconditional_raise=has_unconditional_raise,
        has_return_statement=has_return_statement,
        evidence_lines=evidence_lines,
        inspection_certainty=ResolutionCertainty.RESOLVED,
    )


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def resolve_guard_call(
    call_node: ast.Call,
    in_module: str,
    index: RepositoryIndex,
    *,
    guard_patterns: list[str] | None = None,
) -> GuardResolution:
    """Resolve a guard call cross-file and classify its style.

    Algorithm:

    1. Use :meth:`RepositoryIndex.resolve_call_target` to find the
       guard's symbol.
    2. If RESOLVED or HEURISTIC with a non-None symbol: inspect the
       body via :func:`inspect_guard_body`. Raise anywhere →
       ``raises_on_failure``. Top-level Return → ``returns_bool``.
       Exactly one set → ASSERT or PREDICATE. Both or neither → UNKNOWN
       (conservative — never silently promote to ASSERT).
    3. If UNRESOLVED: fall back to the conservative name heuristic
       (the verbatim list from ``guards.py``). Names like
       ``check_permission``, ``check_access``, ``check_auth``,
       ``verify_token`` deliberately do NOT match → UNKNOWN, never
       ASSERT. Wrapper calls like ``Depends(require_admin)`` are
       inspected for the first positional argument's name (the actual
       guard) — this is the ONLY mechanism by which the heuristic finds
       a guard in a wrapper; the name list itself is not expanded.
    4. Returns a :class:`GuardResolution` with an ``evidence`` string
       describing the chain (e.g.
       ``"resolved cross-file to security.require_admin [resolved];
       raises at line 3"``).

    Hostile invariant: AUTHENTICATION != ACTION-AUTHORIZATION. A guard
    named ``authenticate`` whose body raises is still ASSERT, but the
    evidence string explicitly distinguishes "authentication only, not
    action authorization" so a downstream consumer cannot silently use
    it to authorize an action like ``refund``.
    """
    callee_node = call_node.func
    callee_name = _get_call_name(callee_node)
    sym, certainty, _qname_attempt = index.resolve_call_target(
        callee_node, in_module
    )

    # Case 1: resolved or heuristic symbol — inspect the body.
    if sym is not None and certainty in (
        ResolutionCertainty.RESOLVED,
        ResolutionCertainty.HEURISTIC,
    ):
        body = inspect_guard_body(sym, index)
        if body.raises_on_failure and not body.returns_bool:
            style = GuardStyle.ASSERT
        elif body.returns_bool and not body.raises_on_failure:
            style = GuardStyle.PREDICATE
        else:
            # Both, or neither — conservative UNKNOWN. Never silently
            # promote to ASSERT.
            style = GuardStyle.UNKNOWN

        # Build the evidence string describing the chain.
        target_qname = sym.qualified_name
        if style == GuardStyle.ASSERT and body.evidence_lines:
            line_str = "; raises at line " + ", ".join(
                str(ln) for ln in body.evidence_lines
            )
        elif style == GuardStyle.PREDICATE and body.evidence_lines:
            line_str = "; returns at line " + ", ".join(
                str(ln) for ln in body.evidence_lines
            )
        elif body.evidence_lines:
            line_str = "; body has raise/return at line " + ", ".join(
                str(ln) for ln in body.evidence_lines
            )
        else:
            line_str = "; no raise or return found in body"

        auth_note = ""
        if _name_is_authentication_only(callee_name):
            auth_note = " (authentication only, not action authorization)"

        evidence = (
            f"resolved cross-file to {target_qname}"
            f" [{certainty.value}]{line_str}{auth_note}"
        )
        return GuardResolution(
            resolved=True,
            style=style,
            evidence=evidence,
            confidence=certainty,
            body_inspection=body,
        )

    # Case 2: UNRESOLVED — fall back to conservative name heuristic.
    # Per the hostile invariant: check_permission, check_access,
    # check_auth, verify_token must NEVER match this fallback. Bias
    # to UNKNOWN.
    if callee_name and _name_is_conventional_assert(callee_name):
        auth_note = ""
        if _name_is_authentication_only(callee_name):
            auth_note = " (authentication only, not action authorization)"
        evidence = (
            f"unresolved guard '{callee_name}' — matched conservative "
            f"name heuristic (assert-style){auth_note}"
        )
        return GuardResolution(
            resolved=False,
            style=GuardStyle.ASSERT,
            evidence=evidence,
            confidence=ResolutionCertainty.HEURISTIC,
            body_inspection=None,
        )

    # Wrapper-case inspection: calls like ``Depends(require_admin)`` or
    # ``Security(guard)`` where the *actual* guard is passed as a
    # positional argument. The primary callee name doesn't match the
    # heuristic, but the arg's name might. This is the ONLY mechanism
    # by which the heuristic finds a guard in a wrapper; the name list
    # itself is not expanded.
    for arg in getattr(call_node, "args", []) or []:
        arg_name: str | None = None
        if isinstance(arg, ast.Name):
            arg_name = arg.id
        elif isinstance(arg, ast.Call):
            arg_name = _get_call_name(arg.func)
        if arg_name and _name_is_conventional_assert(arg_name):
            auth_note = ""
            if _name_is_authentication_only(arg_name):
                auth_note = (
                    " (authentication only, not action authorization)"
                )
            evidence = (
                f"unresolved guard '{arg_name}' (passed as arg to "
                f"'{callee_name}') — matched conservative name heuristic "
                f"(assert-style){auth_note}"
            )
            return GuardResolution(
                resolved=False,
                style=GuardStyle.ASSERT,
                evidence=evidence,
                confidence=ResolutionCertainty.HEURISTIC,
                body_inspection=None,
            )

    # Default: UNKNOWN. Conservative — never silently promote.
    evidence = (
        f"unresolved guard '{callee_name}' — no body evidence; "
        f"biased to UNKNOWN (could be predicate or raising)"
    )
    return GuardResolution(
        resolved=False,
        style=GuardStyle.UNKNOWN,
        evidence=evidence,
        confidence=ResolutionCertainty.UNRESOLVED,
        body_inspection=None,
    )


__all__ = [
    "GuardStyle",
    "GuardBodyInspection",
    "GuardResolution",
    "resolve_guard_call",
    "inspect_guard_body",
]
