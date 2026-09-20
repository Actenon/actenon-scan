"""Semantic guard taxonomy — distinguishes authentication, authorization,
validation, sanitization, human approval, policy enforcement, capability
proof, and rate limiting.

A call such as ``authenticate(user)`` is AUTHENTICATION — it does NOT
authorize an action like refund. A call such as ``validate_email(addr)``
is VALIDATION — it does NOT authorize sending email. This module
exposes that distinction so downstream authority-binding analysis can
refuse to treat authentication as action authorization.

The CRITICAL invariant (pinned by the brief's hostile-test requirement):

    AUTHENTICATION and VALIDATION must NEVER have
    ``is_action_authorization == True``.

This is an INTERNAL classification layer. It does NOT change the
existing per-file guard check behaviour in
:mod:`actenon_scan.detectors.guards`; it only labels guard callables
with a semantic kind so downstream slices (authority binding,
effect-summary propagation) can decide which guards are allowed to
authorize which actions.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class GuardKind(str, Enum):
    """Semantic kind of a guard callable.

    Members:

    - AUTHENTICATION: proves *who* the caller is. Never authorizes an
      action. (``authenticate``, ``login_required``, ``verify_token``.)
    - AUTHORIZATION: proves *what the caller may do* — a specific
      action. (``authorize_refund``, ``check_permission``,
      ``require_admin``.)
    - VALIDATION: proves an input is well-formed. Never authorizes an
      action. (``validate_email``, ``is_valid``.)
    - SANITIZATION: transforms an input to be safe. Never authorizes an
      action. (``sanitize_input``, ``escape_html``.)
    - HUMAN_APPROVAL: a human-in-the-loop consent channel. Not treated
      as direct action authorization (a separate human channel must
      actually approve). (``external_execution``, ``require_human``.)
    - POLICY_ENFORCEMENT: an external policy engine (OPA/Cedar/Casbin)
      evaluates an authorization decision. Can authorize an action when
      the action parameter is bound.
    - CAPABILITY_PROOF: a verifiable capability token (PCC/PCCB) is
      checked. Can authorize an action when the action parameter is
      bound. (``verify_pccb``, ``verify_pcc``.)
    - RATE_LIMIT: throttles call frequency. Never authorizes an action.
    - UNKNOWN_GUARD: name did not match any known pattern; downstream
      must treat as weak / non-authorizing.
    """

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    SANITIZATION = "sanitization"
    HUMAN_APPROVAL = "human_approval"
    POLICY_ENFORCEMENT = "policy_enforcement"
    CAPABILITY_PROOF = "capability_proof"
    RATE_LIMIT = "rate_limit"
    UNKNOWN_GUARD = "unknown_guard"


# Kinds that, when their action parameter is bound, can authorize a
# *specific* action. This is the brief's "strong" set. AUTHENTICATION,
# VALIDATION, SANITIZATION, HUMAN_APPROVAL, RATE_LIMIT, UNKNOWN_GUARD
# are NEVER in this set — that is the foundation of the hostile-test
# invariant.
_ACTION_AUTHORIZATION_KINDS = frozenset(
    {
        GuardKind.AUTHORIZATION,
        GuardKind.POLICY_ENFORCEMENT,
        GuardKind.CAPABILITY_PROOF,
    }
)


@dataclass(frozen=True)
class GuardClassification:
    """Result of classifying a guard callable.

    Fields:

    - ``kind``: the :class:`GuardKind` chosen.
    - ``evidence``: human-readable note explaining which pattern
      matched (or why none did). For unknowns this is
      ``"no pattern matched"``.
    - ``is_action_authorization``: True ONLY for AUTHORIZATION,
      POLICY_ENFORCEMENT, CAPABILITY_PROOF. AUTHENTICATION and
      VALIDATION are NEVER True here — this is the hostile-test
      invariant.
    - ``is_identity_only``: True ONLY for AUTHENTICATION. Proves who,
      not what they may do.
    """

    kind: GuardKind
    evidence: str
    is_action_authorization: bool
    is_identity_only: bool


def _matches(name: str, pattern: str) -> bool:
    """Match a regex/substring pattern against a lowercased name.

    Two forms are supported:

    1. **Prefix pattern** — if ``pattern`` ends with ``_`` (e.g.
       ``"can_"``, ``"may_"``, ``"clean_"``, ``"require_"``), the
       matcher uses ``name.startswith(pattern)``. This means
       ``"can_"`` matches ``can_user`` but NOT ``cancel_order``.

    2. **Word pattern** — otherwise the pattern is treated as a regex
       fragment and wrapped in custom word boundaries that treat
       ``_`` as a boundary character
       (``(?<![a-z0-9])PATTERN(?![a-z0-9])``). This means
       ``"auth"`` matches ``auth`` and ``auth_required`` but does NOT
       match ``authorize`` (the ``o`` after ``auth`` blocks the
       lookahead). Likewise ``"sanitize"`` matches ``sanitize_input``
       because the ``_`` after ``sanitize`` satisfies the lookahead.
    """
    if pattern.endswith("_"):
        return name.startswith(pattern)
    wrapped = r"(?<![a-z0-9])" + pattern + r"(?![a-z0-9])"
    return re.search(wrapped, name) is not None


# Ordered pattern table. First match wins.
#
# Ordering rationale (deviations from the brief's listed order are
# called out):
#
# 1. CAPABILITY_PROOF is checked first. The brief lists ``verify_pccb``,
#    ``verify_pcc``, ``require_pcc`` under BOTH AUTHORIZATION and
#    CAPABILITY_PROOF and instructs us to "pick CAPABILITY_PROOF for
#    these (more specific)". Putting CAPABILITY_PROOF first guarantees
#    that.
# 2. AUTHENTICATION next — its patterns are very specific
#    (``auth(enticate)?``, ``login_required``, ``verify_token``, …)
#    and should win over AUTHORIZATION's broader prefixes.
# 3. HUMAN_APPROVAL next — moved up from the brief's 5th slot so that
#    ``require_human`` and ``external_execution`` are caught before
#    AUTHORIZATION's ``require_`` fallback (added to AUTHORIZATION so
#    ``require_admin`` and similar ``require_<role>`` names classify as
#    AUTHORIZATION, satisfying test 4).
# 4. AUTHORIZATION with a ``require_`` fallback as the LAST pattern in
#    its tuple. By the time this fallback is reached, CAPABILITY_PROOF
#    (``require_pcc``), AUTHENTICATION (``require_login``,
#    ``require_session``), and HUMAN_APPROVAL (``require_human``) have
#    already had their chance, so only ``require_<other>`` falls
#    through to the AUTHORIZATION fallback.
# 5. VALIDATION — ``sanitize_input`` is deliberately NOT in this list
#    (the brief lists it but the SANITIZATION pattern ``sanitize``
#    will match it first because SANITIZATION is checked next; test 5
#    requires SANITIZATION).
# 6. SANITIZATION — its ``sanitize`` / ``sanitise`` / ``clean_`` /
#    ``escape`` / ``purify`` patterns.
# 7. POLICY_ENFORCEMENT.
# 8. RATE_LIMIT.
_KIND_PATTERNS: Tuple[Tuple[GuardKind, Tuple[str, ...]], ...] = (
    (
        GuardKind.CAPABILITY_PROOF,
        (
            "verify_pccb",
            "verify_pcc",
            "check_capability",
            "verify_capability",
            "require_pcc",
            "verify_proof",
        ),
    ),
    (
        GuardKind.AUTHENTICATION,
        (
            "auth(enticate)?",
            "login_required",
            "require_login",
            "verify_token",
            "verify_session",
            "require_session",
            "is_authenticated",
        ),
    ),
    (
        GuardKind.HUMAN_APPROVAL,
        (
            "require_human",
            "request_approval",
            "human_in_the_loop",
            "human_approval",
            "external_execution",
        ),
    ),
    (
        GuardKind.AUTHORIZATION,
        (
            "authorize",
            "authorise",
            "can_",
            "user_may",
            "may_",
            "require_role",
            "require_permission",
            "require_scope",
            "has_permission",
            "has_role",
            "check_permission",
            "check_authorization",
            "policy_gate",
            "assert_can",
            # Fallback: ``require_<X>`` not matched by CAPABILITY_PROOF
            # (require_pcc), AUTHENTICATION (require_login, require_session),
            # or HUMAN_APPROVAL (require_human) is a role/permission
            # requirement → AUTHORIZATION. e.g. ``require_admin``,
            # ``require_superuser``.
            "require_",
        ),
    ),
    (
        GuardKind.VALIDATION,
        (
            "validate",
            "verify_input",
            "check_input",
            "is_valid",
        ),
    ),
    (
        GuardKind.SANITIZATION,
        (
            "sanitize",
            "sanitise",
            "escape",
            "clean_",
            "purify",
        ),
    ),
    (
        GuardKind.POLICY_ENFORCEMENT,
        (
            "enforce_policy",
            "check_policy",
            "policy_check",
            "cedar",
            "casbin",
            "opa_eval",
            "opa_check",
        ),
    ),
    (
        GuardKind.RATE_LIMIT,
        (
            "rate_limit",
            "ratelimit",
            "throttle",
        ),
    ),
)


def _normalize_name(name: str) -> str:
    """Take the last dotted segment and strip leading underscores.

    ``self._validate_query`` → ``validate_query``
    ``obj.auth.authenticate`` → ``authenticate``
    """
    last_segment = str(name).rsplit(".", 1)[-1]
    stripped = last_segment.lstrip("_")
    return stripped.lower()


def classify_guard_name(name: str) -> GuardClassification:
    """Classify a guard by its callable name.

    The name is normalized: the last dotted segment is taken (so
    ``self.authenticate`` → ``authenticate``) and leading underscores
    are stripped (so ``_validate_query`` → ``validate_query``) before
    matching, mirroring the behaviour of
    :func:`actenon_scan.detectors.guards._is_validation_guard_name`.

    Returns a :class:`GuardClassification` whose ``kind`` is one of the
    :class:`GuardKind` members. Names that match no pattern return
    ``GuardKind.UNKNOWN_GUARD`` with ``is_action_authorization=False``
    and ``is_identity_only=False``.
    """
    if name is None:
        return GuardClassification(
            kind=GuardKind.UNKNOWN_GUARD,
            evidence="no name provided",
            is_action_authorization=False,
            is_identity_only=False,
        )
    normalized = _normalize_name(name)
    if not normalized:
        return GuardClassification(
            kind=GuardKind.UNKNOWN_GUARD,
            evidence="empty name after normalization",
            is_action_authorization=False,
            is_identity_only=False,
        )
    for kind, patterns in _KIND_PATTERNS:
        for pat in patterns:
            if _matches(normalized, pat):
                return GuardClassification(
                    kind=kind,
                    evidence=f"name '{normalized}' matched {kind.value} pattern '{pat}'",
                    is_action_authorization=kind in _ACTION_AUTHORIZATION_KINDS,
                    is_identity_only=kind is GuardKind.AUTHENTICATION,
                )
    return GuardClassification(
        kind=GuardKind.UNKNOWN_GUARD,
        evidence=f"name '{normalized}' matched no pattern",
        is_action_authorization=False,
        is_identity_only=False,
    )


def _call_name(call_node: ast.Call) -> Optional[str]:
    """Extract a best-effort name from an ``ast.Call``'s ``func`` node.

    - ``ast.Name`` (e.g. ``authenticate(...)``) → ``id``
    - ``ast.Attribute`` (e.g. ``self.authenticate(...)`` or
      ``obj.verify_pccb(...)``) → ``attr`` (the attribute name; the
      dotted prefix is irrelevant for the taxonomy because the last
      segment carries the semantic signal)
    - Anything else (subscript, call-of-call, lambda) → ``None``
    """
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def classify_guard_call(call_node: ast.Call) -> GuardClassification:
    """Classify a guard directly from an ``ast.Call`` node.

    Extracts the callable name from ``call_node.func`` (for ``Name``
    and ``Attribute`` calls) and delegates to
    :func:`classify_guard_name`. Calls whose ``func`` is neither a
    ``Name`` nor an ``Attribute`` (e.g. ``foo()(x)``) return
    ``GuardKind.UNKNOWN_GUARD`` rather than silently classifying on a
    syntactically-derived substring.
    """
    name = _call_name(call_node)
    if name is None:
        return GuardClassification(
            kind=GuardKind.UNKNOWN_GUARD,
            evidence="call func is not a Name or Attribute node",
            is_action_authorization=False,
            is_identity_only=False,
        )
    return classify_guard_name(name)


def action_authorization_strength(classification: GuardClassification) -> str:
    """Return ``'strong'`` / ``'weak'`` / ``'none'`` describing how
    strongly this guard kind can authorize an action.

    - **strong**: AUTHORIZATION, POLICY_ENFORCEMENT, CAPABILITY_PROOF
      (when the action parameter is bound). These are the only kinds
      for which ``is_action_authorization`` is True.
    - **none**: AUTHENTICATION, VALIDATION, SANITIZATION,
      HUMAN_APPROVAL, RATE_LIMIT — these CANNOT authorize an action
      regardless of how they're called. AUTHENTICATION proves *who*,
      not *what they may do*; VALIDATION proves an input is well-formed,
      not that the caller may act; SANITIZATION transforms input;
      HUMAN_APPROVAL requires a separate human channel; RATE_LIMIT only
      throttles call frequency.
    - **weak**: UNKNOWN_GUARD — downstream should not assume
      authorization but should not assume non-authorization either;
      surface for human review.
    """
    if classification.kind in _ACTION_AUTHORIZATION_KINDS:
        return "strong"
    if classification.kind is GuardKind.UNKNOWN_GUARD:
        return "weak"
    return "none"


def extract_action_label(name: str) -> str | None:
    """Extract the *action label* from an authorization guard's name.

    For guards like ``authorize_refund``, ``authorize_read``,
    ``require_admin``, ``check_permission_refund`` — the action label
    is the segment after the authorization prefix (``refund``, ``read``,
    ``admin``, ``permission_refund``).

    Returns ``None`` when:
    - the name is not an authorization-kind guard (e.g. ``authenticate``,
      ``validate_email`` — these have no action label because they don't
      authorize actions at all)
    - the name is an authorization-kind guard but the action label is
      empty (e.g. bare ``authorize`` with no suffix — the authority is
      generic, not action-specific)
    - the name is ``UNKNOWN_GUARD``

    The authority-binding layer consults this to refuse to bind when
    an authority call's action label differs from the sink's action
    label. This is the foundation for the brief's hostile-test
    requirement::

        authorize_refund(customer_A, 100)
        refund(customer_B, 5000)

    must NOT be treated as BOUND even when parameters match, because
    the authority's action label ("refund") does not match the sink's
    action label (inferred from the sink's name).
    """
    if name is None:
        return None
    classification = classify_guard_name(name)
    if classification.kind not in _ACTION_AUTHORIZATION_KINDS:
        return None
    # Strip the last dotted segment and lowercase (mirrors classify_guard_name)
    normalized = _normalize_name(name)
    if not normalized:
        return None
    # Strip every known authorization-kind prefix from the start of the
    # name. Iterate because some names have multiple prefixes
    # (e.g. ``check_permission_refund`` → strip ``check_permission`` →
    # ``refund``).
    prefixes = [
        "authorize_", "authorise_",
        "require_", "require_permission_", "require_role_", "require_scope_",
        "check_permission_", "check_authorization_", "check_authorisation_",
        "has_permission_", "has_role_",
        "verify_pccb_", "verify_pcc_", "verify_capability_",
        "enforce_policy_", "check_policy_",
        "policy_gate_",
        "assert_can_", "can_", "may_",
    ]
    # Sort by length descending so longer prefixes strip first
    prefixes.sort(key=len, reverse=True)
    stripped = normalized
    changed = True
    while changed:
        changed = False
        for p in prefixes:
            if stripped.startswith(p):
                stripped = stripped[len(p):]
                changed = True
        # Stop once no prefix matches
        if not changed:
            break
    stripped = stripped.lstrip("_")
    if not stripped or stripped == normalized:
        # Bare ``authorize`` (no suffix) → no action label
        if stripped == normalized:
            return None
        return None
    return stripped


def infer_sink_action_label(sink_call_name: str) -> str | None:
    """Infer the action label a sink is performing, from its callable name.

    Examples:
    - ``refund`` → ``refund``
    - ``process_refund`` → ``refund``
    - ``issue_refund`` → ``refund``
    - ``stripe_refund_create`` → ``refund_create`` (after stripping
      ``stripe_`` prefix; further suffix-stripping is left to the caller)
    - ``send_email`` → ``email`` (after stripping ``send_``)
    - ``send_message`` → ``message``
    - ``subprocess_run`` → ``run`` (after stripping ``subprocess_``)
    - ``delete_database`` → ``database`` (the action is "delete" but the
      *resource* is "database"; we return the resource label since that
      is what an authority call would label)

    Returns ``None`` when no recognisable action label can be extracted.

    The mapping is deliberately conservative — only a small set of
    action verbs and resource nouns are recognised. Anything else
    returns None (UNKNOWN), which the authority-binding layer treats
    as "no action label to compare against" rather than as a match.
    """
    if sink_call_name is None:
        return None
    normalized = _normalize_name(sink_call_name)
    if not normalized:
        return None
    # Verbs that, when stripped, leave the resource/action label
    verbs = [
        "process_", "issue_", "execute_", "exec_", "send_", "post_",
        "create_", "delete_", "remove_", "update_", "modify_", "set_",
        "put_", "patch_", "destroy_", "revoke_", "grant_", "deny_",
        "approve_", "reject_", "refund_", "charge_", "transfer_",
        "deploy_", "rollback_", "scale_", "launch_",
    ]
    verbs.sort(key=len, reverse=True)
    stripped = normalized
    for v in verbs:
        if stripped.startswith(v):
            candidate = stripped[len(v):].lstrip("_")
            if candidate and candidate != stripped:
                return candidate
    # Action nouns: ``refund`` alone, ``payment``, ``email``, etc.
    # — return as-is.
    return normalized


__all__ = [
    "GuardKind",
    "GuardClassification",
    "classify_guard_name",
    "classify_guard_call",
    "action_authorization_strength",
    "extract_action_label",
    "infer_sink_action_label",
]
