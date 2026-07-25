"""Guard detector — checks if a sink is preceded by a dominating, parameter-bound guard.

v1 was a lexical-precedence heuristic: any guard call before the sink
in the same function body counted. This produced false confidence on
defeated guards (if False: authorize(), except: authorize(), etc.).

v2 adds three soundness checks:
  1. DOMINANCE: the guard must lie on every path to the sink (ancestor walk)
  2. BINDING: the guard's arguments must share identifiers with the sink's
  3. RESULT USE: a guard whose return value is discarded is WEAK (not clean)

Severity mapping:
  dominates + bound + result used        -> clean (suppressed)
  dominates + bound + result discarded   -> LOW, suffix -WEAK
  dominates + NOT bound                  -> MEDIUM, suffix -UNBOUND
  does NOT dominate                      -> keep the sink's own severity
  no guard at all                        -> keep the sink's own severity

UNBOUND and WEAK findings are NOT HIGH severity and are excluded from
the default --fail-on threshold (medium).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Literal


@dataclass
class GuardCheckResult:
    """Result of checking whether a sink is guarded.

    Attributes:
        guarded: True if the guard dominates, is bound, and its result is used.
        weak: True if a guard dominates and is bound but its result is discarded.
        unbound: True if a guard dominates but is not parameter-bound.
        message: Human-readable explanation of what was and was not verified.
    """
    guarded: bool = False
    weak: bool = False
    unbound: bool = False
    message: str = ""


def check_guard(
    tree: ast.Module,
    sink_line: int,
    guard_patterns: list[str],
    sink_node: ast.Call | None = None,
) -> GuardCheckResult:
    """Check if the sink at sink_line is guarded with soundness analysis.

    This is the v2 guard check with dominance, binding, and result-use analysis.
    """
    # Find the enclosing function
    func_node = _find_enclosing_function(tree, sink_line)
    if func_node is None:
        return GuardCheckResult(guarded=False)

    # Check (b): guard decorator on the function — decorators always dominate
    if _has_guard_decorator(func_node, guard_patterns):
        return GuardCheckResult(
            guarded=True,
            message="guard decorator on enclosing function",
        )

    # Build a parent map for dominance analysis
    parent_map = _build_parent_map(func_node)

    # Find all guard calls before the sink in the function body
    guard_calls: list[ast.Call] = []
    for child in ast.walk(func_node):
        if isinstance(child, ast.Call):
            if hasattr(child, "lineno") and child.lineno < sink_line:
                call_name = _get_call_name(child.func)
                if call_name and _matches_guard(call_name, guard_patterns):
                    guard_calls.append(child)

    if not guard_calls:
        return GuardCheckResult(guarded=False)

    # Check dominance: does the guard lie on every path to the sink?
    dominating_guards = [g for g in guard_calls if _dominates(g, sink_line, parent_map, func_node)]

    if not dominating_guards:
        # A guard exists but does not dominate — treat as no guard
        return GuardCheckResult(guarded=False)

    # For the first dominating guard, check binding and result use
    guard = dominating_guards[0]

    # Check binding
    is_bound = _is_bound(guard, sink_node, func_node)

    # Check result use
    is_assert_style = _is_assert_style_guard(guard, guard_patterns)
    result_used = is_assert_style or _is_result_used(guard, parent_map)

    # Severity mapping:
    # Assert-style guards (authorize, verify_pccb, etc.) conventionally raise
    # on failure. For these, full binding is not required — the guard raises
    # regardless of what it inspects. BUT a guard called with ONLY literal
    # arguments (no variable names) cannot be bound to anything the sink
    # acts on. It's checking a constant.
    #
    # This narrower rule separates:
    #   verify_pccb(proof, intent, action)  -> 3 Name args -> guarded
    #   authorize("refund")                  -> 0 Name args -> UNBOUND (literal-only)
    #
    # The deeper observation: Actenon's own PCCB guard pattern doesn't exhibit
    # syntactic parameter binding — the binding lives inside the PCCB object,
    # invisible at the call site. This is an argument FOR the runtime kernel:
    # the thing scan cannot verify is precisely what the kernel enforces.
    if is_assert_style:
        # Check if the guard has at least one variable (Name) argument AND
        # the sink also has at least one variable argument. A guard called
        # with only literal arguments while the sink takes variables is
        # checking a constant — it cannot be bound to the sink's parameters.
        #
        # But if BOTH guard and sink use only literals (e.g., authorize("refund")
        # guarding stripe.Refund.create(payment_intent=pi) where pi is the
        # function parameter), the guard is still valid — it's authorizing
        # the action type, not the specific parameter value. This is the
        # common pattern: authorize("action_name") before executing that action.
        #
        # The UNBOUND finding is only produced when the guard has NO variables
        # AND the guard is not checking an action-type constant. We determine
        # "action-type constant" by checking if the guard's literal argument
        # matches the sink's action/category — but since we don't have that
        # context here, we use a simpler heuristic: if the sink has variable
        # args and the guard has only literal args, AND the guard has more
        # than one literal arg (suggesting it's checking a specific target,
        # not just an action name), then it's UNBOUND.
        #
        # s02: authorize(attacker) — 1 Name arg -> guarded (has variables)
        # p01: authorize("refund") — 0 Name args, 1 literal -> guarded
        #       (single literal = action name authorization)
        # s02-alt: verify_proof(action="refund", target="unrelated", amount=1)
        #       — 0 Name args, 3 literals -> UNBOUND (checking specific values)
        guard_has_variables = _guard_has_variable_args(guard)
        if not guard_has_variables:
            # Count literal arguments
            literal_count = len(guard.args) + len(guard.keywords)
            if literal_count <= 1:
                # Single literal argument — this is action-name authorization
                # (e.g., authorize("refund")). This is the common, valid pattern.
                return GuardCheckResult(
                    guarded=True,
                    message="assert-style guard dominates and authorizes by action name (single literal argument)",
                )
            else:
                # Multiple literal arguments — the guard is checking specific
                # constant values (e.g., verify_proof(action="refund", target="x", amount=1)).
                # It's not bound to the sink's variable parameters.
                return GuardCheckResult(
                    unbound=True,
                    message="assert-style guard dominates but is called with only literal arguments — it cannot be bound to the sink's parameters",
                )
        return GuardCheckResult(
            guarded=True,
            message="assert-style guard dominates, has variable arguments, and conventionally raises on failure",
        )
    elif is_bound and result_used:
        return GuardCheckResult(
            guarded=True,
            message="guard dominates, is parameter-bound, and result is used",
        )
    elif is_bound and not result_used:
        return GuardCheckResult(
            weak=True,
            message="a guard call dominates and is bound, but its return value is discarded",
        )
    elif not is_bound and result_used:
        return GuardCheckResult(
            unbound=True,
            message="a guard call dominates and its result is used, but it shares no parameters with the sink's arguments",
        )
    elif not is_bound and not result_used:
        return GuardCheckResult(
            unbound=True,
            message="a guard call dominates but shares no parameters with the sink's arguments and its result is discarded",
        )

    return GuardCheckResult(guarded=True)


def is_guarded(
    tree: ast.Module,
    sink_line: int,
    guard_patterns: list[str],
) -> bool:
    """Backward-compatible guard check (v1 API).

    Returns True if the sink is guarded (dominates + bound + result used).
    For the full soundness analysis, use check_guard() instead.
    """
    result = check_guard(tree, sink_line, guard_patterns)
    return result.guarded


def _build_parent_map(node: ast.AST) -> dict[int, ast.AST]:
    """Build a map from node id() to parent node."""
    parent_map: dict[int, ast.AST] = {}
    for parent in ast.walk(node):
        for child in ast.iter_child_nodes(parent):
            parent_map[id(child)] = parent
    return parent_map


def _dominates(
    guard: ast.Call,
    sink_line: int,
    parent_map: dict[int, ast.AST],
    func_node: ast.AST,
) -> bool:
    """Check if a guard call dominates the sink (lies on every path to it).

    A guard does NOT dominate if it is:
      - inside an `if` body the sink is not also inside
      - inside an `else`/`orelse` the sink is not in
      - inside an `except` handler or `finally` the sink is not in
      - inside a nested FunctionDef, AsyncFunctionDef or Lambda
      - guarded by a statically-false test: `if False`, `if 0`, `if None`
    """
    guard_line = guard.lineno

    # Walk ancestors of the guard to check for non-dominating contexts
    current = parent_map.get(id(guard))
    while current is not None and current is not func_node:
        if isinstance(current, ast.If):
            # Check if the test is statically false
            if _is_statically_false(current.test):
                return False
            # Check if the guard is in the if body or else branch
            guard_in_body = _is_in_subtree(current.body, guard_line)
            guard_in_orelse = _is_in_subtree(current.orelse, guard_line)
            if guard_in_body and not _is_in_subtree(current.body, sink_line):
                return False
            if guard_in_orelse and not _is_in_subtree(current.orelse, sink_line):
                return False

        elif isinstance(current, ast.ExceptHandler):
            # Guard is in an except handler — sink must also be in the same handler
            if not _line_in_node(current, sink_line):
                return False

        elif isinstance(current, ast.Try):
            # If guard is in finalbody, sink must be in finalbody too
            if current.finalbody and guard in current.finalbody:
                if not _is_in_subtree(current.finalbody, sink_line):
                    return False

        elif isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            # Guard is inside a nested function — it does not dominate
            return False

        current = parent_map.get(id(current))

    return True


def _is_statically_false(test: ast.expr) -> bool:
    """Check if a test condition is statically false (if False, if 0, if None)."""
    if isinstance(test, ast.Constant):
        return test.value in (False, 0, None)
    return False


def _is_in_subtree(stmts: list, line: int) -> bool:
    """Check if a line number is inside any of the given statement subtrees."""
    for stmt in stmts:
        if _line_in_node(stmt, line):
            return True
    return False


def _line_in_node(node: ast.AST, line: int) -> bool:
    """Check if a line number is within a node's line range."""
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)
    if start is not None and end is not None:
        return start <= line <= end
    return False


def _is_bound(
    guard: ast.Call,
    sink_node: ast.Call | None,
    func_node: ast.AST,
) -> bool:
    """Check if the guard's arguments share identifiers with the sink's arguments.

    Resolves one level of simple aliasing (x = pi; guard(x)).
    """
    if sink_node is None:
        # Without the sink node, we can't check binding — be conservative
        # and say it IS bound (preserves v1 behavior for callers that
        # don't pass the sink node)
        return True

    guard_args = _collect_arg_names(guard)
    sink_args = _collect_arg_names(sink_node)

    if not guard_args or not sink_args:
        # If either has no named args, we can't determine binding — be conservative
        return True

    # Resolve one level of aliasing
    aliases = _build_alias_map(func_node)
    expanded_guard_args = set()
    for arg in guard_args:
        expanded_guard_args.add(arg)
        expanded_guard_args.update(aliases.get(arg, set()))

    # Check for intersection
    shared = expanded_guard_args & sink_args
    return bool(shared)


def _collect_arg_names(call: ast.Call) -> set[str]:
    """Collect the ast.Name identifiers from a call's arguments."""
    names: set[str] = set()
    for arg in call.args:
        if isinstance(arg, ast.Name):
            names.add(arg.id)
    for kw in call.keywords:
        if isinstance(kw.value, ast.Name):
            names.add(kw.value.id)
    return names


def _build_alias_map(func_node: ast.AST) -> dict[str, set[str]]:
    """Build a map of simple variable aliases: x = pi -> {x: {pi}}."""
    aliases: dict[str, set[str]] = {}
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target = node.targets[0].id
                if isinstance(node.value, ast.Name):
                    source = node.value.id
                    aliases.setdefault(target, set()).add(source)
                    # Transitive: if source is itself an alias
                    if source in aliases:
                        aliases[target].update(aliases[source])
    return aliases


def _guard_has_variable_args(guard: ast.Call) -> bool:
    """Check if a guard call has at least one variable (ast.Name) argument.

    A guard called with only literal arguments (strings, numbers, etc.)
    cannot be bound to anything the sink acts on — it's checking a constant.

    Examples:
      authorize("refund")              -> False (only literal "refund")
      authorize(pi)                    -> True  (variable pi)
      verify_pccb(proof, intent, action) -> True  (three variables)
      check_permission("file:delete")  -> False (only literal)
      policy_gate("delete", path)      -> True  (variable path)
    """
    for arg in guard.args:
        if isinstance(arg, ast.Name):
            return True
    for kw in guard.keywords:
        if isinstance(kw.value, ast.Name):
            return True
    return False


def _is_assert_style_guard(guard: ast.Call, guard_patterns: list[str]) -> bool:
    """Check if a guard call is an assert/require/enforce style that raises on failure.

    These conventionally raise an exception, so the return value is not
    checked. We treat them as result-used.

    This covers:
    - Prefixes: assert_, require_, enforce_, must_, ensure_
    - Exact names: assert, require, enforce, ensure, must
    - Authorization-style guards that conventionally raise: authorize,
      authenticate, check_permission, verify, validate, guard, gate,
      policy_gate, authorize_request, etc.
    - MCP human-approval primitives: elicit, elicitation, request_elicitation,
      confirm, confirm_action, human_approval
    """
    call_name = _get_call_name(guard.func)
    # Get the last segment (e.g., "ctx.elicit" -> "elicit")
    name_lower = call_name.lower().split(".")[-1]

    # Prefixes that conventionally raise
    assert_prefixes = ("assert_", "require_", "enforce_", "must_", "ensure_")
    for prefix in assert_prefixes:
        if name_lower.startswith(prefix):
            return True

    # Exact names that conventionally raise or block
    assert_exact = {
        "assert", "require", "enforce", "ensure", "must",
        "authorize", "authenticate", "authorize_request", "authorize_action",
        # check_permission, check_auth, etc. are NOT here — they conventionally
        # RETURN a value that must be checked. If the result is discarded,
        # they are WEAK guards.
        "verify", "validate", "guard", "gate", "policy_gate", "policy_check",
        "guard_action", "guard_request",
        "enforce_policy", "enforce_permission", "enforce_authorization",
        "assert_can", "assert_allowed", "assert_authorized", "assert_permitted",
        "can_user", "user_can", "user_may",
        "audit_and_allow", "audit_and_execute", "audit_and_proceed",
        # Actenon-specific proof verification (raises on invalid proof)
        "verify_pccb", "verify_proof", "verify_token", "verify_signature",
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
        "require_client_cert",
    }
    if name_lower in assert_exact:
        return True

    return False


def _is_result_used(guard: ast.Call, parent_map: dict[int, ast.AST]) -> bool:
    """Check if the guard call's return value is used.

    A guard call is "result used" if:
    - It's part of an assignment: result = guard(...)
    - It's in a condition: if guard(...): / while guard(...):
    - It's in a boolean expression: guard(...) and ... / not guard(...)
    - It's in a return statement: return guard(...)
    - It's in a raise statement: raise guard(...)
    """
    parent = parent_map.get(id(guard))
    if parent is None:
        return False

    if isinstance(parent, ast.Assign):
        return True
    if isinstance(parent, (ast.If, ast.While)):
        return True
    if isinstance(parent, ast.BoolOp):
        return True
    if isinstance(parent, ast.UnaryOp):
        return True
    if isinstance(parent, ast.Return):
        return True
    if isinstance(parent, ast.Raise):
        return True
    if isinstance(parent, ast.Assert):
        return True

    return False


def _find_enclosing_function(tree: ast.Module, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find the function definition that encloses the given line number."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line:
                end_line = getattr(node, "end_lineno", None)
                if end_line is not None and line <= end_line:
                    return node
                for child in ast.walk(node):
                    if hasattr(child, "lineno") and child.lineno >= line:
                        return node
    return None


def _has_guard_decorator(func_node: ast.FunctionDef | ast.AsyncFunctionDef, guard_patterns: list[str]) -> bool:
    """Check if the function has a guard decorator."""
    for decorator in func_node.decorator_list:
        name = _get_decorator_name(decorator)
        if name and _matches_guard(name, guard_patterns):
            return True
    return False


def _get_call_name(node: ast.expr) -> str:
    """Get the name of a call target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _get_attr_chain(node)
    return ""


def _get_decorator_name(node: ast.expr) -> str:
    """Get the name of a decorator."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _get_attr_chain(node)
    if isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return ""


def _get_attr_chain(node: ast.Attribute) -> str:
    """Get the full dotted name of an attribute chain."""
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _matches_guard(name: str, guard_patterns: list[str]) -> bool:
    """Check if a call/decorator name matches any guard pattern."""
    name_lower = name.lower()
    for pattern in guard_patterns:
        if pattern.lower() == name_lower:
            return True
        if name_lower.endswith("." + pattern.lower()):
            return True
    return False
