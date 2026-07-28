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

    # Check (b2): framework-level approval flags in decorator keyword arguments.
    # Work Order 4, Part 2.1: @tool(external_execution=True) means agno does
    # NOT execute the tool — the call is handed back for a human to run. This
    # is the framework's own human-in-the-loop primitive, same class as
    # ctx.elicit and LangChain's HumanApprovalCallbackHandler.
    approval_flag = _has_decorator_approval_flag(func_node)
    if approval_flag:
        return GuardCheckResult(
            guarded=True,
            message=f"framework approval flag on enclosing function: {approval_flag}",
        )

    # Build a parent map for dominance analysis
    parent_map = _build_parent_map(func_node)

    # Find all guard calls before the sink in the function body
    guard_calls: list[ast.Call] = []
    for child in ast.walk(func_node):
        if isinstance(child, ast.Call):
            if hasattr(child, "lineno") and child.lineno < sink_line:
                call_name = _get_call_name(child.func)
                if call_name and (_matches_guard(call_name, guard_patterns) or _is_validation_guard_name(call_name)):
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
    # v3: resolve guard by DEFINITION, not by name.
    # If the guard function is defined in the scanned module, classify it
    # from its AST (does it raise? does it return a value?).
    # If unresolvable (imported), fall back to a NARROW name heuristic.
    is_assert_style = _resolve_guard_style(guard, tree, guard_patterns)
    result_used = is_assert_style or _is_result_used(guard, parent_map)

    # Severity mapping:
    # Assert-style guards (authorize, verify_pccb, etc.) conventionally raise
    # on failure. For these, full binding is NOT required — the guard raises
    # regardless of what it inspects, and requiring binding would flag
    # legitimate idioms:
    #
    #   authorize("refund")                     -- authorizes by action name
    #   casbin_enforce("user", "record", "del") -- Casbin's subject/object/action
    #   verify_pccb(proof, intent, action)      -- Actenon's own PCCB pattern
    #
    # None of these share an identifier with the sink they guard, and all
    # three are correct. Binding intersection cannot separate them from a
    # defeated guard, so assert-style guards are exempt from it.
    #
    # There is one case that IS separable: COUNTERFEIT BINDING. A guard that
    # passes variables — thereby appearing to inspect runtime data — where
    # every one of those variables provably resolves to a compile-time
    # constant, and none of them is the data the sink acts on:
    #
    #   attacker = "evil_intent"
    #   authorize(attacker)                     -- looks bound; inspects nothing
    #   stripe.Refund.create(payment_intent=pi)
    #
    # `attacker` is not a parameter and is assigned only from a literal, so
    # the guard's apparent data-dependence is fake. This is distinguishable
    # from all three legitimate idioms above, none of which pass variables at
    # all (authorize/casbin_enforce) or pass function parameters (verify_pccb).
    #
    # Note what remains undetectable: an assert-style guard passing REAL
    # parameters that happen to be the wrong ones. `verify_pccb(proof, intent,
    # action)` and a hypothetical `verify_pccb(wrong, wrong2, wrong3)` are
    # syntactically identical. See docs/COVERAGE.md — the binding that makes
    # PCCB sound is cryptographic, inside the proof object, and invisible to
    # any static reader of the call site.
    if is_assert_style:
        if not is_bound and _is_counterfeit_binding(guard, sink_node, func_node):
            return GuardCheckResult(
                unbound=True,
                message=(
                    "assert-style guard dominates, but every variable it inspects "
                    "resolves to a compile-time constant — it is not bound to the "
                    "data the sink acts on"
                ),
            )
        return GuardCheckResult(
            guarded=True,
            message="assert-style guard dominates and conventionally raises on failure",
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
      - inside a `try` body whose `except` handler swallows exceptions
        (Work Order 1.5: catches a broad type with an empty or pass-only
        body and no re-raise). This defeats an assert-style guard's raise.
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
            # Work Order 1.5: if guard is in the try body, check whether
            # any except handler swallows exceptions (defeats assert-style
            # guards that raise). A swallowing handler catches a broad
            # exception type and has an empty or pass-only body with no
            # re-raise.
            if current.body and _is_in_subtree(current.body, guard_line):
                # Only flag if the sink is NOT in the try body (i.e.,
                # the sink runs after the try block, so a swallowed
                # exception means the guard's raise didn't stop execution).
                if not _is_in_subtree(current.body, sink_line):
                    for handler in current.handlers:
                        if _except_handler_swallows(handler):
                            return False

        elif isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            # Guard is inside a nested function — it does not dominate
            return False

        current = parent_map.get(id(current))

    return True


def _except_handler_swallows(handler: ast.ExceptHandler) -> bool:
    """Check if an except handler swallows exceptions.

    A handler swallows if it catches a broad type (bare `except:`,
    `except Exception:`, `except BaseException:`) and its body is empty,
    contains only `pass`, or contains statements but no `raise`.

    Conservative: a handler with a specific type (e.g., `except ValueError:`)
    or one that re-raises does NOT swallow.
    """
    # Check the exception type — bare except or Exception/BaseException
    if handler.type is not None:
        # Named type — get the name
        if isinstance(handler.type, ast.Name):
            type_name = handler.type.id
            if type_name not in ("Exception", "BaseException"):
                return False  # specific type — don't flag
        elif isinstance(handler.type, ast.Tuple):
            # Tuple of types — if all are broad, treat as broad
            for elt in handler.type.elts:
                if isinstance(elt, ast.Name) and elt.id in ("Exception", "BaseException"):
                    continue
                return False  # has a specific type — don't flag
        else:
            return False  # attribute or other — don't flag

    # Walk the handler body looking for a raise statement
    for child in ast.walk(handler):
        if isinstance(child, ast.Raise):
            return False  # re-raises — does not swallow

    # No raise in the body. The handler swallows.
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


# Sentinel for a name whose value cannot be resolved statically.
_UNRESOLVABLE = object()


def _is_counterfeit_binding(
    guard: ast.Call,
    sink_node: ast.Call | None,
    func_node: ast.AST,
) -> bool:
    """Detect a guard that fakes data-dependence on the sink's parameters.

    Returns True only when ALL of the following hold:

      1. the guard passes at least one variable (so it *appears* bound),
      2. the sink acts on at least one variable (so there is real data to bind to),
      3. every argument the guard passes is a literal or a name that provably
         resolves to a compile-time constant, and
      4. (checked by the caller) the guard shares no identifier with the sink.

    Condition 3 is what separates this from a legitimate guard. A guard
    holding a function parameter, an attribute, a call result, or any name
    this analysis cannot resolve is treated as genuinely data-dependent and
    is NOT counterfeit — the conservative direction, since a false UNBOUND on
    a real guard is a precision loss.

    Examples:
      attacker = "evil_intent"; authorize(attacker)  -> True  (constant laundered)
      authorize("refund")                            -> False (no variables; cond 1)
      casbin_enforce("user", "record", "delete")     -> False (no variables; cond 1)
      verify_pccb(proof, intent, action)             -> False (parameters; cond 3)
      policy_gate("delete", path)                    -> False (parameter; cond 3)
    """
    if sink_node is None:
        return False

    # (1) the guard must appear to inspect runtime data
    if not _collect_arg_names(guard):
        return False

    # (2) the sink must act on runtime data
    if not _collect_arg_names(sink_node):
        return False

    # (3) every guard argument must be a provable compile-time constant
    params = _function_params(func_node)
    bindings = _collect_name_bindings(func_node)

    guard_values = list(guard.args) + [kw.value for kw in guard.keywords]
    for value in guard_values:
        if isinstance(value, ast.Constant):
            continue
        if isinstance(value, ast.Name) and _name_is_constant(value.id, params, bindings):
            continue
        return False

    return True


def _function_params(func_node: ast.AST) -> set[str]:
    """Collect every parameter name bound by a function definition."""
    params: set[str] = set()
    if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return params
    a = func_node.args
    for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs]:
        params.add(arg.arg)
    if a.vararg is not None:
        params.add(a.vararg.arg)
    if a.kwarg is not None:
        params.add(a.kwarg.arg)
    return params


def _collect_name_bindings(func_node: ast.AST) -> dict[str, list]:
    """Map each locally-bound name to every value expression assigned to it.

    Bindings this analysis cannot follow (loop targets, `with ... as`,
    `except ... as`, augmented assignment, `global`/`nonlocal`, tuple
    unpacking) record the _UNRESOLVABLE sentinel, which forces the name to be
    treated as non-constant.
    """
    bindings: dict[str, list] = {}

    def bind(name: str, value: object) -> None:
        bindings.setdefault(name, []).append(value)

    def bind_target_unresolvable(target: ast.AST) -> None:
        for sub in ast.walk(target):
            if isinstance(sub, ast.Name):
                bind(sub.id, _UNRESOLVABLE)

    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bind(target.id, node.value)
                else:
                    # tuple/list unpacking, subscript, attribute
                    bind_target_unresolvable(target)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                bind(node.target.id, node.value if node.value is not None else _UNRESOLVABLE)
        elif isinstance(node, ast.AugAssign):
            bind_target_unresolvable(node.target)
        elif isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name):
                bind(node.target.id, node.value)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            bind_target_unresolvable(node.target)
        elif isinstance(node, ast.comprehension):
            bind_target_unresolvable(node.target)
        elif isinstance(node, ast.withitem):
            if node.optional_vars is not None:
                bind_target_unresolvable(node.optional_vars)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                bind(node.name, _UNRESOLVABLE)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bind(name, _UNRESOLVABLE)

    return bindings


def _name_is_constant(
    name: str,
    params: set[str],
    bindings: dict[str, list],
    seen: set[str] | None = None,
) -> bool:
    """Check whether a name provably holds a compile-time constant.

    Conservative in every unknown direction: a parameter, an unbound name
    (global or closure), a name bound by an unfollowable construct, or an
    assignment cycle all return False.
    """
    if seen is None:
        seen = set()
    if name in seen:
        return False
    seen.add(name)

    # A parameter carries caller-controlled data by definition.
    if name in params:
        return False

    values = bindings.get(name)
    if not values:
        # Never assigned locally — a global, closure or import. Unknown.
        return False

    for value in values:
        if value is _UNRESOLVABLE:
            return False
        if isinstance(value, ast.Constant):
            continue
        if isinstance(value, ast.Name) and _name_is_constant(value.id, params, bindings, seen):
            continue
        if isinstance(value, (ast.Tuple, ast.List, ast.Set)) and all(
            isinstance(elt, ast.Constant) for elt in value.elts
        ):
            continue
        return False

    return True


def _resolve_guard_style(
    guard: ast.Call,
    tree: ast.Module,
    guard_patterns: list[str],
) -> bool:
    """Resolve whether a guard is assert-style (raises) or boolean-style (returns).

    v3: resolve by DEFINITION, not by name.

    1. LOCAL RESOLUTION: If the guard function is defined in the scanned
       module, classify it from its AST:
         - contains a raise statement -> assert-style
         - returns a value and never raises -> boolean-style
         - both -> assert-style (the raise dominates)

    2. UNRESOLVABLE: If the guard is imported or cannot be resolved,
       fall back to a NARROW name heuristic. Per RULE 4, bias to WEAK
       (boolean-style) for anything that is not clearly assert-style.
       Only names beginning with assert_, require_, enforce_, ensure_,
       must_ stay assert-style when unresolvable.

    This closes the false-negative class where check_permission, check_access,
    check_auth, and verify_token were in assert_exact by name but are
    user-defined functions that return bool rather than raising.
    """
    # Get the guard function name
    guard_name = _get_call_name(guard.func)
    if not guard_name:
        return False

    # Try local resolution: find the function definition in the module
    local_def = _find_function_def(tree, guard_name)
    if local_def is not None:
        # Classify from the AST
        return _function_raises(local_def)

    # Unresolvable: fall back to name heuristic.
    # Per RULE 4, bias to WEAK for ambiguous names. But a broad set of
    # guard names are CONVENTIONALLY assert-style — they raise on failure
    # in practice. Removing them all would produce WEAK findings on every
    # authorize()/verify_pccb() call, which is a precision regression.
    #
    # The four names that were false negatives (check_permission, check_access,
    # check_auth, verify_token) are NOT in this set — they have check_*/verify_*
    # prefixes which are ambiguous (could return bool). The names below are
    # those that conventionally raise:
    name_lower = guard_name.lower().split(".")[-1]

    # Prefixes that conventionally raise
    assert_prefixes = ("assert_", "require_", "enforce_", "ensure_", "must_")
    for prefix in assert_prefixes:
        if name_lower.startswith(prefix):
            return True

    # Names that conventionally raise or block (unresolvable fallback)
    conventional_assert = {
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
    if name_lower in conventional_assert:
        return True

    # Also check substring for custom names like my_org_verify_permission
    for entry in conventional_assert:
        if entry in name_lower:
            return True

    # Everything else is NOT assert-style when unresolvable.
    # This includes: check_permission, check_access, check_auth, verify_token
    # — names that could return bool. Per RULE 4, bias to WEAK.
    return False


def _find_function_def(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find a function definition in the module by name.

    Handles dotted names (e.g., self.authorize -> authorize).
    """
    # Strip dotted prefix to get the last segment
    short_name = name.split(".")[-1]

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == short_name or node.name == name:
                return node
    return None


def _function_raises(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check if a function contains a raise statement on a non-exceptional path.

    A function that raises is assert-style — the guard enforces by raising.
    A function that only returns and never raises is boolean-style.
    """
    for child in ast.walk(func_node):
        if isinstance(child, ast.Raise):
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
        # check_permission, check_auth, etc. conventionally raise on failure.
        # The s06 soundness case tests a DIFFERENT pattern: a guard whose
        # result is discarded AND whose name does NOT imply raising.
        # check_permission IS assert-style — it raises PermissionError.
        "check_permission", "check_auth", "check_authorization", "check_access",
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

    # Also check if any assert_exact entry appears as a substring.
    # This catches custom guard names like my_org_verify_permission
    # (contains "verify") or org_authorize_request (contains "authorize").
    for entry in assert_exact:
        if entry in name_lower:
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


# Framework-level approval flags recognised as guards.
# Work Order 4, Part 2.1+2.2: each entry is (decorator_name, kwarg_name, truthy_values)
# A decorator that passes one of these kwargs with a truthy value signals that
# the framework does NOT auto-execute the tool — the call is handed to a human.
_DECORATOR_APPROVAL_FLAGS: list[tuple[str, str, frozenset]] = [
    # agno: @tool(external_execution=True) — the agent returns the tool call
    # to the caller for external execution. The agent does NOT run it.
    ("tool", "external_execution", frozenset({True, "true", "True", "1", 1})),
    # agno: @tool(human_input=True) — the tool requires human input before
    # execution can proceed.
    ("tool", "human_input", frozenset({True, "true", "True", "1", 1})),
    # pydantic-ai: @tool(prepare=...) with human approval — not a kwarg but
    # a function; skip for now (cannot verify without the prepare function body).
]


def _has_decorator_approval_flag(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    """Check if the function has a decorator with a framework-level approval flag.

    Returns a human-readable description of the flag found, or None.

    Recognised flags (Work Order 4, Part 2.1+2.2):
      - @tool(external_execution=True) — agno: tool is NOT auto-executed;
        the call is handed back for a human to run.
      - @tool(human_input=True) — agno: tool requires human input.

    Each was verified against real source in the agno cookbook:
      cookbook/02_agents/10_human_in_the_loop/external_tool_execution.py
    """
    for decorator in func_node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        dec_name = _get_decorator_name(decorator.func)
        for flag_dec_name, kwarg_name, truthy_values in _DECORATOR_APPROVAL_FLAGS:
            if dec_name != flag_dec_name:
                continue
            for kw in decorator.keywords:
                if kw.arg != kwarg_name:
                    continue
                # Check if the value is truthy
                if isinstance(kw.value, ast.Constant):
                    if kw.value.value in truthy_values:
                        return f"{dec_name}({kwarg_name}={kw.value.value!r})"
                elif isinstance(kw.value, ast.Name):
                    if kw.value.id in ("True", "true"):
                        return f"{dec_name}({kwarg_name}={kw.value.id})"
    return None


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


# Validation-guard name patterns. These are method calls that validate,
# sanitise, or check a parameter before it reaches a sink. Unlike
# assert-style guards (authorize, verify_pccb) which raise on failure,
# validation guards typically return a (valid, message) tuple and the
# caller checks the result in an if-condition with an early return.
#
# Recognition requires:
#   1. The method name starts with one of these keywords (after stripping
#      leading underscores)
#   2. The call dominates the sink (early return/raise after the check)
#   3. The call's arguments share identifiers with the sink (binding)
#
# The match is PREFIX-based (validate_*, check_*, sanitize_*, verify_*),
# not substring-based, to avoid false matches on names like "filter",
# "unescape", "get_subtype_of_stateful_step" that happen to contain a
# keyword as a substring.
_VALIDATION_GUARD_KEYWORDS = frozenset({
    "validate", "sanitize", "sanitise", "check", "verify",
    "assert",
})


def _is_validation_guard_name(name: str) -> bool:
    """Check if a call name looks like a validation guard by name pattern.

    Matches method names that START with (after stripping leading
    underscores): validate, sanitize/sanitise, check, verify, assert.

    Examples that match:
      _validate_query, self._validate_query
      _check_input, _sanitize_path, _verify_params
      validate_and_execute

    Examples that DON'T match:
      filter, unescape, get_subtype_of_stateful_step
      execute, run, _get_connection, fetch_results
    """
    # Get the last segment (e.g., self._validate_query -> _validate_query)
    last_segment = name.rsplit(".", 1)[-1].lower()
    # Strip leading underscores for matching
    stripped = last_segment.lstrip("_")
    for keyword in _VALIDATION_GUARD_KEYWORDS:
        if stripped.startswith(keyword + "_") or stripped == keyword:
            return True
    return False
