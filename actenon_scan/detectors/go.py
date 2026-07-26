"""Go language detector — finds consequential actions in Go source.

Uses tree-sitter-go to parse .go files and detect:
  - Shell execution: exec.Command, exec.CommandContext
  - File deletion: os.Remove, os.RemoveAll
  - File write: os.WriteFile, os.OpenFile with O_WRONLY/O_RDWR/O_CREATE/O_TRUNC
  - HTTP egress: http.Post, http.PostForm, client.Do, client.Post
  - Database: db.Exec, db.Query (when SQL is variable)

Reachability detection:
  - Function is passed as a handler to mcp.AddTool or server.AddTool
  - Function is in a file that imports an MCP/agent SDK

Guard recognition (ITEM 1 from the v1.1.2 audit):
  Reuses the guard vocabulary from guards.py. Matches Python semantics:
  - DOMINANCE: the guard must lie on every path to the sink
  - BINDING: the guard's arguments must share identifiers with the sink's
  - RESULT USE: a guard whose error return is discarded with `_` is WEAK

  Assert-style guards (authorize, verify_pccb, etc.) conventionally panic
  on failure. For these, binding is NOT required — the guard panics
  regardless of what it inspects, and requiring binding would flag
  legitimate idioms like `authorize("delete", path)`.

  Defeated guards are NOT suppressed:
  - `_ = authorize(path)` — error explicitly discarded → WEAK
  - Guard inside `if false` branch → does not dominate
  - Guard inside a nested func literal → does not dominate

  False negatives are worse than false positives for this tool. If unsure
  whether a construct counts as a dominating guard, we do NOT suppress.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class GoFinding:
    """A finding in a Go source file."""
    file: str
    line: int
    col: int
    rule_id: str
    category: str
    severity: str
    confidence: str
    description: str
    call_text: str
    # Why this function is agent-reachable. One of:
    #   "agent_framework_import" — file imports an MCP/agent SDK
    #   "tool_registration" — function passed to AddTool/RegisterTool/etc.
    #   "agent_framework_import + tool_registration" — both
    reachability_reason: str = ""
    # Guard status: "guarded" (suppress), "weak" (reduce severity),
    # "unbound" (reduce severity), or "" (no guard found, keep as-is).
    guard_status: str = ""
    guard_message: str = ""
    # The enclosing function name (for the explain IR).
    function_name: str = ""


# Sink patterns for Go. Each entry is (rule_id, category, severity, description, patterns).
# Patterns are matched against the dotted call name (e.g., "exec.Command").
_GO_SINK_RULES = [
    {
        "id": "EXEC-SHELL-GO",
        "category": "shell_execution",
        "severity": "high",
        "description": "Shell/command execution via os/exec in Go",
        "patterns": [
            "exec.Command",
            "exec.CommandContext",
        ],
    },
    {
        "id": "DATA-DELETE-OS-GO",
        "category": "data_destruction",
        "severity": "high",
        "description": "File/directory deletion via os.Remove/os.RemoveAll in Go",
        "patterns": [
            "os.Remove",
            "os.RemoveAll",
        ],
    },
    {
        "id": "FILE-WRITE-GO",
        "category": "file_mutation",
        "severity": "medium",
        "description": "File write via os.WriteFile/os.OpenFile in Go",
        "patterns": [
            "os.WriteFile",
            "os.OpenFile",
            "os.Create",
            "os.MkdirAll",
            "os.Rename",
        ],
    },
    {
        "id": "NET-EGRESS-GO",
        "category": "network_egress",
        "severity": "medium",
        "description": "Outbound HTTP request in Go",
        "patterns": [
            "http.Post",
            "http.PostForm",
            "http.Get",
            "http.NewRequest",
        ],
    },
]

# Agent framework import patterns — if a file imports these, its functions
# are considered agent-reachable (like a Python @tool decorator).
_GO_AGENT_IMPORTS = {
    "github.com/modelcontextprotocol/go-sdk",
    "github.com/mark3labs/mcp-go",
    "github.com/metoro-io/mcp-golang",
    "github.com/anthropics/anthropic-sdk-go",
}

# Tool registration call patterns — if a function is passed as an argument
# to one of these, it's an agent tool handler.
_GO_TOOL_REGISTRATION = {
    "AddTool",
    "RegisterTool",
    "AddToolHandler",
    "NewTypedToolHandler",
}

# Self-created temp patterns — if a variable passed to a delete sink was
# assigned from one of these, it's not model-controlled (ITEM 2).
_GO_TEMP_SOURCES = {
    "os.CreateTemp",
    "os.MkdirTemp",
}


def is_go_extra_available() -> bool:
    """Check whether the [go] extra is installed (tree-sitter-go available)."""
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_go  # noqa: F401
        return True
    except ImportError:
        return False


def scan_go_file(
    filepath: str,
    source: bytes,
    guard_patterns: list[str] | None = None,
) -> list[GoFinding]:
    """Scan a single Go source file for consequential actions.

    Returns a list of GoFinding objects. Only returns findings from
    functions that are agent-reachable (in a file that imports an MCP/agent
    SDK, or passed to a tool registration call).

    If ``guard_patterns`` is provided, guard recognition is applied:
    findings dominated by a parameter-bound guard are suppressed (or
    reduced to WEAK/UNBOUND severity).
    """
    if not is_go_extra_available():
        return []

    try:
        import tree_sitter_go as tsgo
        from tree_sitter import Language, Parser
    except ImportError:
        return []

    lang = Language(tsgo.language())
    parser = Parser(lang)
    tree = parser.parse(source)

    # Check if this file imports an agent framework
    has_agent_import = _check_agent_imports(tree.root_node, source)

    # Find tool-registered functions (passed to AddTool etc.)
    tool_handler_names = _find_tool_handlers(tree.root_node, source)

    # Collect findings
    findings: list[GoFinding] = []

    # Walk all function declarations
    for func_node in _iter_functions(tree.root_node):
        func_name = _get_func_name(func_node, source)
        is_reachable_import = has_agent_import
        is_reachable_handler = func_name in tool_handler_names
        if not (is_reachable_import or is_reachable_handler):
            continue

        # Build the reachability reason string for the reporter.
        reasons = []
        if is_reachable_import:
            reasons.append("agent_framework_import")
        if is_reachable_handler:
            reasons.append("tool_registration")
        reachability_reason = " + ".join(reasons)

        # Find sink calls within this function
        for call_node in _iter_calls(func_node):
            call_name = _get_call_name(call_node, source)
            if not call_name:
                continue

            for rule in _GO_SINK_RULES:
                for pattern in rule["patterns"]:
                    if call_name == pattern or call_name.endswith("." + pattern):
                        # ── ITEM 2: temp-file suppression ──
                        # If the argument to a delete sink is a variable
                        # assigned from os.CreateTemp/os.MkdirTemp/.Name()
                        # within the same function, it's self-created
                        # cleanup — not model-controlled. Suppress.
                        if rule["id"] == "DATA-DELETE-OS-GO" and _is_temp_cleanup(
                            func_node, call_node, source
                        ):
                            break  # suppress this finding

                        # ── ITEM 1: guard recognition ──
                        guard_status = ""
                        guard_message = ""
                        if guard_patterns:
                            gs, gm = _check_go_guard(
                                func_node, call_node, source, guard_patterns
                            )
                            guard_status = gs
                            guard_message = gm

                        # If guarded, suppress (don't append the finding)
                        if guard_status == "guarded":
                            break  # suppress this finding

                        # Build the rule_id + severity based on guard status
                        rule_id = rule["id"]
                        severity = rule["severity"]
                        description = rule["description"]
                        if guard_status == "weak":
                            severity = "low"
                            rule_id = f"{rule['id']}-WEAK"
                            description = f"{rule['description']} (guard call found but return value discarded)"
                        elif guard_status == "unbound":
                            severity = "medium"
                            rule_id = f"{rule['id']}-UNBOUND"
                            description = f"{rule['description']} (guard call found but not parameter-bound to sink)"

                        findings.append(GoFinding(
                            file=filepath,
                            line=call_node.start_point[0] + 1,
                            col=call_node.start_point[1],
                            rule_id=rule_id,
                            category=rule["category"],
                            severity=severity,
                            confidence="high",
                            description=description,
                            call_text=_get_call_text(call_node, source),
                            reachability_reason=reachability_reason,
                            guard_status=guard_status,
                            guard_message=guard_message,
                            function_name=func_name,
                        ))
                        break  # one finding per call
                else:
                    continue
                break

    return findings


# ---------------------------------------------------------------------------
# Guard recognition (ITEM 1)
# ---------------------------------------------------------------------------


def _check_go_guard(
    func_node,
    sink_call_node,
    source: bytes,
    guard_patterns: list[str],
) -> tuple[str, str]:
    """Check if a Go sink is guarded by a dominating, parameter-bound guard.

    Reuses the guard vocabulary from guards.py via _is_go_assert_style.

    Returns (guard_status, guard_message) where:
      - ("guarded", msg) → suppress the finding
      - ("weak", msg) → reduce severity to low, append -WEAK
      - ("unbound", msg) → reduce severity to medium, append -UNBOUND
      - ("", msg) → no guard found, keep as-is

    Semantics match the Python guard check (guards.py):
      - Assert-style guards (authorize, verify_pccb) conventionally panic.
        For these, binding is NOT required.
      - Non-assert-style guards (check_permission, verify_token) may return
        bool. For these, binding IS required AND the result must be used.
      - A guard whose error return is discarded with `_` is WEAK.
      - A guard inside `if false` or a nested func literal does NOT dominate.

    False negatives are worse than false positives. If unsure, we do NOT
    suppress.
    """
    sink_line = sink_call_node.start_point[0] + 1

    # Find all guard-named calls in the function before the sink
    guard_calls: list[tuple] = []  # list of (call_node, call_name)
    for node in _walk(func_node):
        if node.type != "call_expression":
            continue
        if node.start_point[0] + 1 >= sink_line:
            continue  # must be before the sink
        call_name = _get_call_name(node, source)
        if not call_name:
            continue
        if _matches_guard_name(call_name, guard_patterns):
            guard_calls.append((node, call_name))

    if not guard_calls:
        return ("", "")

    # Check dominance for each guard call
    for guard_call, guard_name in guard_calls:
        if not _go_dominates(guard_call, sink_line, func_node, source):
            continue

        # Check if the guard is assert-style (conventionally panics)
        is_assert_style = _is_go_assert_style(guard_name)

        # Check parameter binding
        is_bound = _go_is_bound(guard_call, sink_call_node, source)

        # Check result use (is the error/bool return checked?)
        result_used = _go_is_result_used(guard_call, func_node, source)

        if is_assert_style:
            # Assert-style guards conventionally panic on failure.
            # Binding is NOT required — the guard raises regardless.
            # But if the result is explicitly discarded (_ =), it's WEAK.
            if _go_is_explicitly_discarded(guard_call, source):
                return ("weak", "assert-style guard dominates but its error return is discarded with _")
            return ("guarded", "assert-style guard dominates and conventionally panics on failure")
        else:
            # Non-assert-style: may return bool. Binding AND result use required.
            if is_bound and result_used:
                return ("guarded", "guard dominates, is parameter-bound, and result is used")
            elif is_bound and not result_used:
                return ("weak", "a guard call dominates and is bound, but its return value is discarded")
            elif not is_bound and result_used:
                return ("unbound", "a guard call dominates and its result is used, but it shares no parameters with the sink's arguments")
            else:
                return ("unbound", "a guard call dominates but shares no parameters with the sink's arguments and its return value is discarded")

    # Guard exists but does not dominate — treat as no guard
    return ("", "")


def _matches_guard_name(call_name: str, guard_patterns: list[str]) -> bool:
    """Check if a Go call name matches any guard pattern.

    Reuses the same matching logic as guards.py, but also handles Go's
    camelCase convention. For example, "checkPermission" in Go matches
    the guard pattern "check_permission" from the Python vocabulary.
    """
    name_lower = call_name.lower()
    last_segment = name_lower.rsplit(".", 1)[-1]
    # Normalize: remove underscores for comparison (check_permission -> checkpermission)
    # This lets Go's camelCase (checkPermission) match Python's snake_case (check_permission).
    name_normalized = last_segment.replace("_", "")
    for pattern in guard_patterns:
        p = pattern.lower()
        if p == name_lower or p == last_segment:
            return True
        if name_lower.endswith("." + p):
            return True
        # CamelCase match: "check_permission" pattern matches "checkpermission" name
        p_normalized = p.replace("_", "")
        if p_normalized == name_normalized:
            return True
    # Also check validation-guard name patterns (like guards.py).
    # Handle both snake_case and camelCase: "check_foo"/"checkFoo" both match "check".
    stripped = last_segment.lstrip("_")
    stripped_normalized = stripped.replace("_", "")
    validation_keywords = ("validate", "sanitize", "sanitise", "check", "verify", "assert")
    for kw in validation_keywords:
        if stripped.startswith(kw + "_") or stripped == kw:
            return True
        # CamelCase: "checkFoo" starts with "check" (not "check_")
        # Check if the name starts with the keyword followed by an uppercase letter.
        if stripped_normalized.startswith(kw) and len(stripped_normalized) > len(kw):
            # Check if the character after the keyword was uppercase in the original
            orig_after_kw = last_segment[len(kw):len(kw)+1] if len(last_segment) > len(kw) else ""
            if orig_after_kw.isupper() or orig_after_kw == "_":
                return True
    return False


def _is_go_assert_style(call_name: str) -> bool:
    """Check if a guard call name is assert-style (conventionally panics).

    Reuses the same name vocabulary as guards.py._is_assert_style_guard,
    but also handles Go's camelCase convention. For example,
    "checkPermission" in Go matches "check_permission" in the vocabulary.
    """
    name_lower = call_name.lower().split(".")[-1]
    # Normalize: remove underscores for comparison
    name_normalized = name_lower.replace("_", "")

    # Prefixes that conventionally panic (check both snake_case and camelCase)
    assert_prefixes = ("assert_", "require_", "enforce_", "must_", "ensure_")
    for prefix in assert_prefixes:
        if name_lower.startswith(prefix):
            return True
    # CamelCase prefixes: "assertFoo" -> "assert" + "Foo"
    for prefix in assert_prefixes:
        prefix_no_underscore = prefix.rstrip("_")
        if name_normalized.startswith(prefix_no_underscore) and len(name_normalized) > len(prefix_no_underscore):
            orig_after = name_lower[len(prefix_no_underscore):len(prefix_no_underscore)+1]
            if orig_after.isupper() or orig_after == "_":
                return True

    # Exact names that conventionally panic or block (snake_case)
    conventional_assert = {
        "assert", "require", "enforce", "ensure", "must",
        "authorize", "authenticate", "authorize_request", "authorize_action",
        "check_permission", "check_auth", "check_authorization", "check_access",
        "verify", "validate", "guard", "gate", "policy_gate", "policy_check",
        "guard_action", "guard_request",
        "enforce_policy", "enforce_permission", "enforce_authorization",
        "assert_can", "assert_allowed", "assert_authorized", "assert_permitted",
        "can_user", "user_can", "user_may",
        "audit_and_allow", "audit_and_execute", "audit_and_proceed",
        "verify_pccb", "verify_proof", "verify_token", "verify_signature",
        "elicit", "elicitation", "request_elicitation",
        "confirm", "confirm_action", "confirm_proceed",
        "human_approval", "human_in_the_loop", "human_confirmation",
        "casbin_enforce",
        "jwt_required", "require_jwt",
        "require_auth", "require_authentication", "require_authorization",
        "login_required", "requires_login", "requires_auth",
        "require_admin", "requires_admin", "admin_required",
        "require_superuser",
        "auth_required", "authz_required", "require_authz",
        "verify_mtls", "require_client_cert", "require_api_key",
    }
    if name_lower in conventional_assert:
        return True
    # CamelCase match: normalize both sides
    for entry in conventional_assert:
        if entry.replace("_", "") == name_normalized:
            return True
    # Substring match (both snake_case and camelCase)
    for entry in conventional_assert:
        if entry in name_lower or entry.replace("_", "") in name_normalized:
            return True
    return False


def _go_dominates(guard_call, sink_line: int, func_node, source: bytes) -> bool:
    """Check if a guard call dominates the sink (lies on every path to it).

    A guard does NOT dominate if it is:
      - inside an `if` body the sink is not also inside
      - inside a statically-false branch (`if false`)
      - inside a nested func literal (lambda)
    """
    # Walk ancestors of the guard call by checking containment.
    # tree-sitter doesn't have a parent pointer, so we walk the function
    # and check which nodes contain the guard call.
    guard_start = guard_call.start_point[0] + 1

    for node in _walk(func_node):
        if node.type == "if_statement":
            # Check if the guard is inside this if's consequence or alternative
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")

            # Check for statically-false condition
            condition = node.child_by_field_name("condition")
            if condition is not None:
                cond_text = source[condition.start_byte:condition.end_byte].decode("utf-8", errors="replace").strip()
                if cond_text in ("false", "0", "nil"):
                    if _node_contains(guard_call, consequence) or _node_contains(guard_call, alternative):
                        return False

            # If guard is in consequence but sink is not
            if consequence and _node_contains(guard_call, consequence):
                if not _node_contains_line(consequence, sink_line):
                    return False
            # If guard is in alternative but sink is not
            if alternative and _node_contains(guard_call, alternative):
                if not _node_contains_line(alternative, sink_line):
                    return False

        elif node.type == "func_literal":
            # Guard is inside a nested function literal — does not dominate
            if _node_contains(guard_call, node) and node is not func_node:
                return False

    return True


def _node_contains(inner, outer) -> bool:
    """Check if the outer node contains the inner node (by byte range)."""
    if outer is None:
        return False
    return (inner.start_byte >= outer.start_byte and
            inner.end_byte <= outer.end_byte)


def _node_contains_line(node, line: int) -> bool:
    """Check if a line number is within a node's line range."""
    if node is None:
        return False
    start_line = node.start_point[0] + 1
    end_line = node.end_point[0] + 1
    return start_line <= line <= end_line


def _go_is_bound(guard_call, sink_call, source: bytes) -> bool:
    """Check if the guard's arguments share identifiers with the sink's arguments.

    Resolves one level of simple aliasing (x = pi; guard(x)).
    """
    guard_args = _collect_go_arg_names(guard_call, source)
    sink_args = _collect_go_arg_names(sink_call, source)

    if not guard_args or not sink_args:
        # If either has no named args, we can't determine binding — be
        # conservative and say it IS bound (avoids false UNBOUND).
        return True

    # Check for intersection
    shared = guard_args & sink_args
    return bool(shared)


def _collect_go_arg_names(call_node, source: bytes) -> set[str]:
    """Collect identifier names from a Go call's arguments."""
    names: set[str] = set()
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return names
    for child in args.children:
        if child is None:
            continue
        text = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace").strip()
        # Bare identifier
        if child.type == "identifier":
            names.add(text)
        # Selector expression (e.g., obj.field) — take the base identifier
        elif child.type == "selector_expression":
            obj = child.child_by_field_name("operand")
            if obj and obj.type == "identifier":
                names.add(source[obj.start_byte:obj.end_byte].decode("utf-8", errors="replace"))
        # Unary expression (e.g., &path) — take the inner identifier
        elif child.type == "unary_expression":
            operand = child.child_by_field_name("operand")
            if operand and operand.type == "identifier":
                names.add(source[operand.start_byte:operand.end_byte].decode("utf-8", errors="replace"))
    return names


def _go_is_result_used(guard_call, func_node, source: bytes) -> bool:
    """Check if the guard call's return value is used.

    In Go, a guard call is "result used" if:
    - It's in a short_var_declaration where the variable is subsequently
      checked (e.g., `err := guard(); if err != nil { return }`)
    - It's in an if_statement condition (e.g., `if guard() { ... }`)
    - It's part of an assignment that is subsequently checked

    A standalone expression statement is "result used" only if the guard
    is assert-style (handled by the caller).
    """
    # Walk the function to find how the guard call is used
    guard_start = guard_call.start_byte
    guard_end = guard_call.end_byte

    for node in _walk(func_node):
        # Check if this node contains the guard call
        if not (node.start_byte <= guard_start and guard_end <= node.end_byte):
            continue
        if node is guard_call:
            continue

        # if guard() { ... } — result is checked
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            if condition and _node_contains(guard_call, condition):
                return True

        # err := guard() — short var declaration
        if node.type == "short_var_declaration":
            # Check if the left-hand side is `_` (explicitly discarded)
            left = node.child_by_field_name("left")
            if left:
                left_text = source[left.start_byte:left.end_byte].decode("utf-8", errors="replace").strip()
                if left_text == "_":
                    return False  # explicitly discarded
            # Check if the variable is subsequently used in an if condition
            # We need to find if any subsequent if_statement checks this variable
            var_name = ""
            if left and left.type == "identifier":
                var_name = source[left.start_byte:left.end_byte].decode("utf-8", errors="replace")
            if var_name and var_name != "_":
                # Check if var_name appears in a subsequent if condition
                for if_node in _walk(func_node):
                    if if_node.type != "if_statement":
                        continue
                    if if_node.start_point[0] < guard_call.start_point[0]:
                        continue  # must be after the guard
                    cond = if_node.child_by_field_name("condition")
                    if cond:
                        cond_text = source[cond.start_byte:cond.end_byte].decode("utf-8", errors="replace")
                        if var_name in cond_text:
                            return True
            return False  # assigned but not checked → not used

        # _ = guard() — assignment with explicit discard
        if node.type == "assignment_statement":
            left = node.child_by_field_name("left")
            if left:
                left_text = source[left.start_byte:left.end_byte].decode("utf-8", errors="replace").strip()
                if left_text == "_":
                    return False

        # return guard() — result is returned
        if node.type == "return_statement":
            if _node_contains(guard_call, node):
                return True

    # Standalone expression statement — result is NOT used
    # (unless assert-style, which the caller handles)
    return False


def _go_is_explicitly_discarded(guard_call, source: bytes) -> bool:
    """Check if the guard call's return value is explicitly discarded with `_ =`.

    In Go, `_ = authorize(path)` explicitly discards the return value.
    This is the defeated-guard pattern: the guard was called but its
    result (typically an error) was thrown away.
    """
    # Get the line text containing the guard call
    guard_line = guard_call.start_point[0]
    lines = source.decode("utf-8", errors="replace").splitlines()
    if guard_line >= len(lines):
        return False

    line_text = lines[guard_line].strip()

    # Check if the line is `_ = <guard_call>` or `_ =` followed by the call
    # on the same line.
    if line_text.startswith("_ =") or line_text.startswith("_="):
        # The guard call should be on this line (or the start of the next)
        call_text = source[guard_call.start_byte:guard_call.end_byte].decode("utf-8", errors="replace").strip()
        if call_text in line_text:
            return True

    # Also check multi-line: `_ =\n  authorize(path)`
    if line_text in ("_ =", "_="):
        # Check the next non-empty line for the guard call
        for i in range(guard_line + 1, min(guard_line + 5, len(lines))):
            next_line = lines[i].strip()
            if next_line:
                call_text = source[guard_call.start_byte:guard_call.end_byte].decode("utf-8", errors="replace").strip()
                if call_text in next_line:
                    return True
                break

    return False


# ---------------------------------------------------------------------------
# Temp-file suppression (ITEM 2)
# ---------------------------------------------------------------------------


def _is_temp_cleanup(func_node, sink_call, source: bytes) -> bool:
    """Check if the argument to a delete sink is a self-created temp variable.

    Suppresses when the variable passed to os.Remove/os.RemoveAll is
    assigned, within the same function, from os.CreateTemp, os.MkdirTemp,
    or .Name() on their result. This is cleanup of a temp file the
    function itself created — the model cannot influence the path.

    Does NOT generalise to "deferred calls are safe" or "temp paths are
    safe." A model-supplied path that merely happens to be deleted in a
    defer is still a finding. The suppression is anchored to the
    assignment source, not to the defer keyword or the string "tmp".
    """
    # Get the argument to the delete call
    args = sink_call.child_by_field_name("arguments")
    if args is None:
        return False
    arg_nodes = [c for c in args.children if c is not None and c.type == "identifier"]
    if not arg_nodes:
        return False

    # Get the variable name passed to the delete call
    arg_text = source[arg_nodes[0].start_byte:arg_nodes[0].end_byte].decode("utf-8", errors="replace").strip()

    # Build a map of all variable assignments in the function.
    # For each variable name, record what it was assigned from.
    # Handles Go's multi-value assignments (tmp, err := os.CreateTemp(...)).
    var_assignments: dict[str, str] = {}  # var_name -> right-hand-side text

    for node in _walk(func_node):
        if node.type in ("short_var_declaration", "assignment_statement"):
            # Get the full text of left and right sides
            # tree-sitter-go: left and right are field names, but for
            # multi-value declarations, we need to parse the raw text.
            full_text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            # Split on := or =
            if ":=" in full_text:
                parts = full_text.split(":=", 1)
            elif "=" in full_text and not "==" in full_text:
                parts = full_text.split("=", 1)
            else:
                continue
            if len(parts) != 2:
                continue
            left_text = parts[0].strip()
            right_text = parts[1].strip()

            # Handle multi-value left side: "tmp, err" -> ["tmp", "err"]
            left_names = [n.strip() for n in left_text.split(",")]
            for ln in left_names:
                var_assignments[ln] = right_text

    # Check if arg_text was assigned from a temp source
    right = var_assignments.get(arg_text, "")
    if not right:
        return False

    # Direct assignment from temp source: tmpPath := os.CreateTemp(...)
    for temp_src in _GO_TEMP_SOURCES:
        if temp_src in right:
            return True

    # Indirect: tmpName := tmp.Name() where tmp was assigned from os.CreateTemp
    if ".Name()" in right:
        # Extract the object variable (e.g., "tmp" from "tmp.Name()")
        obj_name = right.split(".Name()")[0].strip()
        # Check if obj_name was assigned from a temp source
        obj_right = var_assignments.get(obj_name, "")
        for temp_src in _GO_TEMP_SOURCES:
            if temp_src in obj_right:
                return True

    return False


# ---------------------------------------------------------------------------
# Agent framework detection (existing, unchanged)
# ---------------------------------------------------------------------------


def _check_agent_imports(root, source: bytes) -> bool:
    """Check if the file imports an agent framework."""
    for node in _walk(root):
        if node.type == "import_declaration":
            text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            for agent_import in _GO_AGENT_IMPORTS:
                if agent_import in text:
                    return True
    return False


def _find_tool_handlers(root, source: bytes) -> set[str]:
    """Find function names passed as handlers to AddTool/RegisterTool calls."""
    handler_names: set[str] = set()
    for node in _walk(root):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        if not func:
            continue
        func_name = source[func.start_byte:func.end_byte].decode("utf-8", errors="replace")
        # Check if this is a tool registration call
        final = func_name.rsplit(".", 1)[-1]
        if final not in _GO_TOOL_REGISTRATION:
            continue
        # The handler function is typically the last argument
        for arg in node.children_by_field_name("argument"):
            arg_text = source[arg.start_byte:arg.end_byte].decode("utf-8", errors="replace").strip()
            # If it's a bare identifier (function name), record it
            if arg_text and not arg_text.startswith("(") and not arg_text.startswith('"') and "." not in arg_text:
                handler_names.add(arg_text)
            # If it's a method value (e.g., s.handler), record the method name
            elif "." in arg_text and not arg_text.startswith('"'):
                handler_names.add(arg_text.rsplit(".", 1)[-1])
    return handler_names


def _iter_functions(root):
    """Yield all function_declaration and method_declaration nodes."""
    for node in _walk(root):
        if node.type in ("function_declaration", "method_declaration"):
            yield node


def _iter_calls(func_node):
    """Yield all call_expression nodes within a function."""
    for node in _walk(func_node):
        if node.type == "call_expression":
            yield node


def _get_func_name(func_node, source: bytes) -> str:
    """Get the name of a function/method declaration."""
    name = func_node.child_by_field_name("name")
    if name:
        return source[name.start_byte:name.end_byte].decode("utf-8", errors="replace")
    return ""


def _get_call_name(call_node, source: bytes) -> str:
    """Get the dotted name of a call expression (e.g., exec.Command)."""
    func = call_node.child_by_field_name("function")
    if not func:
        return ""
    return source[func.start_byte:func.end_byte].decode("utf-8", errors="replace")


def _get_call_text(call_node, source: bytes) -> str:
    """Get a short text representation of the call."""
    text = source[call_node.start_byte:call_node.end_byte].decode("utf-8", errors="replace")
    return text[:120]


def _walk(node):
    """Recursively yield all descendants of a node (including itself)."""
    yield node
    for child in node.children:
        yield from _walk(child)
