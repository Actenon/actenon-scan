"""Reachability detector — determines if a sink is agent-reachable."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Literal


@dataclass
class ReachabilityResult:
    confidence: Literal["none", "medium", "high"] = "none"
    signals: list[str] = None

    def __post_init__(self):
        if self.signals is None:
            self.signals = []


def detect_reachability(
    tree: ast.Module,
    sink_line: int,
    reachability_cfg: dict[str, Any],
    *,
    self_package: str | None = None,
) -> ReachabilityResult:
    """Determine if the sink at sink_line is agent-reachable.

    Checks the enclosing function and module for agent/tool signals.

    Confidence levels:
    - HIGH: sink is inside a @tool-decorated function, a tool-wrapper function,
      a method of a class subclassing a tool base class, or a function passed
      in a tools=[...] list to an agent constructor.
    - MEDIUM: sink is at MODULE LEVEL (not inside any function) and the module
      imports an agent framework. This catches bare calls in framework-importing
      scripts. Sinks inside NON-TOOL functions do NOT get MEDIUM confidence —
      a regular internal function that happens to be in a framework's own repo
      is not agent-reachable just because the file imports the framework.
    - none: sink is inside a non-tool function, or no agent signals found.

    Self-scan suppression: if self_package is set and the module imports that
    package, the agent_framework_import signal is suppressed. This prevents
    scanning a framework's own repo from generating noise on every internal
    function.
    """
    result = ReachabilityResult()

    # Find the function that contains the sink
    func_node = _find_enclosing_function(tree, sink_line)
    if func_node is None:
        # Not in a function — check module-level signals
        return _check_module_signals(tree, reachability_cfg, self_package, sink_line=sink_line)

    return _reachability_for_func(tree, func_node, reachability_cfg, self_package, sink_line)


def _reachability_for_func(
    tree: ast.Module,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    reachability_cfg: dict[str, Any],
    self_package: str | None,
    sink_line: int,
) -> ReachabilityResult:
    """Compute reachability for a known enclosing FunctionDef.

    Phase 5.1: split out of detect_reachability so that callers that already
    hold the FunctionDef (notably detect_same_class_method_reachability, when
    walking nested entrypoints whose ``def`` line is inside an outer method)
    can bypass the line-based _find_enclosing_function lookup. That lookup
    returns the OUTERMOST function whose span contains the line, so for a
    nested ``@tool`` function defined inside ``__init__`` it would resolve
    to ``__init__`` (no decorator) instead of the nested entrypoint.
    """
    result = ReachabilityResult()

    # Check for HIGH confidence: tool decorators on the function
    tool_decorators = reachability_cfg.get("tool_decorators", [])
    if _has_tool_decorator(func_node, tool_decorators):
        result.confidence = "high"
        result.signals.append("tool_decorator")
        return result

    # Work Order 2, Phase 3: resource-boundary entry points.
    # FastAPI/Flask/Django route handlers, CLI commands. These are web
    # endpoints that receive external input — a different entry-point
    # class than agent tool handlers, but equally consequential.
    #
    # Task 4c (bare-verb reconciliation): this signal is now OPT-IN.
    # A route decorator is not evidence that an agent is involved. The
    # README's headline question is "what can your AI agent do without
    # permission?", and a Flask tutorial with no agent framework is not
    # an answer to that question. Enable with --resource-boundary or the
    # config key reachability.resource_boundary_enabled.
    if not reachability_cfg.get("resource_boundary_enabled", False):
        resource_decorators = []
    else:
        resource_decorators = reachability_cfg.get("resource_boundary_decorators", [])
    if resource_decorators and _has_resource_boundary_decorator(func_node, resource_decorators):
        result.confidence = "high"
        result.signals.append("resource_boundary")
        return result

    # Check for HIGH confidence: tool wrapper calls (Tool.from_function, etc.)
    tool_wrappers = reachability_cfg.get("tool_wrappers", [])
    if _is_wrapped_as_tool(tree, func_node.name, tool_wrappers):
        result.confidence = "high"
        result.signals.append("tool_wrapper")
        return result

    # Check for HIGH confidence: method of a class subclassing a tool base
    tool_base_classes = reachability_cfg.get("tool_base_classes", [])
    tool_methods = reachability_cfg.get("tool_methods", [])
    if _is_tool_method(tree, func_node, tool_base_classes, tool_methods):
        result.confidence = "high"
        result.signals.append("tool_base_class_method")
        return result

    # Check for HIGH confidence: function passed in a tools=[...] / plugins=[...]
    # argument to any constructor call. This is how Agno, smolagents, CrewAI,
    # and OpenAI Agents SDK register tools.
    tool_list_params = reachability_cfg.get("tool_list_params", [])
    if tool_list_params and _is_in_tool_list(tree, func_node.name, tool_list_params):
        result.confidence = "high"
        result.signals.append("tool_list_param")
        return result

    # HIGH confidence: the sink sits in a branch selected by a tool name that
    # this module declares in an LLM tool-schema literal. Raw schema dispatch
    # is a tool boundary with no decorator to announce it.
    if _is_tool_schema_dispatch(tree, func_node, sink_line):
        result.confidence = "high"
        result.signals.append("tool_schema_dispatch")
        return result

    # HIGH confidence: the sink consumes an executable payload off a parameter
    # annotated as an agent action type (CmdRunAction.command, etc.). The
    # action/observation architecture dispatches through plain methods.
    if _is_action_dispatch(func_node, sink_line):
        result.confidence = "high"
        result.signals.append("action_dispatch")
        return result

    # The sink is inside a NON-TOOL function. Even if the module imports an
    # agent framework, a regular internal function is not agent-reachable.
    # Without this gate, every file in a framework's own repo (where every
    # file imports the framework) would have all its sinks flagged.
    return result


def _find_enclosing_function(tree: ast.Module, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find the function definition that encloses the given line number."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line:
                end_line = getattr(node, "end_lineno", None)
                if end_line is not None and line <= end_line:
                    return node
                # Fallback: check if any child has a lineno >= the sink line
                for child in ast.walk(node):
                    if hasattr(child, "lineno") and child.lineno >= line:
                        return node
    return None


def _is_inside_main_block(tree: ast.Module, line: int) -> bool:
    """Check if a line is inside an `if __name__ == "__main__":` block.

    Entry-point code in __main__ blocks is NOT agent-reachable — it runs
    when the script is executed directly, not when an agent calls a tool.
    This fixes 5 of 8 false positives in the corpus validation.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            # Check if the test is `__name__ == "__main__"`
            test = node.test
            if isinstance(test, ast.Compare):
                if isinstance(test.left, ast.Name) and test.left.id == "__name__":
                    for comp in test.comparators:
                        if isinstance(comp, ast.Constant) and comp.value == "__main__":
                            # Check if the sink line is inside this if block
                            if node.lineno <= line:
                                end_line = getattr(node, "end_lineno", None)
                                if end_line is not None and line <= end_line:
                                    return True
    return False


def _is_inside_class_body(tree: ast.Module, line: int) -> bool:
    """Check if a line is inside a class body (not in a method).

    Sinks in class-body assignments (e.g., Pydantic ConfigDict with
    lambda serializers) are not agent-reachable. The lambda has no
    enclosing FunctionDef, so it appears to be at module level — but
    it's actually in a class body.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if node.lineno <= line:
                end_line = getattr(node, "end_lineno", None)
                if end_line is not None and line <= end_line:
                    # Check it's NOT inside a method (FunctionDef within the class)
                    for child in ast.walk(node):
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            if child.lineno <= line:
                                child_end = getattr(child, "end_lineno", None)
                                if child_end is not None and line <= child_end:
                                    return False  # It's inside a method, not class body
                    return True
    return False


def _has_tool_decorator(func_node: ast.FunctionDef | ast.AsyncFunctionDef, tool_decorators: list[str]) -> bool:
    """Check if the function has a tool decorator.

    Phase 5: also matches the LAST SEGMENT of attribute-chain decorators
    against tool_decorators. This is what lets ``@self.server.call_tool()``
    match the existing ``"call_tool"`` entry — the MCP callback-registration
    pattern used by browser-use/browser_use/mcp/cli_mcp.py (and the same
    suffix-matching policy that ``_has_resource_boundary_decorator`` already
    applies to ``@app.get("/path")``).
    """
    for decorator in func_node.decorator_list:
        name = _get_decorator_name(decorator)
        # Exact match (e.g., "tool", "mcp.tool", "call_tool")
        if name in tool_decorators:
            return True
        # Suffix match for attribute-chain decorators. Catches
        # @self.server.call_tool() -> "call_tool" and @app.tool() -> "tool".
        # Consistent with _has_resource_boundary_decorator.
        if "." in name:
            last_segment = name.rsplit(".", 1)[-1]
            if last_segment in tool_decorators:
                return True
    return False


def _has_resource_boundary_decorator(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    resource_decorators: list[str],
) -> bool:
    """Check if the function has a resource-boundary decorator.

    Work Order 2, Phase 3: detects FastAPI/Flask/Django route handlers
    and CLI commands. These are called decorators (@app.get("/path"),
    @app.route("/"), @click.command()) rather than bare names (@tool).

    The _get_decorator_name function already handles ast.Call by
    extracting the function name, so @app.get("/path") resolves to
    "app.get" which is matched against the resource_decorators list.
    """
    for decorator in func_node.decorator_list:
        name = _get_decorator_name(decorator)
        # Check exact match (e.g., "app.get", "router.post")
        if name in resource_decorators:
            return True
        # Check suffix match for bare forms (e.g., "get" matches
        # "app.get", "router.get", etc. — this catches @get("/path")
        # used by FastAPI's APIRouter and other frameworks)
        last_segment = name.rsplit(".", 1)[-1]
        if last_segment in resource_decorators:
            return True
    return False


def _get_decorator_name(node: ast.expr) -> str:
    """Get the name of a decorator (handles @tool, @mcp.tool, etc.)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_get_attribute_chain(node)}"
    if isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return ""


def _get_attribute_chain(node: ast.Attribute) -> str:
    """Get the full dotted name of an attribute (e.g., mcp.tool)."""
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _is_wrapped_as_tool(tree: ast.Module, func_name: str, tool_wrappers: list[str]) -> bool:
    """Check if the function is referenced in a tool wrapper call like
    Tool.from_function(func_name) or @tool."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Check if any argument is a reference to our function
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id == func_name:
                    # Check if the call target is a known wrapper
                    call_name = _get_call_name(node.func)
                    for wrapper in tool_wrappers:
                        if wrapper in call_name or call_name in wrapper:
                            return True
    return False


def _get_call_name(node: ast.expr) -> str:
    """Get the name of a call target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _get_attribute_chain(node)
    return ""


def _is_tool_method(
    tree: ast.Module,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    tool_base_classes: list[str],
    tool_methods: list[str],
) -> bool:
    """Check if the function is a _run/_arun method of a class that
    subclasses a known tool base class."""
    if func_node.name not in tool_methods:
        return False
    # Find the enclosing class
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            # Check if func_node is a child of this class
            for child in node.body:
                if child is func_node:
                    # Check bases
                    for base in node.bases:
                        base_name = _get_base_name(base)
                        if base_name in tool_base_classes:
                            return True
    return False


def _get_base_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _get_attribute_chain(node)
    return ""


def _imports_agent_framework(tree: ast.Module, frameworks: list[str]) -> bool:
    """Check if the module imports any agent framework."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for fw in frameworks:
                    if alias.name.startswith(fw) or fw in alias.name:
                        return True
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for fw in frameworks:
                    if node.module.startswith(fw) or fw in node.module:
                        return True
    return False


def _is_in_tool_list(tree: ast.Module, func_name: str, tool_list_params: list[str]) -> bool:
    """Check if the function is referenced inside a tools=[...] / plugins=[...]
    argument to any constructor call.

    This detects the Agno/smolagents/CrewAI/OpenAI Agents SDK pattern:
        agent = Agent(tools=[my_tool_func, other_tool])
        agent = Agno(toolkits=[my_toolkit])

    Phase 5.2 extends the original bare-Name matching to recognise the
    two additional registration shapes that appear in real Agno Toolkit
    subclasses (modelcontextprotocol-registered tools):

      1. ``self.<method>`` references inside the list/tuple literal —
         ``super().__init__(tools=[self.scrape_website])``.
      2. The "local list assigned once, then passed" shape —
         ``tools = [self.scrape_website, ...]; super().__init__(tools=tools)``.

    Conservative constraints (per Phase 5.2 brief):
      - The list literal must be assigned exactly once and not reassigned
        before being passed to the registration kwarg. Anything mutating it
        via ``.append()``, ``.extend()``, or ``getattr(self, name)`` is
        dynamic registration and is NOT resolved — those are disclosed as
        unresolved entry points instead.
      - Generic ``callbacks=`` arguments and event handlers are NOT tools;
        they are not in tool_list_params and so are never matched here.
    """
    # Pattern 1: direct list/tuple literal passed as a registration kwarg
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg in tool_list_params and isinstance(kw.value, (ast.List, ast.Tuple)):
                if _list_contains_func_ref(kw.value.elts, func_name):
                    return True

    # Pattern 2: local list variable assigned exactly once (as a list/tuple
    # literal) and then passed as a registration kwarg. We track every
    # assignment target whose RHS is a list/tuple literal containing the
    # function reference. If the same target is reassigned (e.g., via
    # .append/.extend, or a second literal assignment, or a non-literal RHS),
    # the variable is marked dynamic and excluded.
    list_var_state: dict[str, str] = {}  # var_name -> "clean" | "dynamic"
    for node in ast.walk(tree):
        # ast.Assign: tools = [...] or tools = something_else
        if isinstance(node, ast.Assign):
            value_is_literal_list = isinstance(node.value, (ast.List, ast.Tuple))
            for tgt in node.targets:
                if not isinstance(tgt, ast.Name):
                    continue
                prev = list_var_state.get(tgt.id)
                if prev is not None:
                    list_var_state[tgt.id] = "dynamic"
                    continue
                if value_is_literal_list:
                    contains = _list_contains_func_ref(node.value.elts, func_name)
                    list_var_state[tgt.id] = "clean" if contains else "neutral"
                else:
                    list_var_state[tgt.id] = "dynamic"
        # ast.AnnAssign: tools: List[Any] = [...] — Agno's preferred form.
        # Without this branch, every Agno Toolkit subclass (where the local
        # list is type-annotated) would be missed.
        elif isinstance(node, ast.AnnAssign):
            if (isinstance(node.target, ast.Name)
                    and isinstance(node.value, (ast.List, ast.Tuple))):
                tgt = node.target.id
                prev = list_var_state.get(tgt)
                if prev is not None:
                    list_var_state[tgt] = "dynamic"
                    continue
                contains = _list_contains_func_ref(node.value.elts, func_name)
                list_var_state[tgt] = "clean" if contains else "neutral"
        # Mutating calls (list.append/extend/insert) and getattr() comprehensions
        # mark any list variable as dynamic.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("append", "extend", "insert"):
                if node.func.value and isinstance(node.func.value, ast.Name):
                    name = node.func.value.id
                    if name in list_var_state:
                        list_var_state[name] = "dynamic"

    clean_list_vars = {v for v, s in list_var_state.items() if s == "clean"}
    if not clean_list_vars:
        return False

    # Now look for any call that passes one of these clean list vars as a
    # registration kwarg.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if (
                kw.arg in tool_list_params
                and isinstance(kw.value, ast.Name)
                and kw.value.id in clean_list_vars
            ):
                return True
    return False


def _list_contains_func_ref(elts: list, func_name: str) -> bool:
    """True if any element is ``func_name`` (bare Name) or ``self.func_name``
    (Attribute access on ``self``), or a ``Tool(func_name)`` wrapper around
    either of those."""
    for elt in elts:
        if isinstance(elt, ast.Name) and elt.id == func_name:
            return True
        if (
            isinstance(elt, ast.Attribute)
            and elt.attr == func_name
            and isinstance(elt.value, ast.Name)
            and elt.value.id == "self"
        ):
            return True
        # Tool(func_name) / Tool.from_function(self.func_name) wrapper
        if isinstance(elt, ast.Call):
            for arg in elt.args:
                if isinstance(arg, ast.Name) and arg.id == func_name:
                    return True
                if (
                    isinstance(arg, ast.Attribute)
                    and arg.attr == func_name
                    and isinstance(arg.value, ast.Name)
                    and arg.value.id == "self"
                ):
                    return True
    return False


# ---------------------------------------------------------------------------
# Raw tool-schema dispatch (benchmark recall case r07)
#
# An agent boundary announced by a schema literal rather than a decorator:
#
#     TOOLS = [{"type": "function",
#               "function": {"name": "run_command", "parameters": {...}}}]
#
#     def dispatch_tool(name, args):
#         if name == "run_command":
#             subprocess.run(args["command"], shell=True)   # <- the boundary
#
# Both halves are required: the schema literal supplies the tool name, and the
# sink must sit in the branch that name selects. Detection-only measurement
# across 7,359 files of the ten-repo corpus produced zero candidates, so this
# adds no measured false positives — and no measured real detections either.
# See docs/COVERAGE.md.
# ---------------------------------------------------------------------------

_SCHEMA_PARAM_KEYS = frozenset({"parameters", "input_schema", "inputSchema", "args_schema"})


def _declared_tool_names(tree: ast.Module) -> set[str]:
    """Tool names declared in an LLM tool-schema literal in this module.

    Recognises the OpenAI nested form:
        {"type": "function", "function": {"name": "run_command", ...}}
    and the flat Anthropic / OpenAI-legacy form:
        {"name": "run_command", "description": ..., "input_schema": {...}}
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = {
            k.value for k in node.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }

        if "type" in keys and "function" in keys:
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "function"
                    and isinstance(value, ast.Dict)
                ):
                    names |= _dict_string_value(value, "name")

        if "name" in keys and (keys & _SCHEMA_PARAM_KEYS):
            names |= _dict_string_value(node, "name")

    return names


def _dict_string_value(node: ast.Dict, wanted: str) -> set[str]:
    """Extract a string value for a given key from a dict literal."""
    out: set[str] = set()
    for key, value in zip(node.keys, node.values):
        if (
            isinstance(key, ast.Constant)
            and key.value == wanted
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            out.add(value.value)
    return out


def _is_tool_schema_dispatch(
    tree: ast.Module,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    sink_line: int,
) -> bool:
    """Check if the sink sits in a branch selected by a declared tool name."""
    declared = _declared_tool_names(tree)
    if not declared:
        return False

    for node in ast.walk(func_node):
        if isinstance(node, ast.If):
            if _test_matches_declared_name(node.test, declared) and (
                _stmts_contain_line(node.body, sink_line)
                or _stmts_contain_line(node.orelse, sink_line)
            ):
                return True

        elif isinstance(node, ast.Match):
            for case in node.cases:
                for sub in ast.walk(case.pattern):
                    if (
                        isinstance(sub, ast.MatchValue)
                        and isinstance(sub.value, ast.Constant)
                        and sub.value.value in declared
                        and _stmts_contain_line(case.body, sink_line)
                    ):
                        return True

    return False


def _test_matches_declared_name(test: ast.expr, declared: set[str]) -> bool:
    """Check if a branch test compares against a declared tool name."""
    for node in ast.walk(test):
        if not isinstance(node, ast.Compare):
            continue
        if any(isinstance(op, ast.Eq) for op in node.ops):
            for side in [node.left, *node.comparators]:
                if isinstance(side, ast.Constant) and side.value in declared:
                    return True
        if any(isinstance(op, ast.In) for op in node.ops):
            for side in node.comparators:
                if isinstance(side, (ast.List, ast.Tuple, ast.Set)):
                    for elt in side.elts:
                        if isinstance(elt, ast.Constant) and elt.value in declared:
                            return True
    return False


def _stmts_contain_line(stmts: list, line: int) -> bool:
    for stmt in stmts:
        start = getattr(stmt, "lineno", None)
        end = getattr(stmt, "end_lineno", None)
        if start is not None and end is not None and start <= line <= end:
            return True
    return False


# ---------------------------------------------------------------------------
# Action / observation dispatch (benchmark recall case r06)
#
#     @dataclass
#     class CmdRunAction:
#         command: str
#
#     def _run_cmd(self, action: CmdRunAction):
#         subprocess.run(action.command, shell=True)   # <- the boundary
#
# The anchor is dataflow, not naming: the parameter must be annotated with an
# action-suffixed type AND the sink must read an executable-payload attribute
# off that exact parameter. A method that merely takes an action and happens to
# contain a sink does not qualify.
#
# Detection-only measurement across the ten-repo corpus produced zero
# candidates. See docs/COVERAGE.md.
# ---------------------------------------------------------------------------

_ACTION_TYPE_SUFFIXES = ("Action", "Command", "Instruction", "Invocation", "ToolCall")

_ACTION_PAYLOAD_FIELDS = frozenset({
    "command", "cmd", "code", "script", "shell", "path", "file_path",
    "content", "query", "url", "args", "arguments", "payload", "sql",
})


def _is_action_dispatch(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    sink_line: int,
) -> bool:
    """Check if the sink executes a payload carried by an action parameter."""
    action_params = _action_typed_params(func_node)
    if not action_params:
        return False

    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call) or getattr(node, "lineno", None) != sink_line:
            continue
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            for sub in ast.walk(arg):
                if (
                    isinstance(sub, ast.Attribute)
                    and isinstance(sub.value, ast.Name)
                    and sub.value.id in action_params
                    and sub.attr in _ACTION_PAYLOAD_FIELDS
                ):
                    return True
    return False


def _action_typed_params(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Parameters annotated with a type whose name looks like an agent action.

    The annotation is matched by name only, so an action class imported from
    another module works exactly like one defined locally.
    """
    params: set[str] = set()
    args = func_node.args
    for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        if arg.annotation is None:
            continue
        for sub in ast.walk(arg.annotation):
            name = None
            if isinstance(sub, ast.Name):
                name = sub.id
            elif isinstance(sub, ast.Attribute):
                name = sub.attr
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                name = sub.value  # string annotation / forward reference
            if name and name.endswith(_ACTION_TYPE_SUFFIXES):
                params.add(arg.arg)
                break
    return params


def _check_module_signals(
    tree: ast.Module,
    reachability_cfg: dict[str, Any],
    self_package: str | None = None,
    sink_line: int | None = None,
) -> ReachabilityResult:
    """Check module-level signals when the sink is not in a function.

    Self-scan suppression: if self_package is set and the module imports that
    package, the agent_framework_import signal is suppressed. This prevents
    scanning a framework's own repo (e.g., scanning crewai's own codebase)
    from generating noise on every internal module.

    __main__ block exclusion: sinks inside `if __name__ == "__main__":`
    are NOT agent-reachable. Entry-point code runs when the script is
    executed directly, not when an agent calls a tool.

    Class-body exclusion: sinks in class-body assignments (e.g., Pydantic
    ConfigDict with lambda serializers) are NOT agent-reachable.
    """
    # If we know the sink line, check exclusions
    if sink_line is not None:
        if _is_inside_main_block(tree, sink_line):
            return ReachabilityResult()
        if _is_inside_class_body(tree, sink_line):
            return ReachabilityResult()

    agent_frameworks = reachability_cfg.get("agent_frameworks", [])
    if self_package:
        # Remove the self-package from the frameworks list for this check
        agent_frameworks = [fw for fw in agent_frameworks if fw != self_package]
    if not _imports_agent_framework(tree, agent_frameworks):
        return ReachabilityResult()

    # Module-level code runs at IMPORT time. An LLM cannot select or invoke
    # it, so by the reachability model it is not agent-reachable — the same
    # reasoning that already excludes `if __name__ == "__main__":` blocks
    # above, applied consistently to all module scope.
    #
    # Measured: on the 25-repo corpus this signal produced 19 findings and
    # all 19 were false positives — demo and cookbook setup (`os.remove`
    # of a scratch db before constructing an Agent, `shutil.rmtree` of a
    # seed directory). Precision 0/19. It is off by default and kept behind
    # a flag rather than deleted, so the signal is recoverable for anyone
    # who wants it. See FINDINGS.md.
    if reachability_cfg.get("module_level_reachability", False):
        return ReachabilityResult(confidence="medium", signals=["module_level_agent_import"])
    return ReachabilityResult()


# ---------------------------------------------------------------------------
# Task 2: Same-file, same-class method resolution.
#
# Ground truth (research/reachability-ground-truth/labels.json): 12 of 14
# confirmed AGENT_REACHABLE cases are METHODS. 9 of 14 same-file. 8 single-hop.
# Nothing beyond 3 hops. The existing per-file reachability detector treats
# a sink in a non-@tool method as not-reachable. This function closes that
# gap for the SAME-CLASS case: when an agent-reachable method calls self.x()
# and x is defined in the same class, propagate reachability.
#
# Conservative constraints (per brief):
#   - Same-file, same-class ONLY. No cross-file, no inheritance, no dynamic
#     dispatch.
#   - Resolve only when exactly one definition matches in that class body
#     and the name is not shadowed or reassigned. Anything else → unfollowed.
#   - max_hops=3 (configurable). Chains deeper than this are marked
#     unfollowed, not silently followed.
#   - Confidence is MEDIUM (below an in-body sink which is HIGH).
#   - A guard dominating the call site in the CALLER counts as dominating
#     for the callee — same rule as the per-file detector.
# ---------------------------------------------------------------------------

# Default max_hops for same-class method resolution.
DEFAULT_SAME_CLASS_MAX_HOPS = 3


def detect_same_class_method_reachability(
    tree: ast.Module,
    reachability_cfg: dict[str, Any],
    *,
    self_package: str | None = None,
    max_hops: int = DEFAULT_SAME_CLASS_MAX_HOPS,
) -> dict[int, tuple[str, int]]:
    """Find methods that are transitively reachable via same-class
    method calls from agent-reachable entrypoints.

    Returns a dict mapping callee method line number →
    (signal, hops_from_entrypoint).

    The signal is "same_class_method" for all newly-reachable methods
    (distinct from the per-file signals like "tool_decorator").

    Algorithm:
    1. Walk all ClassDef nodes in the file.
    2. For each class, build a method map: name → FunctionDef (must be
       unique — if two methods share a name, mark as ambiguous and skip).
    3. For each method in the class, determine if it is agent-reachable
       via the EXISTING detect_reachability() signals (tool_decorator,
       tool_base_class_method, etc.). These are the ENTRYPOINTS.
    4. Build a same-class call graph: for each method, find self.x()
       calls where x is a method in the same class.
    5. BFS from entrypoints, following same-class method calls, up to
       max_hops. Mark each newly-reachable method with (signal, hops).
    6. Return the map of newly-reachable methods (excluding the
       entrypoints themselves, which are already HIGH confidence).
    """
    reachable: dict[int, tuple[str, int]] = {}

    for cls_node in ast.walk(tree):
        if not isinstance(cls_node, ast.ClassDef):
            continue

        # Build the method map for this class
        method_map: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        ambiguous_names: set[str] = set()
        for child in cls_node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.name in method_map:
                    # Duplicate name — ambiguous, skip this name entirely
                    ambiguous_names.add(child.name)
                else:
                    method_map[child.name] = child

        # Remove ambiguous names
        for name in ambiguous_names:
            method_map.pop(name, None)

        if not method_map:
            continue

        # Phase 5.1: discover nested FunctionDefs inside the class's direct
        # methods. A nested function decorated with @tool / @server.call_tool()
        # is an agent-reachable entrypoint even though it is not a class-body
        # method. This is the langchain AgentMiddleware pattern
        # (file_search.py:314, anthropic_tools.py:1040):
        #     class M(AgentMiddleware):
        #         def __init__(self): ...
        #             @tool
        #             def file_tool(...): self._handle_delete(...)   # entry
        #         def _handle_delete(self, ...): shutil.rmtree(...)  # sink
        # and the browser-use MCP pattern (cli_mcp.py:128):
        #     class CLIMCPServer:
        #         def _register_handlers(self):
        #             @self.server.call_tool()  # entry via suffix match
        #             async def handle_call_tool(name, args):
        #                 asyncio.to_thread(self._execute, code)
        #         def _execute(self, code): exec(code, ns)   # sink
        nested_funcs: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        seen_nested_ids: set[int] = set()
        for method in method_map.values():
            for sub in ast.walk(method):
                if (
                    isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and sub is not method
                    and id(sub) not in seen_nested_ids
                ):
                    nested_funcs.append(sub)
                    seen_nested_ids.add(id(sub))

        # Find agent-reachable entrypoints in this class. Direct methods
        # (existing) PLUS nested functions that themselves satisfy the
        # per-file reachability detector (e.g., @tool decorator). We call
        # _reachability_for_func directly with the FunctionDef because
        # detect_reachability's line-based _find_enclosing_function would
        # resolve a nested def to its outer wrapper method (which has no
        # decorator) instead of to the nested entrypoint itself.
        entrypoints: list[tuple[int, int]] = []  # (lineno, 0_hops)
        for name, method in method_map.items():
            reach = _reachability_for_func(
                tree, method, reachability_cfg, self_package, method.lineno
            )
            if reach.confidence != "none":
                entrypoints.append((method.lineno, 0))
        for nf in nested_funcs:
            reach = _reachability_for_func(
                tree, nf, reachability_cfg, self_package, nf.lineno
            )
            if reach.confidence != "none":
                entrypoints.append((nf.lineno, 0))

        if not entrypoints:
            continue

        # Same-class call graph: caller_lineno -> [(callee_lineno, callee_name)]
        # Sources walked for outgoing edges: every direct method AND every
        # nested entrypoint. Edges are only added to callees that exist in
        # method_map (direct class-body methods) — we never chain through
        # other nested functions, which keeps the traversal conservative.
        executor_patterns = reachability_cfg.get("callback_executor_functions", [])
        call_graph: dict[int, list[tuple[int, str]]] = {}
        all_callers = list(method_map.values()) + nested_funcs
        for caller in all_callers:
            caller_line = caller.lineno
            for node in ast.walk(caller):
                if not isinstance(node, ast.Call):
                    continue
                # Direct self.x() / cls.x() call
                if isinstance(node.func, ast.Attribute):
                    if (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id in ("self", "cls")
                    ):
                        callee_name = node.func.attr
                        if callee_name in method_map:
                            callee = method_map[callee_name]
                            call_graph.setdefault(caller_line, []).append(
                                (callee.lineno, callee_name)
                            )
                    # ClassName.x() — same class, static method
                    elif (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id == cls_node.name
                    ):
                        callee_name = node.func.attr
                        if callee_name in method_map:
                            callee = method_map[callee_name]
                            call_graph.setdefault(caller_line, []).append(
                                (callee.lineno, callee_name)
                            )
                # Executor pattern: KNOWN_EXECUTOR(self.M, ...) — passing a
                # bound method as the first positional argument to a thread/
                # executor helper is the same-class equivalent of a direct
                # self.M() call (the executor invokes M on the same `self`).
                # Only a small whitelist is followed; getattr(self, name) and
                # arbitrary higher-order functions are NOT resolved.
                if executor_patterns and node.args:
                    executor_name = _get_call_name(node.func)
                    if executor_name and "." in executor_name:
                        executor_suffix = executor_name.rsplit(".", 1)[-1]
                    else:
                        executor_suffix = executor_name
                    is_executor = any(
                        executor_name == p
                        or ("." in p and executor_suffix == p.rsplit(".", 1)[-1])
                        or ("." not in p and executor_suffix == p)
                        for p in executor_patterns
                    )
                    if is_executor:
                        first = node.args[0]
                        if (
                            isinstance(first, ast.Attribute)
                            and isinstance(first.value, ast.Name)
                            and first.value.id in ("self", "cls")
                            and first.attr in method_map
                        ):
                            callee = method_map[first.attr]
                            call_graph.setdefault(caller_line, []).append(
                                (callee.lineno, first.attr)
                            )

        # BFS from entrypoints, up to max_hops
        visited: set[int] = set()
        queue: list[tuple[int, int]] = []  # (method_lineno, hops)
        for ep_line, _ in entrypoints:
            visited.add(ep_line)
            queue.append((ep_line, 0))

        while queue:
            current_line, hops = queue.pop(0)
            if hops >= max_hops:
                continue
            for callee_line, callee_name in call_graph.get(current_line, []):
                if callee_line in visited:
                    continue
                visited.add(callee_line)
                reachable[callee_line] = ("same_class_method", hops + 1)
                queue.append((callee_line, hops + 1))

    return reachable
