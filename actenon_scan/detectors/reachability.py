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
    local_calls: "LocalCallAnalysis | None" = None,
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

    signal = entry_point_signal(tree, func_node, reachability_cfg, sink_line=sink_line)
    if signal is not None:
        result.confidence = "high"
        result.signals.append(signal)
        return result

    # MEDIUM confidence: the enclosing function is not an entry point, but an
    # entry point in this same module calls it directly. The call was resolved
    # to exactly one unshadowed module-level definition; anything less certain
    # was left unfollowed and disclosed instead.
    #
    # MEDIUM, not HIGH, and deliberately so. A sink in the tool body is an
    # action the tool performs. A sink one hop away is an action the tool
    # performs THROUGH a function that may have other callers, other
    # preconditions, and guards the analysis has not examined. The evidence is
    # weaker, so the confidence is lower, and the signal name says which kind
    # of evidence it was.
    if local_calls is not None and func_node.name in local_calls.one_hop_targets:
        result.confidence = "medium"
        result.signals.append("one_hop_local")
        return result

    # The sink is inside a NON-TOOL function. Even if the module imports an
    # agent framework, a regular internal function is not agent-reachable.
    # Without this gate, every file in a framework's own repo (where every
    # file imports the framework) would have all its sinks flagged.
    return result


@dataclass
class ModuleEntryPointIndex:
    """Module-wide entry-point evidence, computed in one pass.

    ``_is_wrapped_as_tool`` and ``_is_in_tool_list`` each walk the whole
    module to answer a question about one function name. Asking them once per
    function makes entry-point detection quadratic in module size, which cost
    an 8x slowdown on the pinned langchain fixture (2.5s -> 19.9s) when the
    call-edge walk started asking about every function rather than only the
    ones enclosing a sink. The answers are collected here in a single walk
    instead.
    """

    wrapped_as_tool: frozenset[str] = frozenset()
    in_tool_list: frozenset[str] = frozenset()
    #: True when the module contains no entry-point evidence of any kind, so
    #: no function in it can be an entry point and the whole file can be
    #: skipped without running a single per-function check.
    empty: bool = False
    #: Tool names declared in an LLM tool-schema literal in this module,
    #: collected in the index walk. _is_tool_schema_dispatch called
    #: _declared_tool_names once per function, each time walking the whole
    #: module: 93% of the cost of the call-edge walk on the langchain fixture.
    _declared: frozenset[str] = frozenset()

    @property
    def declared_tool_names(self) -> frozenset[str]:
        return self._declared


def build_entry_point_index(
    tree: ast.Module, reachability_cfg: dict[str, Any]
) -> ModuleEntryPointIndex:
    """Collect every module-wide entry-point signal in one AST walk."""
    tool_wrappers = reachability_cfg.get("tool_wrappers", [])
    tool_list_params = reachability_cfg.get("tool_list_params", [])
    tool_decorators = reachability_cfg.get("tool_decorators", [])
    resource_decorators = reachability_cfg.get("resource_boundary_decorators", [])
    tool_base_classes = reachability_cfg.get("tool_base_classes", [])

    wrapped: set[str] = set()
    in_list: set[str] = set()
    declared: set[str] = set()
    saw_decorator = False
    saw_base_class = False
    saw_schema_or_action = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            # Tool-schema literals, collected in this same walk rather than in
            # a second pass. _declared_tool_names over the whole module was
            # 360ms of an 850ms index build on the langchain fixture, and the
            # walk it did was identical to this one.
            declared |= _tool_names_in_dict(node)
        elif isinstance(node, ast.Call):
            if tool_wrappers:
                call_name = _get_call_name(node.func)
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        # Matching rule copied verbatim from
                        # _is_wrapped_as_tool, including the case where
                        # _get_call_name returns "" for a call target that is
                        # neither a Name nor an Attribute: "" is a substring
                        # of every wrapper, so that call matches. That is
                        # over-inclusive, and it is REPRODUCED here on
                        # purpose. The index decides which functions the
                        # call-edge walk treats as entry points; the sink path
                        # still uses _is_wrapped_as_tool. If the two disagreed,
                        # the walk would report fewer unfollowed calls than the
                        # findings path implies — under-reporting the gap,
                        # which is the one direction this must never fail in.
                        # (The over-inclusiveness itself is a separate
                        # precision defect; fixing it changes findings and
                        # needs corpus re-triage, so it is not done here.)
                        for wrapper in tool_wrappers:
                            if wrapper in call_name or call_name in wrapper:
                                wrapped.add(arg.id)
                                break
            if tool_list_params:
                for kw in node.keywords:
                    if kw.arg in tool_list_params and isinstance(
                        kw.value, (ast.List, ast.Tuple)
                    ):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Name):
                                in_list.add(elt.id)
                            elif isinstance(elt, ast.Call):
                                for sub in elt.args:
                                    if isinstance(sub, ast.Name):
                                        in_list.add(sub.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not saw_decorator:
                for dec in node.decorator_list:
                    name = _get_decorator_name(dec)
                    if name in tool_decorators or (
                        resource_decorators and name in resource_decorators
                    ):
                        saw_decorator = True
                        break
            if not saw_schema_or_action and _action_typed_params(node):
                saw_schema_or_action = True
        elif isinstance(node, ast.ClassDef):
            saw_base_class = saw_base_class or bool(tool_base_classes)

    return ModuleEntryPointIndex(
        wrapped_as_tool=frozenset(wrapped),
        in_tool_list=frozenset(in_list),
        empty=not (
            wrapped or in_list or declared or saw_decorator or saw_base_class
            or saw_schema_or_action
        ),
        _declared=frozenset(declared),
    )


def entry_point_signal(
    tree: ast.Module,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    reachability_cfg: dict[str, Any],
    *,
    sink_line: int | None = None,
    index: ModuleEntryPointIndex | None = None,
) -> str | None:
    """Return the entry-point signal for ``func_node``, or None.

    Extracted from ``detect_reachability`` so the same question — "is this
    function an agent entry point?" — can be asked about a function directly,
    not only about the function enclosing a sink. The local-call-edge walk
    (``collect_local_call_edges``) needs exactly that, and a second copy of
    these checks would drift from this one.

    ``sink_line`` narrows the two checks that are position-sensitive
    (tool-schema dispatch and action dispatch select on the branch the sink
    sits in). When it is None the function's own line is used, which asks
    whether the function is an entry point anywhere in its body.
    """
    line = sink_line if sink_line is not None else func_node.lineno

    # HIGH: tool decorators on the function
    tool_decorators = reachability_cfg.get("tool_decorators", [])
    if _has_tool_decorator(func_node, tool_decorators):
        return "tool_decorator"

    # Work Order 2, Phase 3: resource-boundary entry points.
    # FastAPI/Flask/Django route handlers, CLI commands. These are web
    # endpoints that receive external input — a different entry-point
    # class than agent tool handlers, but equally consequential.
    resource_decorators = reachability_cfg.get("resource_boundary_decorators", [])
    if resource_decorators and _has_resource_boundary_decorator(func_node, resource_decorators):
        return "resource_boundary"

    # HIGH: tool wrapper calls (Tool.from_function, etc.)
    if index is not None:
        if func_node.name in index.wrapped_as_tool:
            return "tool_wrapper"
    else:
        tool_wrappers = reachability_cfg.get("tool_wrappers", [])
        if _is_wrapped_as_tool(tree, func_node.name, tool_wrappers):
            return "tool_wrapper"

    # HIGH: method of a class subclassing a tool base
    tool_base_classes = reachability_cfg.get("tool_base_classes", [])
    tool_methods = reachability_cfg.get("tool_methods", [])
    if _is_tool_method(tree, func_node, tool_base_classes, tool_methods):
        return "tool_base_class_method"

    # HIGH: function passed in a tools=[...] / plugins=[...] argument to any
    # constructor call. This is how Agno, smolagents, CrewAI, and the OpenAI
    # Agents SDK register tools.
    if index is not None:
        if func_node.name in index.in_tool_list:
            return "tool_list_param"
    else:
        tool_list_params = reachability_cfg.get("tool_list_params", [])
        if tool_list_params and _is_in_tool_list(tree, func_node.name, tool_list_params):
            return "tool_list_param"

    # HIGH: the sink sits in a branch selected by a tool name that this module
    # declares in an LLM tool-schema literal. Raw schema dispatch is a tool
    # boundary with no decorator to announce it.
    declared = index.declared_tool_names if index is not None else None
    if _is_tool_schema_dispatch(tree, func_node, line, declared=declared):
        return "tool_schema_dispatch"

    # HIGH: the sink consumes an executable payload off a parameter annotated
    # as an agent action type (CmdRunAction.command, etc.). The
    # action/observation architecture dispatches through plain methods.
    if _is_action_dispatch(func_node, line):
        return "action_dispatch"

    return None


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
    """Check if the function has a tool decorator."""
    for decorator in func_node.decorator_list:
        name = _get_decorator_name(decorator)
        if name in tool_decorators:
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

    The function name must appear as a bare Name reference inside one of the
    list/tuple arguments named in tool_list_params.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg in tool_list_params and isinstance(kw.value, (ast.List, ast.Tuple)):
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Name) and elt.id == func_name:
                        return True
                    # Also handle Tool(func_name) wrapper inside the list
                    if isinstance(elt, ast.Call):
                        for arg in elt.args:
                            if isinstance(arg, ast.Name) and arg.id == func_name:
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
        if isinstance(node, ast.Dict):
            names |= _tool_names_in_dict(node)
    return names


def _tool_names_in_dict(node: ast.Dict) -> set[str]:
    """Tool names declared by one dict literal, if it is a tool schema.

    Split out of _declared_tool_names so build_entry_point_index can apply
    the identical rule inside its own walk. One definition, two callers —
    a second copy would be free to drift, and the two are required to agree.
    """
    names: set[str] = set()
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
    *,
    declared: "frozenset[str] | set[str] | None" = None,
) -> bool:
    """Check if the sink sits in a branch selected by a declared tool name.

    ``declared`` lets a caller that already walked the module pass the names
    in rather than provoking another full walk per function.
    """
    if declared is None:
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
# Local call edges (A2/A3): what the per-function analysis did not follow.
# ---------------------------------------------------------------------------
#
# The analysis is per-function: a sink is reported when the function that
# encloses it is an agent entry point. A sink one hop away — in a helper the
# entry point calls — is therefore invisible to it.
#
# Before this module existed, that gap was silent. A scan of
#
#     @tool
#     def publish(data): send_to_external_service(data)
#     def send_to_external_service(data): requests.post(URL, json=data)
#
# reported CLEAN, with nothing in the output to say a call had been stepped
# over. Silence read as safety, which is the one thing this project promises
# never to do.
#
# An EDGE is a call site inside an agent-reachable function whose callee is a
# function defined in the file being analysed. Every edge is classified
# followed or unfollowed, and the unfollowed ones are surfaced in every
# output path. The resolution rule is deliberately one-directional: anything
# ambiguous is left UNFOLLOWED and disclosed, never quietly followed.
#
# Calls whose callee cannot be tied to a local definition at all (stdlib,
# third-party, unresolvable names) are not edges. They are not silently
# dropped from a denominator — they were never in one. See docs/COVERAGE.md.


@dataclass
class LocalCallEdge:
    """One call from agent-reachable code into a locally-defined function."""

    file: str
    line: int
    col: int
    caller: str
    callee: str
    followed: bool = False
    #: Why this edge was not followed. One of "not_implemented" (the analysis
    #: does not follow local calls at all), "ambiguous_binding" (the name does
    #: not resolve to exactly one unshadowed module-level def),
    #: "attribute_call" (a method call — receiver type is not resolved), or
    #: "cross_file" (the name is bound by a first-party import; following it
    #: would require cross-file analysis, which this tool does not do).
    reason: str = ""


def _module_level_functions(
    tree: ast.Module,
) -> dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]]:
    """Module-level ``def``s by name. A list, so redefinition is visible."""
    out: dict[str, list] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.setdefault(node.name, []).append(node)
    return out


def _all_local_function_names(tree: ast.Module) -> set[str]:
    """Every function name defined anywhere in this file, methods included."""
    return {
        n.name
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _first_party_imported_names(tree: ast.Module) -> set[str]:
    """Names bound by a relative import — a definition in the scanned tree.

    ``from .helpers import send`` names a function that lives in the scanned
    tree but not in this file. Following it is cross-file analysis, which this
    tool does not do, so the edge is counted and disclosed as unfollowed
    rather than omitted. An absolute import of a third-party or stdlib module
    is not an edge: its callee is not in the scanned tree.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level and node.level > 0:
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.asname or alias.name)
    return names


def _names_shadowed_in(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names rebound inside ``func`` — parameters, assignments, local defs.

    A name rebound in the caller does not resolve to the module-level def of
    the same name, so the call must not be followed.
    """
    shadowed: set[str] = set()
    args = func.args
    for group in (
        getattr(args, "posonlyargs", []),
        args.args,
        args.kwonlyargs,
    ):
        shadowed.update(a.arg for a in group)
    if args.vararg:
        shadowed.add(args.vararg.arg)
    if args.kwarg:
        shadowed.add(args.kwarg.arg)
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Name):
                        shadowed.add(sub.id)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if isinstance(node.target, ast.Name):
                shadowed.add(node.target.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node is not func:
                shadowed.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                shadowed.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.With):
            for item in node.items:
                if item.optional_vars is not None:
                    for sub in ast.walk(item.optional_vars):
                        if isinstance(sub, ast.Name):
                            shadowed.add(sub.id)
        elif isinstance(node, ast.For):
            for sub in ast.walk(node.target):
                if isinstance(sub, ast.Name):
                    shadowed.add(sub.id)
    return shadowed


def _module_level_rebindings(tree: ast.Module) -> set[str]:
    """Names assigned or imported at module level — a def of that name is
    not the only binding, so a call to it does not resolve to one target."""
    rebound: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Name):
                        rebound.add(sub.id)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if isinstance(node.target, ast.Name):
                rebound.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                rebound.add(alias.asname or alias.name.split(".")[0])
    return rebound


def resolve_local_callee(
    name: str,
    *,
    module_funcs: dict[str, list],
    module_rebindings: set[str],
    caller_shadowed: set[str],
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef | None, str]:
    """Resolve a bare call name to the one module-level def it must mean.

    Returns ``(node, "")`` only when the name resolves to exactly one
    module-level ``def`` that nothing shadows. Every other outcome returns
    ``(None, reason)`` so the caller can record an unfollowed edge.

    The direction is fixed by design: ambiguity never resolves to "follow it".
    Following the wrong target would attribute a sink to an entry point that
    cannot reach it, which is a false positive reported at high confidence —
    the failure mode this tool is least willing to have.
    """
    defs = module_funcs.get(name)
    if not defs:
        return None, "unresolved"
    if len(defs) > 1:
        return None, "ambiguous_binding"
    if name in module_rebindings:
        return None, "ambiguous_binding"
    if name in caller_shadowed:
        return None, "ambiguous_binding"
    return defs[0], ""


@dataclass
class LocalCallAnalysis:
    """The result of one walk over a module's agent-reachable call sites.

    ``edges`` is every call into a locally-defined function, each marked
    followed or not. ``one_hop_targets`` maps the name of each module-level
    function that following actually reached to the call sites that reached
    it.

    Both come from the same walk on purpose. If the disclosure and the
    following were computed separately they could disagree, and the failure
    would be silent in the worse direction: an edge counted as followed while
    nothing was analysed behind it.
    """

    edges: list[LocalCallEdge] = None
    one_hop_targets: dict[str, list[LocalCallEdge]] = None

    def __post_init__(self):
        if self.edges is None:
            self.edges = []
        if self.one_hop_targets is None:
            self.one_hop_targets = {}


def collect_local_call_edges(
    tree: ast.Module,
    reachability_cfg: dict[str, Any],
    *,
    rel_path: str,
    follow_one_hop: bool = False,
) -> list[LocalCallEdge]:
    """Every call from agent-reachable code into a locally-defined function."""
    return analyse_local_calls(
        tree, reachability_cfg, rel_path=rel_path, follow_one_hop=follow_one_hop
    ).edges


def analyse_local_calls(
    tree: ast.Module,
    reachability_cfg: dict[str, Any],
    *,
    rel_path: str,
    follow_one_hop: bool = False,
) -> LocalCallAnalysis:
    """Walk agent-reachable functions, recording and optionally following calls.

    ``follow_one_hop`` turns on same-module depth-1 following. When it is on,
    an edge whose callee resolves to exactly one unshadowed module-level
    definition is marked followed and its target recorded; every other edge
    stays unfollowed and disclosed.

    Following is DEPTH 1 AND NON-TRANSITIVE: targets are collected only from
    functions that are entry points in their own right. A function reached by
    following is never itself used as a source of further edges, so a sink two
    hops away stays missed — and stays disclosed, because the callee's own
    outgoing calls are not walked and so are never counted as followed.
    """
    index = build_entry_point_index(tree, reachability_cfg)
    if index.empty:
        # No entry-point evidence anywhere in this module, so no function in
        # it is agent-reachable and it has no edges by definition.
        return LocalCallAnalysis()

    module_funcs = _module_level_functions(tree)
    module_rebindings = _module_level_rebindings(tree)
    local_names = _all_local_function_names(tree)
    first_party = _first_party_imported_names(tree)
    if not local_names and not first_party:
        return LocalCallAnalysis()

    edges: list[LocalCallEdge] = []
    one_hop_targets: dict[str, list[LocalCallEdge]] = {}
    seen_calls: set[int] = set()

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if entry_point_signal(tree, func, reachability_cfg, index=index) is None:
            continue

        caller_shadowed = _names_shadowed_in(func)

        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            if id(node) in seen_calls:
                continue

            callee_name: str | None = None
            attribute_call = False
            if isinstance(node.func, ast.Name):
                callee_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                callee_name = node.func.attr
                attribute_call = True
            if callee_name is None:
                continue

            # An edge requires the callee to be a function defined in the
            # scanned tree. Everything else is a library call, and a library
            # call is not an unfollowed hop — it is the sink layer itself.
            if callee_name not in local_names and callee_name not in first_party:
                continue

            seen_calls.add(id(node))
            edge = LocalCallEdge(
                file=rel_path,
                line=node.lineno,
                col=node.col_offset,
                caller=func.name,
                callee=callee_name,
            )

            if attribute_call:
                # self.helper() / obj.method(): the receiver type is not
                # resolved, so the target is not known. Disclosed, not followed.
                edge.reason = "attribute_call"
            elif callee_name in first_party and callee_name not in module_funcs:
                edge.reason = "cross_file"
            else:
                target, reason = resolve_local_callee(
                    callee_name,
                    module_funcs=module_funcs,
                    module_rebindings=module_rebindings,
                    caller_shadowed=caller_shadowed,
                )
                if target is None:
                    # "unresolved" here means the name is a method or nested
                    # def, not a module-level one: a local definition the
                    # module-level resolution rule cannot reach.
                    edge.reason = (
                        "ambiguous_binding" if reason == "ambiguous_binding"
                        else "not_module_level"
                    )
                elif follow_one_hop and target is not func:
                    # target is not func: a self-call adds no new code to
                    # analyse and following it would be the first step of
                    # recursion.
                    edge.followed = True
                    one_hop_targets.setdefault(callee_name, []).append(edge)
                else:
                    edge.reason = "not_implemented"
            edges.append(edge)

    # A function that is an entry point in its own right is already analysed
    # at full confidence. Recording it as a one-hop target as well would
    # downgrade it, so it is dropped from the map (the EDGE stays followed —
    # the call was resolved and the callee was analysed).
    one_hop_targets = {
        name: sites for name, sites in one_hop_targets.items()
        if entry_point_signal(
            tree, module_funcs[name][0], reachability_cfg, index=index
        ) is None
    }

    return LocalCallAnalysis(edges=edges, one_hop_targets=one_hop_targets)
