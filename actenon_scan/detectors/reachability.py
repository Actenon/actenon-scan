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

    # Check for HIGH confidence: tool decorators on the function
    tool_decorators = reachability_cfg.get("tool_decorators", [])
    if _has_tool_decorator(func_node, tool_decorators):
        result.confidence = "high"
        result.signals.append("tool_decorator")
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
    """Check if the function has a tool decorator."""
    for decorator in func_node.decorator_list:
        name = _get_decorator_name(decorator)
        if name in tool_decorators:
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
