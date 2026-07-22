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
) -> ReachabilityResult:
    """Determine if the sink at sink_line is agent-reachable.

    Checks the enclosing function and module for agent/tool signals.
    """
    result = ReachabilityResult()

    # Find the function that contains the sink
    func_node = _find_enclosing_function(tree, sink_line)
    if func_node is None:
        # Not in a function — check module-level signals
        return _check_module_signals(tree, reachability_cfg)

    # Check for HIGH confidence: tool decorators on the function
    tool_decorators = reachability_cfg.get("tool_decorators", [])
    if _has_tool_decorator(func_node, tool_decorators):
        result.confidence = "high"
        result.signals.append("tool_decorator")
        return result

    # Check for HIGH confidence: tool wrapper calls (Tool.from_function, etc.)
    # These appear at module level, not on the function itself
    # We check if the function name is referenced in a tool wrapper call
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

    # Check for MEDIUM confidence: module imports an agent framework
    agent_frameworks = reachability_cfg.get("agent_frameworks", [])
    if _imports_agent_framework(tree, agent_frameworks):
        result.confidence = "medium"
        result.signals.append("agent_framework_import")
        return result

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


def _check_module_signals(tree: ast.Module, reachability_cfg: dict[str, Any]) -> ReachabilityResult:
    """Check module-level signals when the sink is not in a function."""
    agent_frameworks = reachability_cfg.get("agent_frameworks", [])
    if _imports_agent_framework(tree, agent_frameworks):
        return ReachabilityResult(confidence="medium", signals=["module_level_agent_import"])
    return ReachabilityResult()
