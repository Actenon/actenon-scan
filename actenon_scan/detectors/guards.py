"""Guard detector — checks if a sink is preceded by an authority/proof guard."""

from __future__ import annotations

import ast


def is_guarded(
    tree: ast.Module,
    sink_line: int,
    guard_patterns: list[str],
) -> bool:
    """Check if the sink at sink_line is guarded.

    A guard "covers" a sink if:
    (a) a guard CALL appears lexically before the sink call in the same
        function body, OR
    (b) a recognized guard DECORATOR wraps the function containing the sink.

    This is a lexical-precedence heuristic (v1 limitation documented).
    """
    # Find the enclosing function
    func_node = _find_enclosing_function(tree, sink_line)
    if func_node is None:
        return False

    # Check (b): guard decorator on the function
    if _has_guard_decorator(func_node, guard_patterns):
        return True

    # Check (a): guard call before the sink in the function body
    for child in ast.walk(func_node):
        if isinstance(child, ast.Call):
            if hasattr(child, "lineno") and child.lineno < sink_line:
                call_name = _get_call_name(child.func)
                if call_name and _matches_guard(call_name, guard_patterns):
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
        # Also check suffix match (e.g., "authorize" matches "module.authorize")
        if name_lower.endswith("." + pattern.lower()):
            return True
    return False
