"""Sink detector — finds calls to consequential/irreversible operations."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from actenon_scan.rules.loader import SinkRule


@dataclass
class SinkFinding:
    rule_id: str
    category: str
    severity: str
    description: str
    line: int
    col: int
    call_text: str


def detect_sinks(tree: ast.Module, filepath: str, rules: list[SinkRule]) -> list[SinkFinding]:
    """Walk the AST and find all sink calls matching the rules."""
    findings: list[SinkFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for rule in rules:
                if _match_call(node, rule):
                    findings.append(SinkFinding(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        description=rule.description,
                        line=node.lineno,
                        col=node.col_offset,
                        call_text=_call_to_text(node),
                    ))
                    break  # one finding per call
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # Check string literals for dangerous SQL
            for rule in rules:
                if rule.match.get("type") == "string_pattern":
                    for pattern in rule.match.get("patterns", []):
                        if re.search(pattern, node.value, re.IGNORECASE):
                            findings.append(SinkFinding(
                                rule_id=rule.id,
                                category=rule.category,
                                severity=rule.severity,
                                description=rule.description,
                                line=node.lineno,
                                col=node.col_offset,
                                call_text=repr(node.value[:80]),
                            ))
                            break
    return findings


def _match_call(node: ast.Call, rule: SinkRule) -> bool:
    match_type = rule.match.get("type", "")
    if match_type == "name_call":
        return _match_name_call(node, rule)
    elif match_type == "attr_call":
        return _match_attr_call(node, rule)
    elif match_type == "subprocess_deploy":
        return _match_subprocess_deploy(node)
    return False


def _match_name_call(node: ast.Call, rule: SinkRule) -> bool:
    """Match bare function calls like refund(), delete(), send()."""
    if not isinstance(node.func, ast.Name):
        return False
    func_name = node.func.id
    patterns = rule.match.get("func_patterns", [])
    return func_name in patterns


def _match_attr_call(node: ast.Call, rule: SinkRule) -> bool:
    """Match attribute calls like stripe.Refund.create()."""
    if not isinstance(node.func, ast.Attribute):
        return False
    func_name = node.func.attr
    func_patterns = rule.match.get("func_patterns", [])
    if func_name not in func_patterns:
        return False

    # Check the module/object part
    module_patterns = rule.match.get("module_patterns", [])
    if not module_patterns:
        return True  # any module matches

    # Walk the attribute chain to get the full name
    full_name = _get_attr_chain(node.func)
    for mod_pattern in module_patterns:
        if full_name.startswith(mod_pattern) or mod_pattern in full_name:
            return True
    # Also check if it's a simple variable match (e.g., `stripe` variable)
    if isinstance(node.func.value, ast.Name):
        var_name = node.func.value.id
        for mod_pattern in module_patterns:
            if var_name == mod_pattern or mod_pattern.startswith(var_name):
                return True
    return False


def _match_subprocess_deploy(node: ast.Call) -> bool:
    """Match subprocess/os.system calls with deployment keywords in args."""
    if not isinstance(node.func, ast.Attribute):
        return False
    func_name = node.func.attr
    if func_name not in ("run", "call", "Popen", "check_call", "check_output", "system"):
        return False

    # Check the object part — must be subprocess or os
    if isinstance(node.func.value, ast.Name):
        if node.func.value.id not in ("subprocess", "os"):
            return False
    else:
        return False

    # Check args for deploy keywords
    deploy_keywords = ("terraform", "kubectl", "helm", "ansible", "deploy", "rollback")
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            for kw in deploy_keywords:
                if kw in arg.value.lower():
                    return True
    # Also check list args (common for subprocess.run(["kubectl", "apply"]))
    for arg in node.args:
        if isinstance(arg, ast.List):
            for elt in arg.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    for kw in deploy_keywords:
                        if kw in elt.value.lower():
                            return True
    return False


def _get_attr_chain(node: ast.Attribute) -> str:
    """Get the full dotted name of an attribute chain (e.g., stripe.Refund.create)."""
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _call_to_text(node: ast.Call) -> str:
    """Get a short text representation of the call for reporting."""
    try:
        return ast.unparse(node)[:120]
    except Exception:
        return "<call>"
