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
    """Walk the AST and find all sink calls matching the rules.

    SQL string patterns (type=string_pattern) are only matched on string
    literals that are arguments to execute(), cursor(), or commit() calls,
    or assigned to a variable named 'query'/'sql'/'statement'.
    """
    findings: list[SinkFinding] = []

    # Build a simple variable-type map from assignments like:
    #   p = Path(...)       → p maps to "Path"
    #   session = Session() → session maps to "Session"
    # This lets us match p.unlink() against the "Path" module pattern.
    var_types = _build_var_type_map(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for rule in rules:
                if _match_call(node, rule, var_types):
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

            # Check if this is a cursor.execute("DELETE FROM ...") call
            for rule in rules:
                mt = rule.match.get("type", "")
                if mt in ("sql_execute_pattern", "sql_fstring_pattern"):
                    if _is_sql_execute_call(node, rule):
                        findings.append(SinkFinding(
                            rule_id=rule.id,
                            category=rule.category,
                            severity=rule.severity,
                            description=rule.description,
                            line=node.lineno,
                            col=node.col_offset,
                            call_text=_call_to_text(node),
                        ))
                        break

            # Check if this is an open(path, "w") / open(path, mode="w") call
            for rule in rules:
                if rule.match.get("type") == "open_write":
                    if _is_open_write_call(node):
                        findings.append(SinkFinding(
                            rule_id=rule.id,
                            category=rule.category,
                            severity=rule.severity,
                            description=rule.description,
                            line=node.lineno,
                            col=node.col_offset,
                            call_text=_call_to_text(node),
                        ))
                        break

        # Only match raw string_pattern on strings assigned to query-like vars
        elif isinstance(node, ast.Assign):
            for rule in rules:
                if rule.match.get("type") == "string_pattern":
                    # Check if target is a query-like variable name
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id.lower() in (
                            "query", "sql", "statement", "command", "stmt"
                        ):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                for pattern in rule.match.get("patterns", []):
                                    if re.search(pattern, node.value.value, re.IGNORECASE):
                                        findings.append(SinkFinding(
                                            rule_id=rule.id,
                                            category=rule.category,
                                            severity=rule.severity,
                                            description=rule.description,
                                            line=node.lineno,
                                            col=node.col_offset,
                                            call_text=repr(node.value.value[:80]),
                                        ))
                                        break

    return findings


def _build_var_type_map(tree: ast.Module) -> dict[str, str]:
    """Build a map of variable names to their inferred type names.

    Handles:
        p = Path(...)              → {"p": "Path"}
        session = Session()        → {"session": "Session"}
        client = boto3.client("s3") → {"client": "s3"}  (factory-call pattern)
        client = boto3.client("secretsmanager") → {"client": "secretsmanager"}

    This is NOT full type inference — it only catches direct constructor
    assignments and the common boto3/factory pattern. But it covers the
    common cases for sink matching.
    """
    var_types: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call):
                type_name = _get_call_name(node.value)
                if type_name:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_types[target.id] = type_name

                # Also handle the factory-call pattern:
                # client = boto3.client("secretsmanager")
                # Here the "type" is the string argument, not the method name.
                # This is how boto3, google-cloud, etc. create service clients.
                if (isinstance(node.value.func, ast.Attribute)
                        and node.value.func.attr in ("client", "Client")):
                    # The first argument is the service name
                    if node.value.args:
                        arg = node.value.args[0]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    var_types[target.id] = arg.value
    return var_types


def _get_call_name(node: ast.Call) -> str:
    """Get the name of a call target (e.g., Path from Path(...))."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return _get_attr_chain(node.func)
    return ""


def _match_call(node: ast.Call, rule: SinkRule, var_types: dict[str, str] | None = None) -> bool:
    match_type = rule.match.get("type", "")
    if match_type == "name_call":
        return _match_name_call(node, rule)
    elif match_type == "attr_call":
        return _match_attr_call(node, rule, var_types)
    elif match_type == "subprocess_deploy":
        return _match_subprocess_deploy(node)
    # open_write and sql_execute_pattern are handled in the main detect_sinks loop
    return False


def _match_name_call(node: ast.Call, rule: SinkRule) -> bool:
    """Match bare function calls like refund(), delete(), sendmail()."""
    if not isinstance(node.func, ast.Name):
        return False
    func_name = node.func.id
    patterns = rule.match.get("func_patterns", [])
    return func_name in patterns


def _match_attr_call(node: ast.Call, rule: SinkRule, var_types: dict[str, str] | None = None) -> bool:
    """Match attribute calls like stripe.Refund.create().

    The module_patterns are matched against SEGMENTS of the attribute chain,
    not as substrings. This prevents false positives like "db" matching
    "sandbox.delete" (where "db" appears inside "sandbox" as a substring).

    Variable-type tracking: if var_types maps the root variable to a type
    name (e.g., p → Path), that type name is also checked against module_patterns.

    Chained-call resolution: if the attribute chain starts with a Call node
    (e.g., boto3.client("s3").delete_object()), the inner call's dotted name
    (boto3.client) is added to the segments to check. This catches the common
    idiom of factory-call-then-method.
    """
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
    chain_segments = full_name.split(".")

    # Match if any segment of the chain exactly equals a module pattern.
    for mod_pattern in module_patterns:
        for segment in chain_segments:
            if segment == mod_pattern:
                return True

    # Check variable-type map: if p = Path(...), then p.unlink() should
    # match the "Path" module pattern.
    if var_types and isinstance(node.func.value, ast.Name):
        var_name = node.func.value.id
        inferred_type = var_types.get(var_name)
        if inferred_type:
            # Check the type name and its last segment (e.g., "pathlib.Path" → "Path")
            type_segments = inferred_type.split(".")
            for mod_pattern in module_patterns:
                if inferred_type == mod_pattern:
                    return True
                if type_segments[-1] == mod_pattern:
                    return True

    # Chained-call resolution: if the attribute chain starts with a Call
    # (e.g., boto3.client("s3").delete_object()), resolve the inner call's
    # dotted name and check its segments against module_patterns.
    # This catches the very common factory-then-method idiom that would
    # otherwise be a silent miss.
    if isinstance(node.func.value, ast.Call):
        inner_call = node.func.value
        inner_name = _get_call_name(inner_call)
        if inner_name:
            inner_segments = inner_name.split(".")
            for mod_pattern in module_patterns:
                for segment in inner_segments:
                    if segment == mod_pattern:
                        return True

    return False


def _is_open_write_call(node: ast.Call) -> bool:
    """Check if this is an open() call in write/append mode.

    Matches:
        open(path, "w")
        open(path, "wb")
        open(path, "a")
        open(path, "ab")
        open(path, "w+")
        open(path, mode="w")
        open(path, mode="wb")

    Does NOT match:
        open(path)           # read-only (default)
        open(path, "r")
        open(path, "rb")
    """
    if not isinstance(node.func, ast.Name):
        return False
    if node.func.id != "open":
        return False

    # Check positional args (2nd arg is mode)
    if len(node.args) >= 2:
        mode = _extract_string_from_node(node.args[1])
        if mode and _is_write_mode(mode):
            return True

    # Check keyword args (mode=...)
    for kw in node.keywords:
        if kw.arg == "mode":
            mode = _extract_string_from_node(kw.value)
            if mode and _is_write_mode(mode):
                return True

    return False


def _is_write_mode(mode: str) -> bool:
    """Check if a file mode string indicates write/append."""
    return any(m in mode for m in ("w", "a", "x", "+"))


def _is_sql_execute_call(node: ast.Call, rule: SinkRule) -> bool:
    """Check if this is a cursor.execute() or cursor.executemany() call
    with a SQL string argument containing dangerous patterns.
    """
    if not isinstance(node.func, ast.Attribute):
        return False
    method_name = node.func.attr
    if method_name not in ("execute", "executemany", "executescript"):
        return False

    # Check args for dangerous SQL patterns
    patterns = rule.match.get("patterns", [])
    for arg in node.args:
        text = _extract_string_from_node(arg)
        if text:
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
    return False


def _extract_string_from_node(node: ast.expr) -> str | None:
    """Extract a string value from an AST node (constant, f-string, or joined string)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        # f-string — concatenate all string parts
        parts = []
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
            elif isinstance(val, ast.FormattedValue):
                parts.append("{var}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _extract_string_from_node(node.left)
        right = _extract_string_from_node(node.right)
        if left is not None:
            return left + (right or "")
    return None


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
