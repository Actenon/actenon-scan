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
    # Used by the pretty reporter to show the ACTUAL reachability reason
    # instead of guessing Python decorator syntax from the file path.
    reachability_reason: str = ""


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


def is_go_extra_available() -> bool:
    """Check whether the [go] extra is installed (tree-sitter-go available)."""
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_go  # noqa: F401
        return True
    except ImportError:
        return False


def scan_go_file(filepath: str, source: bytes) -> list[GoFinding]:
    """Scan a single Go source file for consequential actions.

    Returns a list of GoFinding objects. Only returns findings from
    functions that are agent-reachable (in a file that imports an MCP/agent
    SDK, or passed to a tool registration call).
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
                        findings.append(GoFinding(
                            file=filepath,
                            line=call_node.start_point[0] + 1,
                            col=call_node.start_point[1],
                            rule_id=rule["id"],
                            category=rule["category"],
                            severity=rule["severity"],
                            confidence="high",
                            description=rule["description"],
                            call_text=_get_call_text(call_node, source),
                            reachability_reason=reachability_reason,
                        ))
                        break  # one finding per call
                else:
                    continue
                break

    return findings


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
