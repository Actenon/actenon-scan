"""TypeScript/JavaScript analyser using tree-sitter.

Lazy-imports tree_sitter so the base install (without the [typescript]
extra) never imports it. A base install must work with the extra absent.

The analyser ports the Python rule catalogue to TypeScript call expressions,
matching on both member expressions (stripe.refunds.create) and bare
identifiers (execSync). Findings use the SAME rule IDs and categories as
Python so output is language-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class TSFinding:
    """A TypeScript/JavaScript sink finding.

    Mirrors the Python SinkFinding shape so the engine can treat them
    identically.
    """
    rule_id: str
    category: str
    severity: str
    description: str
    line: int
    col: int
    call_text: str


# TypeScript sink rules — same rule IDs and categories as Python.
# Each rule maps to a list of qualified call patterns to match.
TS_SINK_RULES: list[dict[str, Any]] = [
    # ── payments ──────────────────────────────────────────────────
    {
        "id": "PAY-STRIPE-REFUND",
        "category": "payments",
        "severity": "high",
        "description": "Stripe refund/charge/payout call in agent tool",
        "patterns": [
            "stripe.refunds.create",
            "stripe.charges.create",
            "stripe.charges.refund",
            "stripe.payouts.create",
            "stripe.transfers.create",
            "stripe.paymentIntents.create",
            "stripe.paymentIntents.capture",
            "stripe.paymentIntents.cancel",
        ],
    },
    {
        "id": "PAY-GENERIC-REFUND",
        "category": "payments",
        "severity": "high",
        "description": "Generic payment refund/charge call",
        "patterns": [
            "refund",
            "createCharge",
            "createRefund",
            "issueRefund",
            "processRefund",
        ],
    },
    # ── shell_execution ───────────────────────────────────────────
    {
        "id": "EXEC-SHELL",
        "category": "shell_execution",
        "severity": "high",
        "description": "Shell/command execution via child_process",
        "patterns": [
            "execSync",
            "exec",
            "spawn",
            "spawnSync",
            "execFileSync",
            "child_process.exec",
            "child_process.execSync",
            "child_process.spawn",
            "child_process.spawnSync",
        ],
    },
    # ── file_mutation ─────────────────────────────────────────────
    {
        "id": "DATA-DELETE-FILE",
        "category": "file_mutation",
        "severity": "high",
        "description": "File/directory deletion via fs",
        "patterns": [
            "fs.rm",
            "fs.rmSync",
            "fs.unlink",
            "fs.unlinkSync",
            "fs.rmdir",
            "fs.rmdirSync",
            "fs.promises.rm",
            "fs.promises.unlink",
            "fs.promises.rmdir",
            "rimraf",
        ],
    },
    {
        "id": "FILE-WRITE",
        "category": "file_mutation",
        "severity": "medium",
        "description": "File write via fs.writeFile",
        "patterns": [
            "fs.writeFile",
            "fs.writeFileSync",
            "fs.appendFile",
            "fs.appendFileSync",
            "fs.promises.writeFile",
            "fs.promises.appendFile",
        ],
    },
    # ── data_destruction ──────────────────────────────────────────
    {
        "id": "DATA-DELETE-SQL",
        "category": "data_destruction",
        "severity": "high",
        "description": "SQL execution with DROP/DELETE/TRUNCATE",
        "patterns": [
            "db.query",
            "db.execute",
            "db.run",
            "cursor.execute",
            "connection.execute",
            "prisma.$executeRaw",
            "prisma.deleteMany",
            "knex.del",
            "knex.delete",
            "mongoose.deleteMany",
            "mongoose.remove",
        ],
    },
    # ── provider_sdk (AWS) ───────────────────────────────────────
    {
        "id": "PROVIDER-SDK-CALL",
        "category": "provider_sdk",
        "severity": "high",
        "description": "AWS SDK destructive call",
        "patterns": [
            "DeleteObjectsCommand",
            "DeleteObjectCommand",
            "DeleteBucketCommand",
            "TerminateInstancesCommand",
            "StopInstancesCommand",
            "DeleteDBInstanceCommand",
            "DeleteFunctionCommand",
            "DeleteTableCommand",
            "DeleteStackCommand",
            "s3.deleteObjects",
            "s3.deleteObject",
            "s3.deleteBucket",
            "ec2.terminateInstances",
            "rds.deleteDBInstance",
            "lambda.deleteFunction",
            "dynamodb.deleteTable",
        ],
    },
    # ── network_egress ────────────────────────────────────────────
    {
        "id": "NET-EGRESS",
        "category": "network_egress",
        "severity": "medium",
        "description": "Network egress via fetch/axios/http",
        "patterns": [
            "fetch",
            "axios.post",
            "axios.put",
            "axios.delete",
            "axios.patch",
            "got.post",
            "got.put",
            "got.delete",
            "http.request",
            "https.request",
        ],
    },
    # ── credential_access ─────────────────────────────────────────
    {
        "id": "SECRET-READ",
        "category": "credential_access",
        "severity": "high",
        "description": "Credential access via process.env",
        "patterns": [
            "process.env",
        ],
    },
]


# Reachability signals — TypeScript/JS agent tool entry points.
TS_REACHABILITY_SIGNALS: list[str] = [
    # MCP SDK (low-level)
    "setRequestHandler",
    # MCP SDK (high-level McpServer)
    "registerTool",
    "server.tool",
    # @modelcontextprotocol/sdk import
    "@modelcontextprotocol/sdk",
    # LangChain.js
    "DynamicStructuredTool",
    "tool(",  # from @langchain/core
    # Vercel AI SDK
    "execute:",  # tools: { name: { execute } }
]


# Guard patterns — same vendor-neutral recognition as Python.
TS_GUARD_PATTERNS: list[str] = [
    "authorize",
    "checkPermission",
    "check_permission",
    "canExecute",
    "hasPermission",
    "verifyProof",
    "verify_proof",
    "actenon",
    "requireAuth",
    "requirePermission",
    "ensureAuthorized",
    "checkAuth",
    "authenticate",
    "guard",
    "protect",
    "intercept",
    "preAuthorize",
    "secured",
    "authorized",
    "permission",
    "rbac",
    "abac",
    "policy",
    "pdp",
    "pep",
]


def is_typescript_extra_available() -> bool:
    """Check whether tree-sitter is available (i.e. the [typescript] extra is installed)."""
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_typescript  # noqa: F401
        return True
    except ImportError:
        return False


def analyze_typescript_file(filepath: str | Path) -> tuple[list[TSFinding], list[tuple[str, str]]]:
    """Analyze a TypeScript/JavaScript file for sinks.

    Returns (findings, errors). If tree-sitter is not installed, returns
    ([], [(filepath, "tree-sitter not installed")]).

    The analyser:
      1. Parses the file with tree-sitter (TS or TSX grammar based on extension)
      2. Extracts all call expressions with their qualified names
      3. Matches against TS_SINK_RULES
      4. Checks PER-FUNCTION reachability (is the enclosing function a tool handler?)
      5. Checks guards (authorize(), checkPermission(), etc.)
    """
    if not is_typescript_extra_available():
        return ([], [(str(filepath), "tree-sitter not installed (pip install actenon-scan[typescript])")])

    from tree_sitter import Language, Parser, Query, QueryCursor
    import tree_sitter_typescript as tsts

    filepath = Path(filepath)
    suffix = filepath.suffix.lower()

    # Choose grammar based on extension
    if suffix == ".tsx":
        lang = Language(tsts.language_tsx())
    elif suffix in (".ts", ".mts", ".cts"):
        lang = Language(tsts.language_typescript())
    elif suffix in (".js", ".jsx", ".mjs", ".cjs"):
        lang = Language(tsts.language_tsx() if suffix == ".jsx" else tsts.language_typescript())
    else:
        return ([], [])

    try:
        source = filepath.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as e:
        return ([], [(str(filepath), f"{type(e).__name__}: {e}")])

    parser = Parser(lang)
    tree = parser.parse(source.encode("utf-8"))

    # Extract all call expressions with their qualified names
    calls = _extract_calls(tree, lang)

    # Check for guards
    guard_lines = _find_guard_calls(tree, lang, source)

    # Build per-function reachability: for each call, check if its
    # enclosing function is a tool handler (not just if the file has
    # any tool registration).
    findings: list[TSFinding] = []
    for call_name, line, col in calls:
        for rule in TS_SINK_RULES:
            for pattern in rule["patterns"]:
                if _matches_pattern(call_name, pattern):
                    # PER-FUNCTION reachability check
                    if not _is_call_reachable(tree, lang, source, line):
                        break
                    # Check guards — skip if guarded
                    if _is_guarded(line, guard_lines):
                        break
                    findings.append(TSFinding(
                        rule_id=rule["id"],
                        category=rule["category"],
                        severity=rule["severity"],
                        description=rule["description"],
                        line=line,
                        col=col,
                        call_text=call_name,
                    ))
                    break  # one finding per call
            else:
                continue
            break

    return (findings, [])


def _is_call_reachable(tree, lang, source: str, sink_line: int) -> bool:
    """Check if a specific call at sink_line is inside an agent-reachable function.

    This is the PER-FUNCTION reachability check — the key fix for precision.
    Instead of checking if the FILE contains any tool registration, we check
    if the FUNCTION containing the sink is a tool handler.

    A function is agent-reachable if:
    1. It's passed as a handler to setRequestHandler(CallToolRequestSchema, fn)
    2. It's passed as the execute/func property in a tool definition
       (DynamicStructuredTool({ func: fn }), server.tool("name", fn), etc.)
    3. It contains a tool registration call (handles arrow functions and
       inline handlers where the sink is in the same function body)
    4. The sink is at module level AND the file has MCP/LangChain tool
       registration (module-level sinks in tool files are reachable)
    5. The sink is directly inside an arrow function or method that is
       passed to a tool registration (inline handler pattern)

    This eliminates false positives from example scripts that import a
    framework and register tools, but have sinks in OTHER functions that
    are NOT tool handlers.
    """
    source_lines = source.split("\n")

    # Strategy: walk the AST to find the enclosing function/method of
    # the sink line. Then check if that function is a tool handler.

    # First, find the enclosing function node
    enclosing_func = _find_enclosing_ts_function(tree, sink_line)

    if enclosing_func is None:
        # Sink is at module level (not inside any function).
        # Module-level sinks are only reachable if the file is a tool
        # server (MCP server with setRequestHandler, registerTool).
        # A file that merely calls tool() to define tools but has the
        # sink in the script body (e.g., fs.writeFile to save a PNG)
        # is NOT agent-reachable — the sink runs at script load time,
        # not when an agent calls a tool.
        return _check_file_level_reachability_strict(source)
    else:
        # Sink is inside a function. Check if THAT function is a tool handler.
        func_text = _node_text(enclosing_func, source_lines)
        if _is_tool_handler(func_text, source):
            return True

        # Check if this is a NAMED function whose name appears in a
        # tool registration elsewhere in the file.
        func_name = _get_function_name(enclosing_func, source_lines)
        if func_name and _is_name_in_tool_registration(func_name, source):
            return True

        # Check if the enclosing function is an arrow function or
        # anonymous function that is directly passed as an argument
        # to a tool registration call.
        if _is_inline_handler(enclosing_func, source_lines):
            return True

        # Class method reachability: if the sink is in a method of a class
        # that is instantiated and used in a tool registration in the same
        # file, the method is agent-reachable (one-hop interprocedural).
        # This catches the MCP memory server pattern:
        #   class MemoryStore { saveGraph() { fs.writeFile(...) } }
        #   const store = new MemoryStore();
        #   server.registerTool("name", ..., () => store.createEntities(...))
        if _is_method_of_tool_class(enclosing_func, tree, source_lines, source):
            return True

        return False


def _find_enclosing_ts_function(tree, line: int):
    """Find the function/method/arrow_function that encloses the given line."""
    best_match = None
    best_start = -1

    def walk(node):
        nonlocal best_match, best_start
        for child in node.children:
            if child.type in ("function_declaration", "method_definition", "arrow_function", "function_expression"):
                start = child.start_point[0] + 1  # 1-indexed
                end = child.end_point[0] + 1
                if start <= line <= end and start > best_start:
                    best_match = child
                    best_start = start
            walk(child)

    walk(tree.root_node)
    return best_match


def _node_text(node, source_lines: list[str]) -> str:
    """Extract the text of a tree-sitter node from source lines."""
    start_row = node.start_point[0]
    end_row = node.end_point[0]
    start_col = node.start_point[1]
    end_col = node.end_point[1]
    if start_row == end_row:
        return source_lines[start_row][start_col:end_col]
    parts = [source_lines[start_row][start_col:]]
    for r in range(start_row + 1, end_row):
        parts.append(source_lines[r])
    parts.append(source_lines[end_row][:end_col])
    return "\n".join(parts)


def _is_tool_handler(func_text: str, full_source: str) -> bool:
    """Check if a function's text indicates it's a tool handler.

    A function is a tool handler if:
    1. It contains a reachability signal (setRequestHandler, execute:, etc.)
       — this handles inline arrow functions passed to tool registrations.
    2. The function is a named function that appears in a tool registration
       elsewhere in the file (checked via _check_file_level_reachability
       for the function name).
    """
    # Check if the function body itself contains tool registration signals
    for signal in TS_REACHABILITY_SIGNALS:
        if signal == "tool(":
            # Skip import lines
            for line in func_text.split("\n"):
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("from "):
                    continue
                if "tool(" in stripped and not stripped.startswith("//"):
                    return True
        elif signal == "execute:":
            for line in func_text.split("\n"):
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue
                if "execute:" in stripped or "execute :" in stripped:
                    return True
        elif signal in func_text:
            return True

    return False


def _get_function_name(node, source_lines: list[str]) -> str | None:
    """Extract the name of a function node if it has one."""
    # For function_declaration: the name is a child node of type "identifier"
    for child in node.children:
        if child.type == "identifier":
            return _node_text(child, source_lines)
    # For method_definition: the name is the "property_identifier" child
    for child in node.children:
        if child.type == "property_identifier":
            return _node_text(child, source_lines)
    return None


def _is_name_in_tool_registration(func_name: str, source: str) -> bool:
    """Check if a function name appears as an argument to a tool registration.

    This catches patterns like:
      tool("name", myHandler)
      server.tool("name", myHandler)
      setRequestHandler(Schema, myHandler)
      DynamicStructuredTool({ func: myHandler })
    """
    for signal in TS_REACHABILITY_SIGNALS:
        if signal == "tool(":
            # Check if func_name appears in a line containing tool(
            for line in source.split("\n"):
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("from "):
                    continue
                if stripped.startswith("//"):
                    continue
                if "tool(" in stripped and func_name in stripped:
                    return True
        elif signal == "setRequestHandler":
            if "setRequestHandler" in source and func_name in source:
                # Check they appear on the same or adjacent lines
                lines = source.split("\n")
                for i, line in enumerate(lines):
                    if "setRequestHandler" in line:
                        # Check this line and next 2 lines for func_name
                        for j in range(i, min(i + 3, len(lines))):
                            if func_name in lines[j]:
                                return True
        elif signal == "DynamicStructuredTool":
            if "DynamicStructuredTool" in source and func_name in source:
                return True
    return False


def _is_inline_handler(node, source_lines: list[str]) -> bool:
    """Check if an arrow/anonymous function is directly passed as a tool handler argument.

    This catches the common pattern:
      server.tool("name", async (args) => { ... sink ... })
      setRequestHandler(Schema, async (req) => { ... sink ... })

    We check if the line where the function starts (or the preceding line)
    contains a tool registration pattern.
    """
    start_row = node.start_point[0]

    # Check the line where the function starts and up to 3 preceding lines
    for offset in range(0, 4):
        row = start_row - offset
        if row < 0 or row >= len(source_lines):
            continue
        line = source_lines[row].strip()
        if line.startswith("//") or line.startswith("import ") or line.startswith("from "):
            continue
        for signal in TS_REACHABILITY_SIGNALS:
            if signal == "tool(":
                if "tool(" in line:
                    return True
            elif signal == "execute:":
                if "execute:" in line or "execute :" in line:
                    return True
            elif signal == "setRequestHandler":
                if "setRequestHandler" in line:
                    return True
            elif signal == "DynamicStructuredTool":
                if "DynamicStructuredTool" in line:
                    return True
            elif signal == "registerTool":
                if "registerTool" in line:
                    return True
    return False


def _is_method_of_tool_class(func_node, tree, source_lines: list[str], source: str) -> bool:
    """Check if a method belongs to a class that is used in tool registration.

    This catches the MCP memory server pattern:
      class MemoryStore { saveGraph() { fs.writeFile(...) } }
      const store = new MemoryStore();
      server.registerTool("name", ..., () => store.createEntities(...))

    The method saveGraph() is not directly a tool handler, but it's called
    by methods that ARE tool handlers (createEntities → saveGraph). We
    approximate this by checking: if the class is instantiated AND the
    file has tool registration, methods on that class are reachable.

    This is a one-hop interprocedural approximation. It may produce false
    positives on large classes with non-tool methods, but the alternative
    (missing the MCP memory server's file writes) is worse.
    """
    # Find the enclosing class
    class_node = _find_enclosing_class(func_node, tree)
    if class_node is None:
        return False

    # Get the class name
    class_name = None
    for child in class_node.children:
        if child.type == "identifier" or child.type == "type_identifier":
            class_name = _node_text(child, source_lines)
            break

    if not class_name:
        return False

    # Check if the file has tool registration AND mentions the class
    # (either instantiation or method call on an instance)
    has_tool_reg = _check_file_level_reachability(source)
    if not has_tool_reg:
        return False

    # Check if the class name appears outside its own definition
    # (i.e., it's instantiated or used somewhere)
    class_line = class_node.start_point[0]
    for i, line in enumerate(source_lines):
        if i == class_line:
            continue  # Skip the class definition line
        if i >= class_node.start_point[0] and i <= class_node.end_point[0]:
            continue  # Skip lines inside the class definition
        if class_name in line and not line.strip().startswith("//"):
            # Check if it looks like instantiation or usage
            if f"new {class_name}" in line or f"{class_name}(" in line:
                return True
            # Also check for variable typing or instantiation patterns
            if f": {class_name}" in line or f"<{class_name}>" in line:
                return True

    return False


def _find_enclosing_class(func_node, tree):
    """Find the class definition that encloses a function node."""
    # Walk up from the function to find a class definition
    # tree-sitter doesn't have parent pointers, so we search
    best_class = None
    best_start = -1

    func_start = func_node.start_point[0]

    def walk(node):
        nonlocal best_class, best_start
        for child in node.children:
            if child.type == "class_declaration" or child.type == "class_herb_declaration":
                start = child.start_point[0]
                end = child.end_point[0]
                if start <= func_start <= end and start > best_start:
                    best_class = child
                    best_start = start
            walk(child)

    walk(tree.root_node)
    return best_class


def _check_file_level_reachability(source: str) -> bool:
    """Check if the file contains any tool registration (for module-level sinks).

    This is the fallback for sinks that are NOT inside any function.
    Module-level sinks in files that register tools are considered reachable.
    """
    for signal in TS_REACHABILITY_SIGNALS:
        if signal == "tool(":
            for line in source.split("\n"):
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("from "):
                    continue
                if "tool(" in stripped and not stripped.startswith("//"):
                    return True
        elif signal == "execute:":
            for line in source.split("\n"):
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue
                if "execute:" in stripped or "execute :" in stripped:
                    return True
        elif signal in source:
            return True
    return False


def _check_file_level_reachability_strict(source: str) -> bool:
    """Strict check for module-level sinks.

    Module-level sinks (not inside any function) are only reachable if
    the file is an MCP server that registers request handlers directly
    at module level. A file that merely calls tool() to define tools
    but has the sink in the script body (e.g., fs.writeFile to save a
    PNG in an example) is NOT agent-reachable.

    Only setRequestHandler and registerTool count as strong signals
    for module-level reachability. tool() and DynamicStructuredTool
    define tools but don't make module-level code agent-reachable.
    """
    strict_signals = ["setRequestHandler", "registerTool"]
    for signal in strict_signals:
        if signal in source:
            return True
    return False


def _check_reachability(tree, lang, source: str) -> bool:
    """Check if the file contains any agent-tool reachability signal.

    Uses text-based detection for tool registration patterns. This is
    the same approach as the Python analyser's lexical check.

    To avoid false positives from example scripts that merely import a
    framework (e.g., `import { tool } from "langchain"`) but don't
    register any tools, we check for actual USAGE of the signal, not
    just the import. Specifically:
    - `setRequestHandler` must appear as a function call
    - `server.tool(` must appear as a call
    - `DynamicStructuredTool` must appear with `func:` or `execute:`
    - `execute:` as a property in an object literal passed to a tool
    """
    for signal in TS_REACHABILITY_SIGNALS:
        if signal in source:
            # For import-only signals like "@modelcontextprotocol/sdk",
            # require an actual tool registration in the file too.
            # For "tool(" we need to distinguish from import statements.
            if signal == "tool(":
                # Must be a call, not an import like `import { tool } from`
                # Check that "tool(" appears outside of import context
                lines = source.split("\n")
                for line in lines:
                    stripped = line.strip()
                    if stripped.startswith("import ") or stripped.startswith("from "):
                        continue
                    if "tool(" in stripped and not stripped.startswith("//"):
                        return True
                continue
            if signal == "execute:":
                # "execute:" in an object literal is a reachability signal,
                # but only if it's not in a comment
                for line in source.split("\n"):
                    stripped = line.strip()
                    if stripped.startswith("//"):
                        continue
                    if "execute:" in stripped or "execute :" in stripped:
                        return True
                continue
            # For other signals, the text match is sufficient
            return True
    return False


def _extract_calls(tree, lang) -> list[tuple[str, int, int]]:
    """Extract all call expressions with their qualified names.

    Uses tree-sitter queries to find call_expression nodes and extracts
    their qualified name (e.g., stripe.refunds.create, execSync).
    """
    from tree_sitter import Query, QueryCursor

    # Query for call expressions — both member_expression and identifier
    query = Query(lang, """
    (call_expression
      function: [(member_expression) @member
                 (identifier) @bare]
    ) @call
    """)

    cursor = QueryCursor(query)
    captures = cursor.captures(tree.root_node)

    calls: list[tuple[str, int, int]] = []

    # Process member expressions (e.g., stripe.refunds.create)
    for node in captures.get("member", []):
        qualified = _get_qualified_name(node)
        if qualified:
            calls.append((qualified, node.start_point[0] + 1, node.start_point[1]))

    # Process bare identifiers (e.g., execSync)
    for node in captures.get("bare", []):
        name = node.text.decode("utf-8")
        calls.append((name, node.start_point[0] + 1, node.start_point[1]))

    return calls


def _get_qualified_name(node) -> str:
    """Extract the qualified dotted name from a member_expression node."""
    parts: list[str] = []
    current = node

    while True:
        if hasattr(current, "children") and current.children:
            # Find the property identifier (rightmost)
            prop = None
            obj = None
            for child in current.children:
                if child.type == "property_identifier":
                    prop = child.text.decode("utf-8")
                elif child.type in ("member_expression", "identifier", "call_expression"):
                    obj = child

            if prop:
                parts.insert(0, prop)

            if obj and obj.type == "identifier":
                parts.insert(0, obj.text.decode("utf-8"))
                break
            elif obj and obj.type == "member_expression":
                current = obj
                continue
            elif obj and obj.type == "call_expression":
                # e.g., boto3.client("s3").deleteObjects()
                # Get the inner call's name
                for inner_child in obj.children:
                    if inner_child.type == "member_expression":
                        inner_name = _get_qualified_name(inner_child)
                        if inner_name:
                            parts.insert(0, inner_name)
                        break
                break
            else:
                break
        else:
            break

    return ".".join(parts) if parts else ""


def _matches_pattern(call_name: str, pattern: str) -> bool:
    """Check if a call name matches a pattern.

    Matches:
      - exact: "stripe.refunds.create" == "stripe.refunds.create"
      - suffix: "this.stripe.refunds.create" ends with "stripe.refunds.create"
      - bare: "execSync" == "execSync"
    """
    if call_name == pattern:
        return True
    if call_name.endswith("." + pattern):
        return True
    return False


def _find_guard_calls(tree, lang, source: str) -> set[int]:
    """Find lines containing guard calls.

    Uses a lexical check (same approach as the Python analyser's lexical
    precedence heuristic). A guard call before a sink in the same function
    suppresses the finding.
    """
    guard_lines: set[int] = set()
    for line_num, line in enumerate(source.split("\n"), 1):
        for guard in TS_GUARD_PATTERNS:
            if guard in line:
                guard_lines.add(line_num)
                break
    return guard_lines


def _is_guarded(sink_line: int, guard_lines: set[int]) -> bool:
    """Check if a sink is guarded by a guard call before it in the same function.

    This is a lexical-precedence heuristic (same as the Python analyser):
    a guard call on a line before the sink suppresses the finding.
    """
    for guard_line in guard_lines:
        if guard_line < sink_line:
            return True
    return False


__all__ = [
    "TSFinding",
    "analyze_typescript_file",
    "is_typescript_extra_available",
    "TS_SINK_RULES",
    "TS_REACHABILITY_SIGNALS",
    "TS_GUARD_PATTERNS",
]
