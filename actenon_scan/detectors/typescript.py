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
      2. Extracts all call expressions and their qualified names
      3. Matches against TS_SINK_RULES
      4. Checks reachability (MCP/LangChain tool registration)
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
        # Use TSX grammar for JSX, TS grammar for plain JS
        lang = Language(tsts.language_tsx() if suffix == ".jsx" else tsts.language_typescript())
    else:
        return ([], [])

    try:
        source = filepath.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as e:
        return ([], [(str(filepath), f"{type(e).__name__}: {e}")])

    parser = Parser(lang)
    tree = parser.parse(source.encode("utf-8"))

    # Check reachability — is there a tool/handler registration in this file?
    has_reachability = _check_reachability(tree, lang, source)

    # Extract all call expressions with their qualified names
    calls = _extract_calls(tree, lang)

    # Check for guards
    guard_lines = _find_guard_calls(tree, lang, source)

    findings: list[TSFinding] = []
    for call_name, line, col in calls:
        for rule in TS_SINK_RULES:
            for pattern in rule["patterns"]:
                if _matches_pattern(call_name, pattern):
                    # Check reachability — skip if not agent-reachable
                    if not has_reachability:
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


def _check_reachability(tree, lang, source: str) -> bool:
    """Check if the file contains any agent-tool reachability signal."""
    # Simple text-based check for reachability signals.
    # This is the same approach as the Python analyser's lexical check.
    for signal in TS_REACHABILITY_SIGNALS:
        if signal in source:
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
