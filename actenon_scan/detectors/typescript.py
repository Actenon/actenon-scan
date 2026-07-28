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
    # Work Order 1.5: guard-state fields (parity with Go's GoFinding).
    # Empty string means "no guard found"; "guarded" means suppress;
    # "weak" means downgrade to LOW; "unbound" means downgrade to MEDIUM.
    guard_status: str = ""
    guard_message: str = ""


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
        # Work Order 1.8: these are bare payment verbs that collide with
        # common method names. `order.refund()`, `billing.createCharge()`,
        # etc. would false-positive without bare_only. The qualified forms
        # (stripe.refunds.create, etc.) are in PAY-STRIPE-REFUND.
        "bare_only_patterns": ["refund", "createCharge", "createRefund", "issueRefund", "processRefund"],
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
        # Work Order 1.8: `exec` and `spawn` are bare globals that collide
        # with common member expressions:
        #   - `regex.exec(str)` (RegExp.prototype.exec — input validation)
        #   - `pool.spawn(n)` (unrelated method named spawn)
        # Without bare_only, the endswith match in _matches_pattern treats
        # any `X.exec(...)` or `X.spawn(...)` as shell execution, producing
        # HIGH-severity false positives on defensive code inside tool handlers.
        #
        # Bare `exec`/`spawn` calls where the identifier is imported from
        # "child_process" ARE shell execution and must still flag. The
        # matching loop resolves imports to verify this.
        "bare_only_patterns": ["exec", "spawn"],
        # When the call is a member expression (X.exec / X.spawn / X.fetch),
        # flag only if the receiver X is a recognised shell/global binding.
        # For exec/spawn: "child_process" and common alias "cp" are genuine.
        # Other receivers (SAFE, pool, regex) are not shell execution.
        "global_receivers": ["child_process", "cp"],
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
        # Work Order 1.7: `fetch` is a Web API global. It must match the
        # bare identifier `fetch(url)` and the qualified `globalThis.fetch`,
        # but NOT member expressions like `handler.fetch(request)` (an MCP
        # HTTP handler entry point that processes incoming requests, not
        # outbound egress). Without this restriction, the endswith match in
        # _matches_pattern treats `handler.fetch` as `fetch`, producing false
        # positives on the MCP TypeScript SDK's webStandard.examples.ts.
        #
        # Work Order 1.8: `global_receivers` allows `window.fetch(url)`,
        # `globalThis.fetch(url)`, `self.fetch(url)` to still flag — these
        # ARE the global fetch accessed via member expression. Other
        # receivers (handler, guarded, secured) are not egress.
        # Aliased imports (`import { fetch as f }` → `f(url)`) are not
        # caught by name-based matching regardless of this fix.
        "bare_only_patterns": ["fetch"],
        "global_receivers": ["window", "globalThis", "self"],
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


def analyze_typescript_file(
    filepath: str | Path,
    guard_patterns: list[str] | None = None,
) -> tuple[list[TSFinding], list[tuple[str, str]]]:
    """Analyze a TypeScript/JavaScript file for sinks.

    Returns (findings, errors). If tree-sitter is not installed, returns
    ([], [(filepath, "tree-sitter not installed")]).

    The analyser:
      1. Parses the file with tree-sitter (TS or TSX grammar based on extension)
      2. Extracts all call expressions with their qualified names
      3. Matches against TS_SINK_RULES
      4. Checks PER-FUNCTION reachability (is the enclosing function a tool handler?)
      5. Checks guards with soundness analysis (Work Order 1.5):
         dominance + binding + result-use, ported from go.py / guards.py.
         Defeated guards (result discarded, after sink, dead branch, try/catch
         swallow, split branch) are flagged, not suppressed.

    ``guard_patterns`` is the user-configured guard name list from
    .actenon-scan.json. If None, falls back to the built-in TS_GUARD_PATTERNS.
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
        # utf-8-sig strips a UTF-8 BOM if present (Windows editor convention).
        source = filepath.read_text(encoding="utf-8-sig")
    except (UnicodeDecodeError, OSError) as e:
        return ([], [(str(filepath), f"{type(e).__name__}: {e}")])

    parser = Parser(lang)
    tree = parser.parse(source.encode("utf-8"))
    source_bytes = source.encode("utf-8")

    # Resolve effective guard patterns: user config + built-in TS vocab.
    effective_guards = list(guard_patterns) if guard_patterns else []
    for g in TS_GUARD_PATTERNS:
        if g not in effective_guards:
            effective_guards.append(g)

    # Extract all call expressions with their qualified names
    calls = _extract_calls(tree, lang)

    # Work Order 1.8: resolve imports from "child_process" so bare `exec`
    # and `spawn` calls can be verified as genuine shell execution. This
    # is the same local-resolution approach used for guard assert-style
    # classification (_ts_find_function_def). Returns a set of identifier
    # names imported from child_process (handling `import { exec }`,
    # `import { exec as runCommand }`, `import * as cp`, `import child_process`).
    child_process_bindings = _resolve_child_process_imports(tree.root_node, source_bytes)

    # Work Order 1.8: also build a map from call line/col to the actual
    # call_expression node, so we can inspect whether the function is a
    # bare identifier or a member_expression. _extract_calls flattens
    # both into strings, losing the distinction for cases like `/re/.exec()`
    # where _get_qualified_name returns "exec" (the property) without the
    # receiver. We need the node to check the receiver type.
    call_nodes_by_pos: dict[tuple[int, int], object] = {}
    for node in _ts_walk(tree.root_node):
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                call_nodes_by_pos[(node.start_point[0] + 1, node.start_point[1])] = func_node

    # Build per-function reachability: for each call, check if its
    # enclosing function is a tool handler (not just if the file has
    # any tool registration).
    findings: list[TSFinding] = []
    for call_name, line, col in calls:
        # Work Order 1.8: inspect the actual function node to determine
        # if this is a bare identifier call or a member expression. This
        # matters for bare_only_patterns: `/re/.exec(name)` extracts as
        # call_name="exec" but the function node is a member_expression,
        # so we must treat it as a member expression (and check the receiver).
        func_node_at_pos = call_nodes_by_pos.get((line, col))
        is_member_expr = func_node_at_pos is not None and func_node_at_pos.type == "member_expression"
        actual_receiver = ""
        if is_member_expr and func_node_at_pos is not None:
            # Extract the receiver's text to check against global_receivers
            obj = func_node_at_pos.child_by_field_name("object")
            if obj is not None:
                actual_receiver = _ts_node_text(obj, source_bytes)

        for rule in TS_SINK_RULES:
            bare_only = set(rule.get("bare_only_patterns", []))
            global_receivers = set(rule.get("global_receivers", []))
            for pattern in rule["patterns"]:
                # Work Order 1.7 + 1.8: bare_only_patterns match the exact
                # call_name (bare global) or a member expression whose
                # receiver is a recognised global. They do NOT match member
                # expressions on arbitrary receivers.
                if pattern in bare_only:
                    if call_name == pattern and not is_member_expr:
                        # Bare global call (e.g., `fetch(url)` with function
                        # node being an identifier, not a member_expression).
                        # Work Order 1.8: for exec/spawn, verify the bare
                        # identifier is imported from child_process. If not
                        # imported, it's ambiguous — flag it (prefer false
                        # positive over false negative on shell execution).
                        if pattern in ("exec", "spawn"):
                            if pattern not in child_process_bindings:
                                # Not imported from child_process. Could be
                                # a user-defined function or a global. We
                                # flag it because shell execution is HIGH
                                # severity and a false negative is worse.
                                # A false positive here is a review; a false
                                # negative is a missed shell-execution path.
                                pass  # flag — proceed
                        pass  # match — proceed to reachability check
                    elif is_member_expr and call_name == pattern:
                        # Member expression where the property matches the
                        # bare_only pattern (e.g., handler.fetch, SAFE.exec).
                        # Check the receiver against global_receivers.
                        if actual_receiver in global_receivers:
                            pass  # global receiver — flag (e.g., window.fetch)
                        elif actual_receiver in child_process_bindings and pattern in ("exec", "spawn"):
                            pass  # cp.exec / child_process.exec — flag
                        else:
                            continue  # arbitrary receiver — no match (SAFE.exec, pool.spawn)
                    elif is_member_expr and call_name != pattern:
                        # The call_name (qualified) doesn't match the bare
                        # pattern exactly. Check if the last segment matches
                        # (e.g., call_name="child_process.exec", pattern="exec").
                        last_seg = call_name.rsplit(".", 1)[-1]
                        if last_seg == pattern:
                            if actual_receiver in global_receivers:
                                pass
                            elif actual_receiver in child_process_bindings and pattern in ("exec", "spawn"):
                                pass
                            elif "." in call_name and call_name.startswith(tuple(global_receivers)):
                                # e.g., "child_process.exec" — receiver is "child_process"
                                receiver_from_name = call_name.rsplit(".", 1)[0]
                                if receiver_from_name in global_receivers or receiver_from_name in child_process_bindings:
                                    pass
                                else:
                                    continue
                            else:
                                continue
                        else:
                            continue
                    else:
                        continue  # no match — try next pattern
                elif not _matches_pattern(call_name, pattern):
                    continue  # no match — try next pattern
                # Match found — proceed to reachability + guard check
                # PER-FUNCTION reachability check
                if not _is_call_reachable(tree, lang, source, line):
                    break  # not reachable — exit for-pattern loop
                # Work Order 1.5: soundness guard check (ported from go.py).
                # Replaces the lexical _is_guarded heuristic.
                guard_status = ""
                guard_message = ""
                enclosing_func = _find_enclosing_ts_function(tree, line)
                if enclosing_func is not None:
                    sink_call_node = _find_call_at_line(tree, line, source_bytes, call_name)
                    if sink_call_node is not None:
                        gs, gm = _check_ts_guard(
                            enclosing_func,
                            sink_call_node,
                            tree.root_node,
                            source_bytes,
                            effective_guards,
                        )
                        guard_status = gs
                        guard_message = gm
                # Work Order 2.1: do NOT suppress guarded findings here.
                # Return them with guard_status="guarded" so the engine can
                # record them as GUARD_FOUND capabilities. The engine decides
                # what becomes a finding (guarded → capability only, not finding).
                # Build rule_id + severity based on guard status
                rule_id = rule["id"]
                severity = rule["severity"]
                description = rule["description"]
                if guard_status == "weak":
                    severity = "low"
                    rule_id = f"{rule['id']}-WEAK"
                    description = f"{rule['description']} (guard call found but return value discarded)"
                elif guard_status == "unbound":
                    severity = "medium"
                    rule_id = f"{rule['id']}-UNBOUND"
                    description = f"{rule['description']} (guard call found but not parameter-bound to sink)"
                findings.append(TSFinding(
                    rule_id=rule_id,
                    category=rule["category"],
                    severity=severity,
                    description=description,
                    line=line,
                    col=col,
                    call_text=call_name,
                    guard_status=guard_status,
                    guard_message=guard_message,
                ))
                break  # one finding per call — exit for-pattern loop
            else:
                continue  # no pattern matched — try next rule
            break  # pattern matched — stop checking rules (one finding per call)

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


# ---------------------------------------------------------------------------
# Guard soundness analysis (Work Order 1.5)
#
# Ported from go.py (_check_go_guard) and guards.py (check_guard).
# Replaces the v1 lexical-precedence heuristic that suppressed any finding
# whenever a guard name appeared on any earlier line in the file.
#
# The v2 algorithm checks three things:
#   1. DOMINANCE: the guard lies on every path to the sink (ancestor walk).
#      Defeated if inside: if-body the sink is not in, statically-false branch
#      (if false), nested function, or try/catch where the catch swallows.
#   2. BINDING: the guard's arguments share identifiers with the sink's.
#   3. RESULT USE: the guard's return value is consumed (assigned and tested,
#      used in a condition, returned, or thrown). Assert-style guards
#      (conventionally throw) are exempt from result-use.
#
# Returns 3-state (matching Python/Go parity):
#   ("guarded", msg)  → suppress
#   ("weak",     msg) → LOW, suffix -WEAK
#   ("unbound",  msg) → MEDIUM, suffix -UNBOUND
#   ("",         msg) → no guard found, keep original severity
#
# Bias: when uncertain whether a construct defeats a guard, treat it as
# defeated and flag it. A false positive is a review; a false negative is a
# clean report on code with a broken guard.
# ---------------------------------------------------------------------------


def _check_ts_guard(
    func_node,
    sink_call_node,
    root_node,
    source: bytes,
    guard_patterns: list[str],
) -> tuple[str, str]:
    """Check if a TS/JS sink is guarded by a dominating, parameter-bound guard.

    Ported from go.py._check_go_guard. See module docstring above for the
    full semantics.
    """
    sink_line = sink_call_node.start_point[0] + 1
    sink_start_byte = sink_call_node.start_byte

    # Find all guard-named calls in the function before the sink.
    # "Before" is by byte offset (execution order), not line number —
    # `if (guard()) { sink(); }` has guard and sink on the same line but
    # the guard's byte range precedes the sink's. A line-based check
    # would miss this common TS/JS pattern.
    guard_calls: list = []
    for node in _ts_walk(func_node):
        if node.type != "call_expression":
            continue
        if node.start_byte >= sink_start_byte:
            continue  # must be before the sink in byte order
        call_name = _ts_get_call_name(node, source)
        if not call_name:
            continue
        if _ts_matches_guard_name(call_name, guard_patterns):
            guard_calls.append((node, call_name))

    if not guard_calls:
        return ("", "")

    # Check dominance for each guard call
    for guard_call, guard_name in guard_calls:
        if not _ts_dominates(guard_call, sink_line, func_node, source):
            continue

        # Check if the guard is assert-style (conventionally throws)
        is_assert_style = _ts_is_assert_style(guard_name, root_node, source)

        # Check parameter binding
        is_bound = _ts_is_bound(guard_call, sink_call_node, source)

        # Check result use
        result_used = _ts_is_result_used(guard_call, func_node, source)

        if is_assert_style:
            # Assert-style guards conventionally throw on failure.
            # Binding is NOT required — the guard raises regardless.
            # But if the result is explicitly discarded (_ = / void), it's WEAK.
            if _ts_is_explicitly_discarded(guard_call, source):
                return ("weak", "assert-style guard dominates but its return value is discarded")
            return ("guarded", "assert-style guard dominates and conventionally throws on failure")
        else:
            # Non-assert-style: may return bool. Binding AND result use required.
            if is_bound and result_used:
                return ("guarded", "guard dominates, is parameter-bound, and result is used")
            elif is_bound and not result_used:
                return ("weak", "a guard call dominates and is bound, but its return value is discarded")
            elif not is_bound and result_used:
                return ("unbound", "a guard call dominates and its result is used, but it shares no parameters with the sink's arguments")
            else:
                return ("unbound", "a guard call dominates but shares no parameters with the sink's arguments and its result is discarded")

    # Guard exists but does not dominate — treat as no guard
    return ("", "")


def _ts_walk(node):
    """Generator: yield all descendants of a tree-sitter node (including itself)."""
    yield node
    for child in node.children:
        yield from _ts_walk(child)


def _ts_get_call_name(call_node, source: bytes) -> str:
    """Extract the qualified name from a TS call_expression node.

    Handles: bare identifier (execSync), member expression (fs.rmSync),
    and deeper member expressions (stripe.refunds.create).
    """
    func = call_node.child_by_field_name("function")
    if func is None:
        return ""
    return _ts_node_text(func, source)


def _ts_node_text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _ts_matches_guard_name(call_name: str, guard_patterns: list[str]) -> bool:
    """Check if a TS call name matches any guard pattern.

    Handles both camelCase (TS convention) and snake_case. Mirrors
    go.py._matches_guard_name.
    """
    name_lower = call_name.lower()
    last_segment = name_lower.rsplit(".", 1)[-1]
    # Normalize: remove underscores so checkPermission matches check_permission
    name_normalized = last_segment.replace("_", "")
    for pattern in guard_patterns:
        p = pattern.lower()
        if p == name_lower or p == last_segment:
            return True
        if name_lower.endswith("." + p):
            return True
        # camelCase match
        p_normalized = p.replace("_", "")
        if p_normalized == name_normalized:
            return True
    # Validation-guard name patterns (check_*, verify_*, etc.) — same set as
    # guards.py._is_validation_guard_name.
    stripped = last_segment.lstrip("_")
    validation_prefixes = (
        "check", "verify", "validate", "ensure", "require", "enforce",
        "assert", "authorize", "authenticate", "guard", "gate", "permit",
        "allow", "deny", "can", "may", "must",
    )
    for prefix in validation_prefixes:
        if stripped.startswith(prefix):
            return True
        # camelCase variant: checkPermission starts with "check"
        if name_normalized.startswith(prefix.replace("_", "")):
            return True
    return False


def _ts_is_assert_style(call_name: str, root_node, source: bytes) -> bool:
    """Check if a TS guard call name is assert-style (conventionally throws).

    Work Order 1.5: unlike the v1 substring heuristic, this function first
    tries LOCAL RESOLUTION — finding the function definition in the same
    file and checking whether it contains a `throw` statement. If found,
    the guard is assert-style. This correctly classifies user-defined
    guards like `authorizeBool` (returns boolean, no throw) as boolean-style,
    which the substring heuristic missed.

    If the function cannot be resolved locally (imported), falls back to a
    name-based heuristic with prefix and exact-name sets mirroring
    guards.py._resolve_guard_style.
    """
    # 1. Local resolution: find the function definition in the same file.
    local_def = _ts_find_function_def(root_node, call_name, source)
    if local_def is not None:
        return _ts_function_throws(local_def, source)

    # 2. Unresolvable: fall back to name heuristic.
    name_lower = call_name.lower().split(".")[-1]
    name_normalized = name_lower.replace("_", "")

    # Prefixes that conventionally throw
    assert_prefixes = ("assert", "require", "enforce", "must", "ensure")
    for prefix in assert_prefixes:
        if name_lower.startswith(prefix + "_") or name_lower == prefix:
            return True
        # camelCase: assertFoo starts with "assert" followed by uppercase
        if name_normalized.startswith(prefix) and len(name_normalized) > len(prefix):
            orig_after = name_lower[len(prefix):len(prefix)+1]
            if orig_after.isupper() or orig_after == "_":
                return True

    # Exact names that conventionally throw or block (snake_case + camelCase)
    conventional_assert = {
        "assert", "require", "enforce", "ensure", "must",
        "authorize", "authenticate", "authorize_request", "authorize_action",
        "verify", "validate", "guard", "gate", "policy_gate", "policy_check",
        "guard_action", "guard_request",
        "enforce_policy", "enforce_permission", "enforce_authorization",
        "assert_can", "assert_allowed", "assert_authorized", "assert_permitted",
        "can_user", "user_can", "user_may",
        "audit_and_allow", "audit_and_execute", "audit_and_proceed",
        "verify_pccb", "verify_proof", "verify_token", "verify_signature",
        "elicit", "elicitation", "request_elicitation",
        "confirm", "confirm_action", "confirm_proceed",
        "human_approval", "human_in_the_loop", "human_confirmation",
        "casbin_enforce",
        "jwt_required", "require_jwt",
        "require_auth", "require_authentication", "require_authorization",
        "login_required", "requires_login", "requires_auth",
        "require_admin", "requires_admin", "admin_required",
        "require_superuser",
        "auth_required", "authz_required", "require_authz",
        "verify_mtls", "require_client_cert", "require_api_key",
    }
    if name_lower in conventional_assert:
        return True
    # camelCase exact match
    for entry in conventional_assert:
        if entry.replace("_", "") == name_normalized:
            return True

    # NOTE: deliberately NO substring match here. The Go detector's substring
    # match (entry in name_lower) caused "authorize" to match "authorizebool",
    # misclassifying boolean guards as assert-style. Local resolution is the
    # principled fix; the name heuristic is a narrow fallback for unresolvable
    # (imported) guards only.
    return False


def _ts_find_function_def(root_node, name: str, source: bytes):
    """Find a function_declaration or method_definition by name in the AST.

    Handles dotted names (obj.authorize -> authorize). Returns the node or None.
    """
    short_name = name.split(".")[-1]
    for node in _ts_walk(root_node):
        if node.type in ("function_declaration", "method_definition", "function_expression"):
            for child in node.children:
                if child.type in ("identifier", "property_identifier"):
                    child_text = _ts_node_text(child, source)
                    if child_text == short_name or child_text == name:
                        return node
    return None


def _resolve_child_process_imports(root_node, source: bytes) -> set[str]:
    """Resolve which identifier names are bound to child_process imports.

    Work Order 1.8: used to verify that a bare `exec(cmd)` or `spawn(cmd)`
    call is genuine shell execution (imported from "child_process") rather
    than a user-defined function or unrelated global.

    Handles all common import forms:
      - `import { exec } from "child_process"`       -> {"exec"}
      - `import { exec as runCommand } from "..."`   -> {"runCommand"}
      - `import { exec, spawn } from "child_process"` -> {"exec", "spawn"}
      - `import * as cp from "child_process"`         -> {"cp"}
      - `import child_process from "child_process"`   -> {"child_process"}
      - `const cp = require("child_process")`         -> {"cp"}

    Returns a set of identifier names that, when used as a bare call or as
    a member-expression receiver, indicate child_process access.
    """
    bindings: set[str] = set()
    for node in _ts_walk(root_node):
        if node.type == "import_statement":
            # Check if the source is "child_process"
            source_text = ""
            for child in node.children:
                if child.type == "string":
                    source_text = _ts_node_text(child, source).strip().strip('"').strip("'")
                    break
            if source_text != "child_process":
                continue
            # Extract the import clause
            clause = node.child_by_field_name("source")
            # Walk the import_clause to find imported names
            for child in node.children:
                if child.type == "import_clause":
                    # Named imports: { exec }, { exec as runCommand }, { exec, spawn }
                    for sub in _ts_walk(child):
                        if sub.type == "import_specifier":
                            # import_specifier has: identifier (imported) and optionally identifier (local)
                            idents = [c for c in sub.children if c.type == "identifier"]
                            if len(idents) == 1:
                                bindings.add(_ts_node_text(idents[0], source))
                            elif len(idents) >= 2:
                                # The local alias is the second identifier
                                bindings.add(_ts_node_text(idents[1], source))
                        elif sub.type == "namespace_import":
                            # import * as cp
                            for c in sub.children:
                                if c.type == "identifier":
                                    bindings.add(_ts_node_text(c, source))
                        elif sub.type == "identifier" and child.type == "import_clause":
                            # import child_process from "child_process" (default import)
                            # The identifier is a direct child of import_clause
                            if sub.parent == child:
                                bindings.add(_ts_node_text(sub, source))
        elif node.type == "lexical_declaration" or node.type == "variable_declaration":
            # const cp = require("child_process")
            for decl in node.children:
                if decl.type == "variable_declarator":
                    value = decl.child_by_field_name("value")
                    if value is None or value.type != "call_expression":
                        continue
                    func = value.child_by_field_name("function")
                    if func is None or _ts_node_text(func, source) != "require":
                        continue
                    args = value.child_by_field_name("arguments")
                    if args is None:
                        continue
                    for arg in args.children:
                        if arg.type == "string":
                            arg_text = _ts_node_text(arg, source).strip().strip('"').strip("'")
                            if arg_text == "child_process":
                                name_node = decl.child_by_field_name("name")
                                if name_node and name_node.type == "identifier":
                                    bindings.add(_ts_node_text(name_node, source))
    return bindings


def _ts_function_throws(func_node, source: bytes) -> bool:
    """Check if a TS function contains a throw statement.

    A function that throws is assert-style — the guard enforces by throwing.
    A function that only returns is boolean-style.
    """
    for node in _ts_walk(func_node):
        if node.type == "throw_statement":
            return True
    return False


def _ts_dominates(guard_call, sink_line: int, func_node, source: bytes) -> bool:
    """Check if a TS guard call dominates the sink (lies on every path to it).

    A guard does NOT dominate if it is:
      - inside an `if` body the sink is not also inside
      - inside a statically-false branch (`if (false)`, `if (0)`, `if (null)`)
      - inside a nested function/arrow_function
      - inside a try block whose catch clause swallows exceptions
        (catches a broad type and has an empty body or only `pass`-like
        statements with no re-throw)
    """
    for node in _ts_walk(func_node):
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")

            # Statically-false condition
            if condition is not None:
                cond_text = _ts_node_text(condition, source).strip()
                if cond_text in ("false", "0", "null", "undefined", "void 0"):
                    if _ts_node_contains(guard_call, consequence) or _ts_node_contains(guard_call, alternative):
                        return False

            # Guard in consequence but sink not in consequence
            if consequence and _ts_node_contains(guard_call, consequence):
                if not _ts_node_contains_line(consequence, sink_line):
                    return False
            # Guard in alternative but sink not in alternative
            if alternative and _ts_node_contains(guard_call, alternative):
                if not _ts_node_contains_line(alternative, sink_line):
                    return False

        elif node.type == "try_statement":
            # If guard is inside the try body, check whether any catch
            # clause swallows exceptions (defeats an assert-style guard).
            try_body = node.child_by_field_name("body")
            if try_body and _ts_node_contains(guard_call, try_body):
                # Check each catch_clause — if ANY catch swallows, the
                # guard's throw is defeated.
                for child in node.children:
                    if child.type == "catch_clause":
                        if _ts_catch_swallows(child, source):
                            return False

        elif node.type in ("function_declaration", "method_definition",
                           "function_expression", "arrow_function"):
            # Guard inside a nested function — does not dominate
            if _ts_node_contains(guard_call, node) and node is not func_node:
                # But the sink might also be inside this nested function.
                # If so, the guard can still dominate (lexical scope).
                if not _ts_node_contains_line(node, sink_line):
                    return False

    return True


def _ts_catch_swallows(catch_node, source: bytes) -> bool:
    """Check if a catch clause swallows exceptions (no re-throw, empty or pass-only body).

    A catch that catches a broad type (Exception, Error, any, or untyped)
    and has an empty body, a body with only comments, or a body that does
    not re-throw, defeats an assert-style guard's throw.

    Conservative: if the catch has a type guard (e.g., catch (e if e.code === 'X')),
    or if the body contains a throw, it does NOT swallow.
    """
    body = catch_node.child_by_field_name("body")
    if body is None:
        return True  # no body — definitely swallows

    # Walk the body looking for a throw statement
    for node in _ts_walk(body):
        if node.type == "throw_statement" and node is not body:
            return False  # re-throws — does not swallow

    # No throw in the body. Check if the body is effectively empty
    # (only contains the block node and maybe comments/empty statements).
    has_real_statement = False
    for child in body.children:
        if child.type in ("comment", "block"):
            continue
        if child.type == "empty_statement":
            continue
        # An expression_statement with just an identifier or literal is
        # effectively a no-op (e.g., `catch (e) { undefined; }`)
        if child.type == "expression_statement":
            text = _ts_node_text(child, source).strip().rstrip(";").strip()
            if text in ("", "undefined", "null", "void 0", "0", "false", "true"):
                continue
            # A call like console.log(e) is a real statement but still swallows
            has_real_statement = True
            continue
        has_real_statement = True

    # If the body has real statements but no throw, it swallows.
    # If the body is empty, it definitely swallows.
    return True


def _ts_node_contains(inner, outer) -> bool:
    """Check if the outer node contains the inner node (by byte range)."""
    if outer is None:
        return False
    return (inner.start_byte >= outer.start_byte and
            inner.end_byte <= outer.end_byte)


def _ts_node_contains_line(node, line: int) -> bool:
    """Check if a line number is within a node's line range."""
    if node is None:
        return False
    start_line = node.start_point[0] + 1
    end_line = node.end_point[0] + 1
    return start_line <= line <= end_line


def _ts_is_bound(guard_call, sink_call, source: bytes) -> bool:
    """Check if the guard's arguments share identifiers with the sink's.

    Ported from go.py._go_is_bound. Resolves one level of simple aliasing.
    """
    guard_args = _ts_collect_arg_names(guard_call, source)
    sink_args = _ts_collect_arg_names(sink_call, source)

    if not guard_args or not sink_args:
        # If either has no named args, we can't determine binding — be
        # conservative and say it IS bound (avoids false UNBOUND).
        return True

    shared = guard_args & sink_args
    return bool(shared)


def _ts_collect_arg_names(call_node, source: bytes) -> set[str]:
    """Collect identifier names from a TS call's arguments."""
    names: set[str] = set()
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return names
    for child in args.children:
        if child is None:
            continue
        if child.type == "identifier":
            names.add(_ts_node_text(child, source))
        elif child.type == "member_expression":
            # obj.field — take the base identifier
            obj = child.child_by_field_name("object")
            if obj and obj.type == "identifier":
                names.add(_ts_node_text(obj, source))
    return names


def _ts_is_result_used(guard_call, func_node, source: bytes) -> bool:
    """Check if the TS guard call's return value is used.

    A guard call is "result used" if:
      - It's in an if/while/for condition: `if (guard(...)) { ... }`
      - It's in a variable declaration with subsequent test:
        `const ok = guard(...); if (ok) { ... }`
      - It's in a return statement: `return guard(...)`
      - It's in a throw statement: `throw guard(...)`
      - It's in a binary expression: `guard(...) && ...`, `!guard(...)`

    A standalone expression statement is "result NOT used".
    """
    guard_start = guard_call.start_byte
    guard_end = guard_call.end_byte

    for node in _ts_walk(func_node):
        if not (node.start_byte <= guard_start and guard_end <= node.end_byte):
            continue
        if node is guard_call:
            continue

        # if (guard(...)) { ... }
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            if condition and _ts_node_contains(guard_call, condition):
                return True
        # while / for / do-while condition
        if node.type in ("while_statement", "for_statement", "do_statement"):
            cond = node.child_by_field_name("condition")
            if cond and _ts_node_contains(guard_call, cond):
                return True
        # const ok = guard(...) — lexical/variable declaration
        if node.type in ("lexical_declaration", "variable_declaration"):
            # Check if guard_call is in the initializer
            for child in node.children:
                if child.type == "variable_declarator":
                    value = child.child_by_field_name("value")
                    if value and _ts_node_contains(guard_call, value):
                        # Found: const X = guard(...). Check if X is
                        # subsequently tested in an if/return.
                        name_node = child.child_by_field_name("name")
                        if name_node and name_node.type == "identifier":
                            var_name = _ts_node_text(name_node, source)
                            if _ts_var_subsequently_tested(var_name, func_node, guard_call, source):
                                return True
                        return False  # assigned but not tested → not used
        # assignment: ok = guard(...)
        if node.type == "assignment_expression":
            right = node.child_by_field_name("right")
            if right and _ts_node_contains(guard_call, right):
                left = node.child_by_field_name("left")
                if left and left.type == "identifier":
                    var_name = _ts_node_text(left, source)
                    if _ts_var_subsequently_tested(var_name, func_node, guard_call, source):
                        return True
                return False
        # return guard(...)
        if node.type == "return_statement":
            if _ts_node_contains(guard_call, node):
                return True
        # throw guard(...)
        if node.type == "throw_statement":
            if _ts_node_contains(guard_call, node):
                return True
        # binary/unary expression: guard(...) && ..., !guard(...)
        if node.type in ("binary_expression", "unary_expression"):
            # If the guard call is a direct operand, its result is used.
            if _ts_node_contains(guard_call, node):
                return True

    # Standalone expression statement — result is NOT used
    return False


def _ts_var_subsequently_tested(var_name: str, func_node, guard_call, source: bytes) -> bool:
    """Check if a variable name is tested in an if/while/return after the guard call."""
    guard_line = guard_call.start_point[0] + 1
    for node in _ts_walk(func_node):
        if node.type in ("if_statement", "while_statement", "for_statement", "do_statement"):
            cond = node.child_by_field_name("condition")
            if cond is None:
                continue
            if node.start_point[0] + 1 < guard_line:
                continue  # must be after the guard
            cond_text = _ts_node_text(cond, source)
            if var_name in cond_text:
                return True
        if node.type == "return_statement":
            if node.start_point[0] + 1 < guard_line:
                continue
            ret_text = _ts_node_text(node, source)
            if var_name in ret_text:
                return True
    return False


def _ts_is_explicitly_discarded(guard_call, source: bytes) -> bool:
    """Check if the guard call's return value is explicitly discarded.

    In TS/JS, there's no `_` discard like Go. But `void guard(...)` explicitly
    discards. A standalone expression statement also discards, but that's
    already handled by _ts_is_result_used returning False.
    """
    parent = guard_call.parent
    if parent is None:
        return False
    # void guard(...)
    if parent.type == "unary_expression":
        operator = parent.child_by_field_name("operator")
        if operator is not None:
            op_text = _ts_node_text(operator, source)
            if op_text == "void":
                return True
    return False


def _find_call_at_line(tree, line: int, source: bytes = b"", call_name: str = ""):
    """Find the call_expression node at the given line.

    Used by analyze_typescript_file to get the sink_call_node for binding
    analysis. If ``call_name`` and ``source`` are provided, returns the
    first call whose qualified name matches — this disambiguates same-line
    calls where a guard and sink share a line (e.g.,
    `if (guard()) { sink(); }`).

    Without name filtering, returns the smallest call_expression spanning
    the line (preferring calls that START on the line).
    """
    best_match = None
    for node in _ts_walk(tree.root_node):
        if node.type != "call_expression":
            continue
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        if not (start <= line <= end):
            continue
        # If a call_name is specified, only accept calls matching it.
        if call_name and source:
            node_name = _ts_get_call_name(node, source)
            if node_name != call_name:
                continue
        # Prefer the call that STARTS on this line (the sink), over one
        # that merely spans it.
        if start == line:
            return node
        if best_match is None or (node.end_byte - node.start_byte) < (best_match.end_byte - best_match.start_byte):
            best_match = node
    return best_match


__all__ = [
    "TSFinding",
    "analyze_typescript_file",
    "is_typescript_extra_available",
    "TS_SINK_RULES",
    "TS_REACHABILITY_SIGNALS",
    "TS_GUARD_PATTERNS",
]
