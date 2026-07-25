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
    suppressed: bool = False
    suppression_reason: str = ""
    tier: str = "production"


def detect_sinks(
    tree: ast.Module,
    filepath: str,
    rules: list[SinkRule],
    *,
    parent_map: dict[int, ast.AST] | None = None,
) -> list[SinkFinding]:
    """Walk the AST and find all sink calls matching the rules.

    SQL string patterns (type=string_pattern) are only matched on string
    literals that are arguments to execute(), cursor(), or commit() calls,
    or assigned to a variable named 'query'/'sql'/'statement'.
    """
    findings: list[SinkFinding] = []

    # Sort rules by priority (lower = evaluated first) so that more specific
    # rules (qualified_call, priority 10) are checked before less specific
    # rules (attr_call, priority 20). This ensures session.delete(url) matches
    # NET-EGRESS (qualified, priority 10) before DATA-DELETE-OBJ (priority 20).
    sorted_rules = sorted(rules, key=lambda r: r.priority)

    # Build a simple variable-type map from assignments like:
    #   p = Path(...)       → p maps to "Path"
    #   session = Session() → session maps to "Session"
    # This lets us match p.unlink() against the "Path" module pattern.
    var_types = _build_var_type_map(tree)

    # Build receiver-origin support maps (Work Order 1, Part 1 + Part 2):
    #   self_attr_origins — maps self.<attr> to constructor names for
    #                       `self.github = Github(...)` patterns.
    #   import_aliases    — maps `import psycopg2 as pg` so origin chains
    #                       can be normalised to canonical module names.
    self_attr_origins = _build_self_attr_origins(tree)
    import_aliases = _build_import_aliases(tree)

    # Build a parent-pointer map so we can find the enclosing function
    # for any node (needed for arg_is_tainted escalation and declarative
    # guard detection).
    # Profiling showed this identical map was built twice per file — once
    # here and once in the engine — costing ~12% of a langchain scan.
    # Callers that already have one pass it in.
    if parent_map is None:
        parent_map = _build_parent_map(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for rule in sorted_rules:
                if _match_call(
                    node, rule, var_types,
                    self_attr_origins=self_attr_origins,
                    import_aliases=import_aliases,
                ):
                    severity = rule.severity
                    # Check for escalation: if the rule has an escalate_when
                    # block and the condition matches, upgrade severity.
                    if rule.escalate_when:
                        enclosing_func = _find_enclosing_function_with_parents(node, parent_map)
                        if _check_escalate(node, rule.escalate_when, enclosing_func):
                            severity = rule.escalate_when.get("severity", "high")

                    findings.append(SinkFinding(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=severity,
                        description=rule.description,
                        line=node.lineno,
                        col=node.col_offset,
                        call_text=_call_to_text(node),
                    ))
                    break  # one finding per call

            # Check if this is a cursor.execute("DELETE FROM ...") call
            for rule in sorted_rules:
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
            for rule in sorted_rules:
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
            for rule in sorted_rules:
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


def _build_parent_map(tree: ast.Module) -> dict[int, ast.AST]:
    """Build a map from node id() to parent node, for walking up the tree."""
    parent_map: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[id(child)] = parent
    return parent_map


def _find_enclosing_function_with_parents(
    node: ast.AST, parent_map: dict[int, ast.AST]
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Walk up the parent chain to find the enclosing function."""
    current = node
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = parent_map.get(id(current))
    return None


def _check_escalate(
    node: ast.Call,
    escalate: dict[str, Any],
    enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> bool:
    """Check if the escalate_when condition is met.

    Currently supports:
      - type="arg_is_tainted": checks if the argument at the specified
        position or keyword derives from a parameter of the enclosing function.
    """
    if enclosing_func is None:
        return False

    esc_type = escalate.get("type", "")
    if esc_type == "arg_is_tainted":
        arg_positions = escalate.get("arg_positions", [])
        arg_keywords = escalate.get("arg_keywords", [])

        # Collect parameter names of the enclosing function
        param_names = set()
        for arg in enclosing_func.args.args:
            param_names.add(arg.arg)
        for arg in enclosing_func.args.posonlyargs:
            param_names.add(arg.arg)
        for arg in enclosing_func.args.kwonlyargs:
            param_names.add(arg.arg)
        if enclosing_func.args.vararg:
            param_names.add(enclosing_func.args.vararg.arg)
        if enclosing_func.args.kwarg:
            param_names.add(enclosing_func.args.kwarg.arg)

        # Check positional args
        for pos in arg_positions:
            if pos < len(node.args):
                if _is_tainted(node.args[pos], param_names):
                    return True

        # Check keyword args
        for kw in node.keywords:
            if kw.arg in arg_keywords:
                if _is_tainted(kw.value, param_names):
                    return True

    return False


def _is_tainted(node: ast.expr, param_names: set[str]) -> bool:
    """Check if an AST expression is tainted (derives from a function parameter).

    Tainted:
      - A Name node matching a parameter: url, host, etc.
      - An f-string containing a parameter: f"https://{host}/api"
      - A BinOp string concat containing a parameter: "https://" + host
      - An attribute access rooted at a parameter: req.url
      - A method call on a parameter: url.strip()

    Not tainted:
      - String literals: "https://api.vendor.com/..."
      - Module-level constants (Name nodes not in param_names)
      - self.attr (unless self is a param AND attr is tainted — rare)
    """
    if isinstance(node, ast.Name):
        return node.id in param_names

    if isinstance(node, ast.JoinedStr):
        # f-string — check all interpolated values
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                if _is_tainted(val.value, param_names):
                    return True
        return False

    if isinstance(node, ast.BinOp):
        return _is_tainted(node.left, param_names) or _is_tainted(node.right, param_names)

    if isinstance(node, ast.Attribute):
        # e.g., req.url — check if the root is a parameter
        root = node
        while isinstance(root.value, ast.Attribute):
            root = root.value
        if isinstance(root.value, ast.Name):
            return root.value.id in param_names
        return False

    if isinstance(node, ast.Call):
        # Method call on a parameter: url.strip(), url.replace(...)
        if isinstance(node.func, ast.Attribute):
            return _is_tainted(node.func.value, param_names)
        return False

    return False


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


# ---------------------------------------------------------------------------
# Receiver-origin resolution (Work Order 1, Part 1 + Part 2 foundation).
#
# The goal is to answer "what produced this call receiver?" without relying
# primarily on variable names. The resolver supports:
#   - direct module attribute:        requests.put(...)
#   - constructor call:               WebClient("token").chat_postMessage(...)
#   - chained method call:            psycopg2.connect("dsn").cursor().execute(...)
#   - local variable assignment:      cursor = conn.cursor(); cursor.execute(...)
#   - module-level assignment:        github = Github("token"); github.get_repo(...)
#   - instance attribute assignment:  self.github = Github("token"); self.github.get_repo(...)
#   - alias imports:                  import psycopg2 as pg; pg.connect(...)
#
# The resolver is depth-limited (max ~3 origin hops), caches per file,
# terminates safely on cycles, and distinguishes strong evidence from
# heuristic evidence. Full interprocedural / cross-file dataflow is out of
# scope.
# ---------------------------------------------------------------------------


# Maximum number of origin hops when walking assignment chains.
_RECEIVER_ORIGIN_MAX_DEPTH = 3


@dataclass
class ReceiverOrigin:
    """Resolved origin of a call receiver.

    `chain` is the list of constructor / module / method hops from the
    outermost expression down to the receiver, e.g.:
        ["Github(...)", "get_repo(repo)"]   for github.get_repo(repo)
        ["psycopg2.connect(...)", "cursor()"] for psycopg2.connect(...).cursor()

    `confidence` is one of:
        strong    — origin established from a constructor call, module
                    attribute, or assignment traced to a constructor.
        heuristic — origin inferred from a naming convention only (e.g.
                    variable literally named `cursor`). Heuristic evidence
                    MUST NOT be presented as strongly bound (RULE 4).
    """

    expression: str
    origin: str
    chain: list[str]
    confidence: str  # "strong" | "heuristic" | "unknown"

    @property
    def is_strong(self) -> bool:
        return self.confidence == "strong"


def _origin_label_for_call(call: ast.Call) -> str:
    """Short human-readable label for a constructor/factory call.

    Returns strings like ``Github(...)`` or ``psycopg2.connect(...)`` so the
    chain is readable in briefs and findings.
    """
    name = _get_call_name(call)
    return f"{name}(...)" if name else "(...)"


def _resolve_receiver_origin(
    receiver: ast.expr,
    var_types: dict[str, str] | None,
    self_attr_origins: dict[str, str] | None,
    import_aliases: dict[str, str] | None,
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> ReceiverOrigin | None:
    """Resolve what produced a call receiver.

    Returns ``None`` when no evidence can be gathered. Returns a
    ``ReceiverOrigin`` with ``confidence="heuristic"`` when only naming
    evidence is available — callers MUST treat heuristic evidence as weak
    (RULE 4).
    """
    if _depth > _RECEIVER_ORIGIN_MAX_DEPTH:
        return None
    if _seen is None:
        _seen = set()
    if id(receiver) in _seen:
        return None  # cycle safety
    _seen.add(id(receiver))

    # Form 2.1 / 2.2: receiver is itself a constructor call.
    #   WebClient("token").chat_postMessage(...)
    #   psycopg2.connect("dsn").cursor()           <- receiver of .execute()
    if isinstance(receiver, ast.Call):
        label = _origin_label_for_call(receiver)
        origin = _get_call_name(receiver) or label
        # Resolve the constructor's module through import aliases so that
        # `import psycopg2 as pg; pg.connect(...)` reports origin
        # `psycopg2.connect` rather than `pg.connect`.
        origin = _resolve_qualified_name_through_aliases(origin, import_aliases)
        return ReceiverOrigin(
            expression=_short_expr(receiver),
            origin=origin,
            chain=[label],
            confidence="strong",
        )

    # Form 2.3: receiver is a chained method call on a constructor.
    #   psycopg2.connect("dsn").cursor().execute(...)
    # Here `receiver` is `psycopg2.connect("dsn").cursor()` (a Call), which
    # is already handled by the branch above. The remaining chained form is
    # an Attribute on a Call, e.g. `psycopg2.connect("dsn").cursor` — but
    # that would be the receiver of `.execute()` only if written as
    # `psycopg2.connect("dsn").cursor.execute(...)`, which is rare. The
    # common form goes through the Call branch.
    if isinstance(receiver, ast.Attribute) and isinstance(receiver.value, ast.Call):
        inner = _resolve_receiver_origin(
            receiver.value, var_types, self_attr_origins, import_aliases,
            _depth=_depth + 1, _seen=_seen,
        )
        if inner is not None:
            return ReceiverOrigin(
                expression=_short_expr(receiver),
                origin=inner.origin,
                chain=inner.chain + [f"{receiver.attr}()"],
                confidence="strong" if inner.is_strong else "heuristic",
            )

    # Form 2.4 / 2.5: receiver is a bare Name (local or module-level var).
    #   github.get_repo(repo)             where github = Github("token")
    #   cursor.execute(query)             where cursor = conn.cursor()
    if isinstance(receiver, ast.Name):
        var_name = receiver.id
        # Strong evidence: var_types maps the variable to a constructor.
        if var_types and var_name in var_types:
            mapped = var_types[var_name]
            mapped = _resolve_qualified_name_through_aliases(mapped, import_aliases)
            # A constructor assignment (github = Github("token")) stores the
            # call name "Github" — strong evidence. A factory assignment
            # (client = boto3.client("s3")) stores the service name "s3" —
            # also strong evidence for the boto3 family.
            return ReceiverOrigin(
                expression=var_name,
                origin=mapped,
                chain=[f"{mapped}(...)"] if mapped else [],
                confidence="strong",
            )
        # Heuristic-only: variable name matches a known DB receiver name.
        # This is the legacy fallback. It MUST be flagged heuristic so
        # callers can bias to WEAK under ambiguity (RULE 4).
        return None

    # Form 2.6: receiver is `self.<attr>`.
    #   self.github.get_repo(...)
    # Strong only when self_attr_origins maps the attr to a constructor.
    if isinstance(receiver, ast.Attribute) and isinstance(receiver.value, ast.Name) and receiver.value.id == "self":
        attr = receiver.attr
        if self_attr_origins and attr in self_attr_origins:
            mapped = self_attr_origins[attr]
            mapped = _resolve_qualified_name_through_aliases(mapped, import_aliases)
            return ReceiverOrigin(
                expression=f"self.{attr}",
                origin=mapped,
                chain=[f"self.{attr}", f"{mapped}(...)"] if mapped else [f"self.{attr}"],
                confidence="strong",
            )
        # Heuristic-only: attr name matches a known pattern. Flag heuristic.
        return None

    return None


def _short_expr(node: ast.AST) -> str:
    """Best-effort short text representation of an AST node for chains."""
    try:
        return ast.unparse(node)[:80]
    except Exception:
        return "<expr>"


def _resolve_qualified_name_through_aliases(
    name: str, import_aliases: dict[str, str] | None
) -> str:
    """Rewrite the leading segment of a dotted name through import aliases.

    For example, if ``import psycopg2 as pg`` is in scope, ``pg.connect``
    resolves to ``psycopg2.connect``. Aliases are only applied to the first
    segment — we do not chase cross-module renames.
    """
    if not import_aliases or not name:
        return name
    if "." not in name:
        # Bare name that might be an aliased import.
        return import_aliases.get(name, name)
    head, _, tail = name.partition(".")
    if head in import_aliases:
        return f"{import_aliases[head]}.{tail}"
    return name


def _build_self_attr_origins(tree: ast.Module) -> dict[str, str]:
    """Build a map of `self.<attr>` names to their constructor call names.

    Covers the common pattern:
        class Foo:
            def __init__(self):
                self.github = Github("token")
                self.client = A2AClient(...)
    which produces ``{"github": "Github", "client": "A2AClient"}``.

    This is file-local and best-effort — it does not chase inheritance or
    cross-file assignments.
    """
    origins: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if (isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, (ast.Name, ast.Attribute))):
                ctor = _get_call_name(node.value)
                for target in node.targets:
                    if (isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "self"):
                        if ctor:
                            origins[target.attr] = ctor
    return origins


def _build_import_aliases(tree: ast.Module) -> dict[str, str]:
    """Build a map of alias -> original module name from import statements.

    Covers:
        import psycopg2 as pg             -> {"pg": "psycopg2"}
        from github import Github as GH   -> {"GH": "Github"}  (name-level)
        import github                     -> (no alias, not added)
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
    return aliases


def _receiver_origin_is_excluded(
    receiver: ast.expr,
    excluded_receivers: list[str],
    var_types: dict[str, str] | None,
    self_attr_origins: dict[str, str] | None = None,
    import_aliases: dict[str, str] | None = None,
) -> bool:
    """Return True only when there is ORIGIN evidence that the receiver is
    a member of ``excluded_receivers``.

    Origin evidence (strong):
      - var_types maps the receiver variable to a constructor whose name
        matches an excluded receiver (covers `client = A2AClient(...)`).
      - the receiver is a direct constructor call to an excluded receiver
        (covers `A2AClient(...).send_message(...)`).
      - the receiver is `self.<attr>` and self_attr_origins maps the attr
        to an excluded constructor.

    Name-only evidence (heuristic) is NOT sufficient to exclude — that
    would create false negatives (RULE 7). If a future Part 2 caller wants
    to treat heuristic evidence as weak rather than clean, it can call
    `_resolve_receiver_origin` directly and inspect `.confidence`.
    """
    origin = _resolve_receiver_origin(
        receiver, var_types, self_attr_origins, import_aliases
    )
    if origin is None or not origin.origin:
        return False
    # Only exclude on STRONG evidence. Heuristic-only matches must not
    # suppress a finding (RULE 4 + RULE 7).
    if not origin.is_strong:
        return False
    low = origin.origin.lower()
    # Match on the final segment (e.g. "A2AClient" from "agno.client.a2a.A2AClient")
    # as well as the full dotted form, so excluded_receivers can list either.
    final = low.rsplit(".", 1)[-1]
    for excluded in excluded_receivers:
        ex = excluded.lower()
        if ex == low or ex == final or low.endswith("." + ex):
            return True
    return False


def _match_call(
    node: ast.Call,
    rule: SinkRule,
    var_types: dict[str, str] | None = None,
    *,
    self_attr_origins: dict[str, str] | None = None,
    import_aliases: dict[str, str] | None = None,
) -> bool:
    match_type = rule.match.get("type", "")
    if match_type == "name_call":
        return _match_name_call(node, rule)
    elif match_type == "attr_call":
        return _match_attr_call(node, rule, var_types)
    elif match_type == "qualified_call":
        return _match_qualified_call(
            node, rule, var_types,
            self_attr_origins=self_attr_origins,
            import_aliases=import_aliases,
        )
    elif match_type == "subprocess_deploy":
        return _match_subprocess_deploy(node)
    # open_write and sql_execute_pattern are handled in the main detect_sinks loop
    return False


def _match_qualified_call(
    node: ast.Call,
    rule: SinkRule,
    var_types: dict[str, str] | None = None,
    *,
    self_attr_origins: dict[str, str] | None = None,
    import_aliases: dict[str, str] | None = None,
) -> bool:
    """Match calls by their full qualified dotted name (e.g., subprocess.run).

    This is the SAFE replacement for the cross-product matching in attr_call.
    Instead of matching module_patterns × func_patterns (which produces false
    positives like asyncio.run matching EXEC-SHELL because asyncio is a module
    and run is a func), qualified_call matches the FULL dotted name of the call
    against an explicit list of known-dangerous qualified names.

    Supports:
      - Direct qualified calls: subprocess.run(...), os.system(...)
      - Variable-type tracking: p = Path(...); p.unlink() matches Path.unlink
      - Chained calls: boto3.client("s3").delete_object() matches boto3.client
    """
    qualified_patterns = rule.match.get("qualified_patterns", [])
    if not qualified_patterns:
        return False

    # RECEIVER EXCLUSION: some verbs are shared between a consequential
    # external channel and internal framework plumbing. `send_message` is
    # both "send a Slack message" and "hand a task to another agent over
    # A2A". The second is inter-agent transport, not a side effect on the
    # outside world, and it is the dominant false-positive category recorded
    # in the r05 negative result. Mirrors the _is_db_receiver constraint.
    #
    # DISCIPLINE (Work Order 1, Part 1): the exclusion must require evidence
    # that the receiver is an A2A / agent-transport object — not a bare
    # method name. A bare name fallback (`or recv.id`) is forbidden because
    # it would falsely suppress a real SMTP send if the variable happened to
    # be named `a2a_client`. Origin evidence is established by:
    #   - var_types mapping the receiver variable to a known A2A constructor
    #     (covers `client = A2AClient(...); client.send_message(...)`);
    #   - the receiver being a direct constructor call to a known A2A client
    #     (covers `A2AClient(...).send_message(...)`);
    #   - the receiver being `self.<attr>` where the attr name matches a
    #     known A2A client name AND the class assigned that attr from a
    #     known A2A constructor in __init__ (best-effort, file-local).
    # Name-only matches on the receiver variable are NOT sufficient.
    excluded_receivers = rule.match.get("exclude_receiver_types", [])
    if excluded_receivers and isinstance(node.func, ast.Attribute):
        if _receiver_origin_is_excluded(
            node.func.value, excluded_receivers, var_types,
            self_attr_origins=self_attr_origins,
            import_aliases=import_aliases,
        ):
            return False

    # Get the full dotted name of the call
    if isinstance(node.func, ast.Name):
        call_name = node.func.id
    elif isinstance(node.func, ast.Attribute):
        call_name = _get_attr_chain(node.func)
    else:
        return False

    # Direct match against qualified patterns
    for pattern in qualified_patterns:
        if call_name == pattern:
            return True
        # Also match if the call name ends with the pattern (e.g., pattern is
        # "system" and call is "os.system")
        if call_name.endswith("." + pattern):
            return True

    # Variable-type tracking: if p = Path(...), then p.unlink() matches "Path.unlink"
    if var_types and isinstance(node.func, ast.Attribute):
        root = node.func
        while isinstance(root.value, ast.Attribute):
            root = root.value
        if isinstance(root.value, ast.Name):
            var_name = root.value.id
            inferred_type = var_types.get(var_name)
            if inferred_type:
                # Replace the variable name with its inferred type
                typed_name = call_name.replace(var_name, inferred_type, 1)
                for pattern in qualified_patterns:
                    if typed_name == pattern:
                        return True
                    if typed_name.endswith("." + pattern):
                        return True
                # Also check just the type.method part
                if "." in call_name:
                    method = call_name.split(".")[-1]
                    type_method = f"{inferred_type.split('.')[-1]}.{method}"
                    for pattern in qualified_patterns:
                        if type_method == pattern:
                            return True

    # Chained-call resolution: boto3.client("s3").delete_object()
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
        inner_call = node.func.value
        if isinstance(inner_call.func, ast.Attribute):
            inner_name = _get_attr_chain(inner_call.func)
            method = node.func.attr
            full = f"{inner_name}.{method}"
            for pattern in qualified_patterns:
                if full == pattern or full.endswith("." + pattern):
                    return True

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
    """Check if this is a cursor.execute() or cursor.executemany() call.

    The SINK is the execute/executemany/executescript method call itself.
    The SQL argument's content is a SEVERITY MODIFIER, not a gate:

      literal SQL containing DROP/DELETE/TRUNCATE/ALTER  -> HIGH (destructive)
      non-literal SQL (variable, f-string, concatenation) -> HIGH (caller-controlled)
      literal SELECT-only                                 -> not reported

    RECEIVER CONSTRAINT: the call must be on a database receiver. A bare
    .execute() on any object (e.g., step.execute(), task.execute()) does
    NOT match. Evidence that the receiver is a DB connection or cursor:
      - receiver name matches conn/cur/cursor/session/engine/db
      - receiver was constructed from a known connect() call
      - module imports a DB driver (sqlite3, psycopg2, asyncpg, sqlalchemy, pymysql)

    This prevents false positives like agno's step.execute() matching
    DATA-DELETE-SQL at HIGH severity.
    """
    if not isinstance(node.func, ast.Attribute):
        return False
    method_name = node.func.attr
    if method_name not in ("execute", "executemany", "executescript", "exec"):
        return False

    # Must have at least one argument (the SQL)
    if not node.args:
        return False

    # RECEIVER CONSTRAINT: check that the receiver looks like a DB connection
    receiver = node.func.value
    if not _is_db_receiver(receiver):
        return False

    patterns = rule.match.get("patterns", [])
    first_arg = node.args[0]

    # Check if the first arg is a string literal
    text = _extract_string_from_node(first_arg)
    if text:
        # Literal SQL — check if it contains dangerous patterns
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        # Literal SELECT-only — not reported
        return False

    # Non-literal SQL (variable, f-string, concatenation) — this is the
    # CALLER-CONTROLLED case. It is strictly more dangerous than a literal
    # because the agent controls the SQL. Always report.
    return True


# Names that indicate a database receiver.
_DB_RECEIVER_NAMES = frozenset({
    "conn", "connection", "cur", "cursor", "session", "engine",
    "db", "database", "client", "cnx",
})

# DB driver module names that, if imported, indicate DB context.
_DB_DRIVER_IMPORTS = frozenset({
    "sqlite3", "psycopg2", "psycopg", "asyncpg", "sqlalchemy",
    "pymysql", "mysql", "cx_Oracle", "pyodbc", "mongodb",
    "pymongo", "redis", "cassandra",
})

# Names that look like DB connect() calls.
_DB_CONNECT_NAMES = frozenset({
    "connect", "create_engine", "create_async_engine",
    "Connection", "Cursor",
})


def _is_db_receiver(receiver: ast.expr) -> bool:
    """Check if a call receiver looks like a database connection or cursor.

    Conservative: returns True only when there's positive evidence the
    receiver is a DB object. This prevents false positives on generic
    .execute() calls (step.execute(), task.execute(), etc.).
    """
    # Direct name: conn.execute(...), cursor.execute(...)
    if isinstance(receiver, ast.Name):
        name_lower = receiver.id.lower()
        # Check if the name matches a DB receiver pattern
        for db_name in _DB_RECEIVER_NAMES:
            if name_lower == db_name or name_lower.startswith(db_name):
                return True
        # Also match compound names like db_conn, my_cursor
        for db_name in _DB_RECEIVER_NAMES:
            if db_name in name_lower:
                return True
        return False

    # Chained call: sqlite3.connect("...").execute(...) or conn.cursor().execute(...)
    if isinstance(receiver, ast.Call):
        # Get the call's function name
        call_func = receiver.func
        if isinstance(call_func, ast.Name):
            call_name = call_func.id
        elif isinstance(call_func, ast.Attribute):
            call_name = _get_attr_chain(call_func)
        else:
            call_name = ""

        if call_name:
            for connect_name in _DB_CONNECT_NAMES:
                if call_name.endswith(connect_name):
                    return True
        # Check if the inner call's function is an attribute of a DB module
        if isinstance(call_func, ast.Attribute):
            module_name = ""
            if isinstance(call_func.value, ast.Name):
                module_name = call_func.value.id.lower()
            for driver in _DB_DRIVER_IMPORTS:
                if module_name == driver:
                    return True
        return False

    # Attribute: self.conn.execute(...), self.cursor.execute(...)
    if isinstance(receiver, ast.Attribute):
        attr_lower = receiver.attr.lower()
        for db_name in _DB_RECEIVER_NAMES:
            if attr_lower == db_name or attr_lower.startswith(db_name):
                return True
        return False

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
