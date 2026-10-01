"""Repository-index adapters for the common invocation graph.

Three passes construct scopes/bindings, enumerate separately owned bodies,
and resolve evidence-bearing binding claims. Legacy indexes supply parsing
and module coordinates, never authority from flattened same-name resolution.
"""
from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass, field
import os
import posixpath
from pathlib import Path
import re

from actenon_scan.engine import _collect_files, _glob_match, _UNSUPPORTED_SUFFIXES
from actenon_scan.invocation_graph import (
    CallableSymbol, Entrypoint, GraphLimits, ImplementationTarget, InvocationGraph,
    InvocationNode, InvocationRoot, RootKind, stable_id,
)
from actenon_scan.repository.symbol_index import RepositoryIndex, ResolutionCertainty
from actenon_scan.binding_claims import BindingClaim, BindingEvidence as E, BindingState
from actenon_scan.semantic_ir import (
    BindingEdgeProof, EdgeObligation as O, SemanticState as S, EvaluationMode,
    TargetKind, WriteOperation, WriteCertainty, WriteEvent, meet,
)
from actenon_scan import reachability_kernel as kernel

TS_SUFFIXES = {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
_FUNCTION_TYPES = {"function_declaration", "function_expression", "arrow_function",
                   "generator_function_declaration", "generator_function",
                   "method_definition", "method_declaration", "func_literal"}
_SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", ".env", "node_modules",
              "bower_components", "__pycache__", "build", "dist", "target", ".eggs",
              ".mypy_cache", ".ruff_cache", ".tox", ".cache", ".pytest_cache"}


@dataclass
class _Site:
    owner: CallableSymbol
    line: int
    column: int
    spelling: str
    node: object
    dynamic: bool = False
    lexical_scope: str | None = None
    resumes_coroutine: bool = False
    region: object = None
    arguments: tuple[str, ...] = ()
    ordinal: int = 0


@dataclass
class _Binding:
    """A lexical declaration, never a repository-wide name match."""
    kind: str = "unknown"
    callable_key: str | None = None
    module: str = ""
    # `import a.b` binds a, while explicitly loading the a.b attribute path.
    # `import a.b as saved` instead captures the a.b module object directly.
    qualified_import: str = ""
    member: str | None = None
    level: int = 0
    receiver_class: str | None = None
    conditional: bool = False
    line: int = 0
    column: int = 0
    alias_name: str | None = None
    alias_scope: str | None = None
    capture_sources: tuple[str, ...] = ()
    counter_evidence: frozenset[E] = frozenset()


@dataclass
class _Unit:
    language: str
    file: str
    source: str
    tree: object
    module: str
    symbols: list[CallableSymbol] = field(default_factory=list)
    sites: list[_Site] = field(default_factory=list)
    nodes: dict[str, object] = field(default_factory=dict)
    bindings: dict[str, dict[str, list[_Binding]]] = field(default_factory=dict)
    scope_parents: dict[str, str] = field(default_factory=dict)
    class_scopes: dict[str, str] = field(default_factory=dict)
    # Pass 1 syntax coordinates and execution-region boundaries. No calls yet.
    node_scopes: dict[object, str] = field(default_factory=dict)
    execution_scopes: dict[str, CallableSymbol] = field(default_factory=dict)
    write_events: list[WriteEvent] = field(default_factory=list)
    regions: dict = field(default_factory=dict)
    node_regions: dict = field(default_factory=dict)
    certificates: dict = field(default_factory=dict)
    semantic_gaps: set = field(default_factory=set)
    package_name: str = ""
    exports: set[str] = field(default_factory=set)
    discovered: dict[str, tuple[str, ...]] = field(default_factory=dict)
    syntactic_parents: dict[str, str] = field(default_factory=dict)
    scope_constructs: dict[str, str] = field(default_factory=dict)
    scope_nodes: dict[str, object] = field(default_factory=dict)
    environments: dict = field(default_factory=dict)
    compiler_tables: dict = field(default_factory=dict)
    compiler_provenance: dict = field(default_factory=dict)
    escape_events: list = field(default_factory=list)
    grammar_digest: str = ""
    proof_inventory: object = None

    @property
    def module_key(self):
        return CallableSymbol(self.language, self.file, self.module or "<module>", 1, 1).key

    def bind(self, scope, name, binding=None):
        if name and name != "_":
            if not scope:
                # An unmodeled declaration container has no exact namespace.
                # Retain its observations in a file-owned unknown environment;
                # an empty identifier must never join unrelated source files.
                scope=stable_id('unknown-binding-environment',self.language,self.file)
                self.scope_constructs[scope]='unknown'
                self.scope_parents[scope]=self.module_key
                self.syntactic_parents[scope]=self.module_key
                self.semantic_gaps.add((self.file,'declaration environment not established'))
            self.bindings.setdefault(scope, {}).setdefault(name, []).append(binding or _Binding())
            invalidation = binding is not None and binding.kind == "write"
            self.write_events.append(WriteEvent(scope, TargetKind.LEXICAL_BINDING,
                WriteOperation.MAY_WRITE if invalidation else WriteOperation.DECLARE,
                binding=name, certainty=WriteCertainty.POSSIBLE if invalidation else WriteCertainty.EXACT,
                line=binding.line if binding else 0,
                syntax="accumulated binding counter-evidence" if invalidation else "lexical declaration"))

    def symbol(self, name, node, scope=""):
        if self.language == "python":
            line, col = node.lineno, node.col_offset + 1
        else:
            line, col = node.start_point[0] + 1, node.start_point[1] + 1
        sym = CallableSymbol(self.language, self.file, name, line, col, scope)
        self.symbols.append(sym)
        self.nodes[sym.key] = node
        return sym


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def _text(node, data):
    return data[node.start_byte:node.end_byte].decode("utf-8") if node else ""


def _collect_sources(target, entrypoints, include_globs, exclude_globs):
    if target.is_file():
        return [target]
    py_files, _ = _collect_files(target, include_globs, exclude_globs)
    files = set(py_files)
    for directory, dirs, names in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not d.endswith(".egg-info")
                         and not (Path(directory) / d / "pyvenv.cfg").exists())
        for name in sorted(names):
            path = Path(directory) / name
            if path.suffix == ".py" or path.suffix not in _UNSUPPORTED_SUFFIXES:
                continue
            rel = path.relative_to(target).as_posix()
            if any(_glob_match(rel, g) for g in exclude_globs or ()):
                continue
            if include_globs and not any(_glob_match(rel, g) for g in include_globs):
                continue
            if not any("test" in g or "spec" in g for g in include_globs or ()):
                if name.endswith("_test.go") or re.search(r"\.(test|spec|bench)\.[^.]+$", name):
                    continue
                if any(p in {"__tests__", "__mocks__"} for p in path.relative_to(target).parts):
                    continue
            files.add(path)
    for ep in entrypoints:
        path = target / ep.path
        # Explicit roots override default excludes but respect user excludes.
        if path.is_file() and not any(_glob_match(ep.path, g) for g in exclude_globs or ()):
            files.add(path)
    return sorted(files)


def _python_generator(node):
    """Yield in this body, excluding separately owned nested bodies."""
    pending = list(node.body)
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.Yield, ast.YieldFrom)):
            return True
        if not isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            pending.extend(ast.iter_child_nodes(current))
    return False


def _python_unit(file, source, tree, index, cfg, *, enumerate_calls=True):
    from actenon_scan.detectors.reachability import _reachability_for_func
    module = index._module_qualified_name(file)
    unit = _Unit("python", file, source, tree, module)
    module_sym = CallableSymbol("python", file, module or "<module>", 1, 1)
    unit.execution_scopes[unit.module_key] = module_sym
    unit.scope_constructs[unit.module_key] = "module"
    unit.scope_nodes[unit.module_key] = tree
    directives = {}
    cross_scope_writes = []

    class Collector(ast.NodeVisitor):
        owner = module_sym
        conditional = False
        # A method's lexical parent skips the class namespace.
        class_context = None
        execution_owner = None

        def visit(self, node):
            unit.node_scopes[node] = self.owner.key
            return super().visit(node)

        def bind(self, name, **values):
            directive = directives.get((self.owner.key, name))
            if directive:
                cross_scope_writes.append((self.owner.key, name, directive))
                unit.bind(self.owner.key, name, _Binding("write", counter_evidence=frozenset({E.REASSIGNMENT_WRITE})))
            else:
                unit.bind(self.owner.key, name, _Binding(conditional=self.conditional, **values))

        def parameters(self, args, receiver=None):
            positional = args.posonlyargs + args.args
            for arg in positional + args.kwonlyargs + [a for a in (args.vararg, args.kwarg) if a]:
                self.bind(arg.arg, kind="receiver" if receiver and positional and arg is positional[0] else "unknown",
                          receiver_class=receiver if receiver and positional and arg is positional[0] else None)

        def visit_FunctionDef(self, node):
            for expression in node.decorator_list + node.args.defaults + [x for x in node.args.kw_defaults if x]:
                self.visit(expression)
            previous, conditional, context, execution = self.owner, self.conditional, self.class_context, self.execution_owner
            name = previous.symbol + "." + node.name if previous.symbol != "<module>" else node.name
            sym = unit.symbol(name, node, previous.symbol)
            # A decorator may replace the binding; a generator call does not
            # establish resumption of its body. Keep the source candidate.
            kind = "coroutine_callable" if isinstance(node, ast.AsyncFunctionDef) else "callable"
            counter = set()
            if node.decorator_list:
                counter.add(E.UNKNOWN_DECORATOR)
            if _python_generator(node):
                counter.add(E.DEFERRED_EXECUTION)
            self.bind(node.name, kind=kind, callable_key=sym.key, line=node.lineno,
                      counter_evidence=frozenset(counter))
            unit.execution_scopes[sym.key] = sym
            unit.scope_parents[sym.key] = context[1].key if context else previous.key
            unit.syntactic_parents[sym.key] = previous.key
            unit.scope_constructs[sym.key] = "function"
            unit.scope_nodes[sym.key] = node
            signal = _reachability_for_func(tree, node, cfg, None, node.lineno)
            if signal.confidence == "high":
                unit.discovered[sym.key] = tuple(signal.signals)
            receiver = unit.class_scopes[context[0]] if context else None
            if any(ast.unparse(d).rsplit(".", 1)[-1] in {"staticmethod", "classmethod"} for d in node.decorator_list):
                receiver = None
            self.owner, self.conditional, self.class_context, self.execution_owner = sym, False, None, None
            self.parameters(node.args, receiver)
            for statement in node.body:
                self.visit(statement)
            self.owner, self.conditional, self.class_context, self.execution_owner = previous, conditional, context, execution

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            for expression in node.decorator_list + node.bases + [k.value for k in node.keywords]:
                self.visit(expression)
            previous, context, execution = self.owner, self.class_context, self.execution_owner
            name = previous.symbol + "." + node.name if previous.symbol != "<module>" else node.name
            cls = CallableSymbol("python", file, name, node.lineno, node.col_offset + 1)
            self.bind(node.name, kind="class_object", receiver_class=cls.key, line=node.lineno)
            unit.class_scopes[name] = cls.key
            unit.scope_constructs[cls.key] = "class"
            unit.scope_nodes[cls.key] = node
            unit.syntactic_parents[cls.key] = previous.key
            if node.decorator_list:
                unit.bind(cls.key, "*", _Binding(counter_evidence=frozenset({E.UNKNOWN_DECORATOR})))
            caller = execution or previous
            unit.execution_scopes[cls.key] = caller
            unit.scope_parents[cls.key] = caller.key
            self.owner, self.class_context, self.execution_owner = cls, (name, caller), caller
            for statement in node.body:
                self.visit(statement)
            self.owner, self.class_context, self.execution_owner = previous, context, execution

        def visit_Lambda(self, node):
            for expression in node.args.defaults + [x for x in node.args.kw_defaults if x]:
                self.visit(expression)
            previous, conditional, context, execution = self.owner, self.conditional, self.class_context, self.execution_owner
            name = f"{previous.symbol}.<lambda@{node.lineno}:{node.col_offset + 1}>"
            self.owner = unit.symbol(name, node, previous.symbol)
            unit.execution_scopes[self.owner.key] = self.owner
            unit.scope_parents[self.owner.key] = context[1].key if context else previous.key
            unit.syntactic_parents[self.owner.key] = previous.key
            unit.scope_constructs[self.owner.key] = "lambda"
            unit.scope_nodes[self.owner.key] = node
            self.conditional, self.class_context, self.execution_owner = False, None, None
            self.parameters(node.args)
            self.visit(node.body)
            self.owner, self.conditional, self.class_context, self.execution_owner = previous, conditional, context, execution

        def comprehension(self, node):
            # Syntactic containment, implicit lookup and eager ownership are
            # separate observations. The kernel validates the lookup parent.
            self.visit(node.generators[0].iter)
            previous, context, execution = self.owner, self.class_context, self.execution_owner
            implicit = CallableSymbol("python", file,
                previous.symbol + f".<{type(node).__name__}@{node.lineno}:{node.col_offset+1}>",
                node.lineno, node.col_offset+1)
            parent = previous.key
            while unit.scope_constructs.get(parent) == "class":
                parent = unit.syntactic_parents.get(parent, unit.module_key)
            unit.scope_constructs[implicit.key] = "comprehension"
            unit.scope_nodes[implicit.key] = node
            unit.syntactic_parents[implicit.key] = previous.key
            unit.scope_parents[implicit.key] = parent
            unit.execution_scopes[implicit.key] = execution or previous
            self.owner, self.class_context, self.execution_owner = implicit, None, execution or previous
            for generator in node.generators:
                self.visit(generator.target)
            for generator in node.generators:
                if generator is not node.generators[0]:
                    self.visit(generator.iter)
                for expression in generator.ifs:
                    self.visit(expression)
            for expression in ([node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]):
                self.visit(expression)
            self.owner, self.class_context, self.execution_owner = previous, context, execution

        visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = comprehension

        def assignment(self, node, targets, value):
            if value:
                self.visit(value)
            for target in targets:
                if isinstance(target, ast.Name):
                    values = dict(line=node.lineno, column=node.col_offset + 1)
                    if isinstance(value, ast.Name):
                        values.update(kind="alias", alias_name=value.id, alias_scope=self.owner.key)
                    elif isinstance(value, (ast.Attribute,ast.Subscript)):
                        # Captured members need not be exactly resolved. Their
                        # known source identities still escape monotonically.
                        values.update(kind="capture_alias", alias_scope=self.owner.key,
                            capture_sources=tuple(sorted({ast.unparse(n) for n in ast.walk(value)
                                if isinstance(n,(ast.Name,ast.Attribute,ast.Subscript))})))
                    elif isinstance(value, ast.Lambda):
                        symbol = next(s for s in unit.symbols if unit.nodes[s.key] is value)
                        values.update(kind="callable", callable_key=symbol.key)
                    self.bind(target.id, **values)
                else:
                    self.visit(target)

        def visit_Assign(self, node):
            self.assignment(node, node.targets, node.value)

        def visit_AnnAssign(self, node):
            self.assignment(node, [node.target], node.value)

        def visit_Name(self, node):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                self.bind(node.id, line=node.lineno)

        def visit_Attribute(self, node):
            self.generic_visit(node)

        def visit_Subscript(self, node):
            self.generic_visit(node)

        def visit_ExceptHandler(self, node):
            if node.name:
                self.bind(node.name, line=node.lineno)
            self.generic_visit(node)

        def visit_Import(self, node):
            for alias in node.names:
                self.bind(alias.asname or alias.name.split(".")[0], kind="import",
                          module=alias.name if alias.asname else alias.name.split(".")[0],
                          qualified_import=alias.name if not alias.asname else "", line=node.lineno)

        def visit_ImportFrom(self, node):
            for alias in node.names:
                self.bind(alias.asname or alias.name, kind="import", module=node.module or "",
                          member=alias.name, level=node.level, line=node.lineno)

        def visit_Global(self, node):
            for name in node.names:
                directives[(self.owner.key, name)] = "global"
                self.bind(name, line=node.lineno)

        def visit_Nonlocal(self, node):
            for name in node.names:
                directives[(self.owner.key, name)] = "nonlocal"
                self.bind(name, line=node.lineno)

        def visit_MatchAs(self, node):
            if node.name:
                self.bind(node.name, line=node.lineno)
            self.generic_visit(node)

        visit_MatchStar = visit_MatchAs

        def visit_MatchMapping(self, node):
            if node.rest:
                self.bind(node.rest, line=node.lineno)
            self.generic_visit(node)

        def visit_conditional(self, node):
            previous = self.conditional
            self.conditional = True
            self.generic_visit(node)
            self.conditional = previous

        visit_If = visit_While = visit_For = visit_AsyncFor = visit_Try = visit_conditional
        visit_TryStar = visit_Match = visit_With = visit_AsyncWith = visit_conditional

        def visit_Call(self, node):
            # Pass 1 records lexical scope only. Pass 2 owns enumeration.
            self.generic_visit(node)

    Collector().visit(tree)
    invalidations = set()
    for scope, name, directive in cross_scope_writes:
        if directive == "global":
            destination = unit.module_key
        else:
            destination, _ = _lexical_bindings(unit, unit.scope_parents.get(scope, unit.module_key), name)
        invalidations.add((destination, name))
    for scope, name in sorted(invalidations):
        unit.bind(scope, name, _Binding("write", counter_evidence=frozenset({E.REASSIGNMENT_WRITE})))
    if enumerate_calls:
        _construct_execution_ownership(unit)
    return unit


def _pattern_names(node, data):
    """Binding identifiers only: skip property keys, types and RHS expressions."""
    if node is None:
        return []
    if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
        return [_text(node, data)]
    if node.type in {"required_parameter", "optional_parameter"}:
        return _pattern_names(node.child_by_field_name("pattern"), data)
    if node.type in {"pair_pattern", "assignment_pattern", "object_assignment_pattern"}:
        value = node.child_by_field_name("value") if node.type == "pair_pattern" else node.child_by_field_name("left")
        return _pattern_names(value, data)
    if node.type in {"object_pattern", "array_pattern", "rest_pattern", "formal_parameters", "expression_list"}:
        return [name for child in node.named_children for name in _pattern_names(child, data)]
    if node.type in {"parameter_list", "parameter_declaration", "variadic_parameter_declaration"}:
        if node.type == "parameter_list":
            return [name for child in node.named_children for name in _pattern_names(child, data)]
        return [_text(child, data) for i, child in enumerate(node.children)
                if node.field_name_for_child(i) == "name"]
    return []


def _tree_unit(language, file, source, tree, index, *, enumerate_calls=True):
    module = (index._module_qualified_name(file) if language == "typescript"
              else index._package_qualified_name(file))
    unit = _Unit(language, file, source, tree, module)
    data = source.encode()
    module_sym = CallableSymbol(language, file, module or "<module>", 1, 1)
    unit.execution_scopes[unit.module_key] = module_sym
    unit.scope_constructs[unit.module_key] = "module"
    unit.scope_nodes[unit.module_key] = tree
    if language == "go":
        package = next((n for n in tree.named_children if n.type == "package_clause"), None)
        unit.package_name = _text(package.named_children[0], data) if package and package.named_children else ""

    def class_scope(name):
        if name not in unit.class_scopes:
            unit.class_scopes[name] = stable_id("class-scope", language, file, name)
        return unit.class_scopes[name]

    def this_scope(node, parent, receiver=None):
        scope = stable_id("class-execution-scope", language, file, node.start_point[0] + 1,
                          node.start_point[1] + 1)
        unit.scope_parents[scope] = parent
        unit.execution_scopes[scope] = unit.execution_scopes[parent]
        unit.bind(scope, "this", _Binding("receiver", receiver_class=receiver) if receiver else _Binding())
        return scope

    def visit(node, owner, class_name="", conditional=False, class_identity="", lexical_scope=None):
        scope = lexical_scope or owner.key
        definition_children = ()
        if node.type in {"if_statement", "for_statement", "while_statement", "do_statement",
                         "try_statement", "switch_statement", "switch_case", "conditional_expression",
                         "type_switch_statement", "type_case", "for_in_statement", "catch_clause",
                         "select_statement", "communication_case"}:
            conditional = True
        if node.type in {"statement_block", "block"} and (not node.parent or node.parent.type not in _FUNCTION_TYPES):
            # Block scopes are summarized conservatively, so declarations in
            # a nested block cannot establish an edge from outside that block.
            conditional = True
        if node.type in {"class_declaration", "class"}:
            name = _text(node.child_by_field_name("name"), data)
            class_name = ".".join(x for x in (module, name) if x)
            # Distinct declarations with the same spelling are not one class.
            class_identity = stable_id("class-scope", language, file, node.start_point[0] + 1,
                                       node.start_point[1] + 1, class_name)
            unit.bind(scope, name, _Binding("class_object", receiver_class=class_identity,
                conditional=conditional, line=node.start_point[0] + 1))
            unit.execution_scopes[class_identity] = owner
            unit.scope_constructs[class_identity] = "class"
            unit.scope_nodes[class_identity] = node
            unit.syntactic_parents[class_identity] = scope
            if any(c.type == "decorator" for c in node.children):
                unit.bind(class_identity, "*", _Binding(counter_evidence=frozenset({E.UNKNOWN_DECORATOR})))
                unit.bind(stable_id("static-scope", class_identity), "*", _Binding(counter_evidence=frozenset({E.UNKNOWN_DECORATOR})))
        if language == "typescript" and node.type not in _FUNCTION_TYPES | {"class_declaration", "class"}:
            if node.type.endswith("_declaration") or node.type in {"internal_module", "module"}:
                declared = node.child_by_field_name("name")
                if declared and declared.type in {"identifier", "type_identifier"}:
                    # Unmodeled declarations cannot be passed through as
                    # exact outer value bindings, even for type-only syntax.
                    unit.bind(scope, _text(declared, data), _Binding(conditional=conditional))
            if node.type in {"internal_module", "module"}:
                namespace = stable_id("namespace-scope", language, file, node.start_point[0] + 1,
                                      node.start_point[1] + 1)
                unit.scope_parents[namespace] = scope
                unit.execution_scopes[namespace] = owner
                scope = namespace
        if language == "go" and any(c.type == ":=" for c in node.children) and node.type not in {
                "short_var_declaration", "range_clause", "type_switch_statement"}:
            declared = node.child_by_field_name("left") or node.child_by_field_name("alias")
            for identifier in _pattern_names(declared, data):
                unit.bind(scope, identifier, _Binding(conditional=True))
        if language == "typescript" and node.type == "class_static_block":
            # Executed with the class definition, but its this is the
            # constructor, never an enclosing method's instance receiver.
            scope = this_scope(node, scope)
        if language == "typescript" and node.type in {"public_field_definition", "field_definition"}:
            static = any(child.type == "static" for child in node.children)
            member_scope = stable_id("static-scope", class_identity) if static else class_identity
            name = node.child_by_field_name("name")
            literal_name = name and name.type in {"property_identifier", "private_property_identifier", "identifier"}
            unit.bind(member_scope, _text(name, data) if literal_name else "*")
            value = node.child_by_field_name("value")
            if value:
                if static:
                    initializer, initializer_scope = owner, this_scope(node, scope)
                else:
                    # Instance initialization is a separate, deferred body.
                    # Declaring the class does not establish instantiation.
                    name = f"{class_name}.<field@{node.start_point[0] + 1}:{node.start_point[1] + 1}>"
                    initializer = unit.symbol(name, node, owner.symbol)
                    initializer_scope = initializer.key
                    unit.execution_scopes[initializer_scope] = initializer
                    unit.scope_parents[initializer_scope] = scope
                    unit.bind(initializer_scope, "this", _Binding("receiver", receiver_class=class_identity))
            for child in node.named_children:
                # Computed keys/decorator expressions execute at definition;
                # only the value expression belongs to initialization.
                if value and child == value:
                    visit(child, initializer, class_name, conditional, class_identity, initializer_scope)
                else:
                    visit(child, owner, class_name, conditional, class_identity, scope)
            return
        if node.type in _FUNCTION_TYPES:
            previous_scope = scope
            name_node = node.child_by_field_name("name")
            definition_children = tuple(c for c in node.named_children
                                        if c.type == "decorator" or (c == name_node and c.type == "computed_property_name"))
            for child in definition_children:
                visit(child, owner, class_name, conditional, class_identity, scope)
            name = _text(name_node, data)
            internal_name = name
            declarator = node.parent if node.parent and node.parent.type == "variable_declarator" else None
            variable = declarator.child_by_field_name("name") if declarator else None
            go_value = None
            if language == "go" and node.type == "func_literal" and node.parent and node.parent.type == "expression_list":
                declaration = node.parent.parent
                if len(node.parent.named_children) == 1 and declaration.type in {"short_var_declaration", "var_spec"}:
                    pattern = declaration.child_by_field_name("left") or declaration.child_by_field_name("name")
                    identifiers = _pattern_names(pattern, data)
                    if len(identifiers) == 1:
                        go_value = identifiers[0]
            if not name and variable and variable.type == "identifier":
                name = _text(variable, data)
            method = node.type in {"method_definition", "method_declaration"}
            class_method = method and (language == "go" or (node.parent and node.parent.type == "class_body"))
            if language == "go" and node.type == "method_declaration":
                from actenon_scan.repository.go_symbol_index import _receiver_type_name
                class_name = ".".join(x for x in (module, _receiver_type_name(node, data)) if x)
                class_identity = class_scope(class_name)
            prefix = class_name or (owner.symbol if owner != module_sym else module)
            if not name:
                name = f"<callback@{node.start_point[0] + 1}:{node.start_point[1] + 1}>"
            sym = unit.symbol(".".join(x for x in (prefix, name) if x), node, owner.symbol)
            unit.execution_scopes[sym.key] = sym
            unit.scope_parents[sym.key] = previous_scope
            unit.syntactic_parents[sym.key] = previous_scope
            unit.scope_constructs[sym.key] = "function"
            unit.scope_nodes[sym.key] = node
            static = any(child.type == "static" for child in node.children)
            counter = set()
            if node.type in {"generator_function_declaration", "generator_function"} or (method and any(c.type == "*" for c in node.children)):
                counter.add(E.DEFERRED_EXECUTION)
            if method and any(c.type in {"get", "set"} for c in node.children):
                counter.add(E.EXECUTION_NOT_ESTABLISHED)
            if any(c.type == "decorator" for c in node.children) or bool(
                    class_method and node.prev_named_sibling and node.prev_named_sibling.type == "decorator"):
                counter.add(E.UNKNOWN_DECORATOR)
            if language == "typescript" and class_method and not static and name == "constructor":
                counter.add(E.EXECUTION_NOT_ESTABLISHED)
            kind, binding_counter = "callable", frozenset(counter)
            member_scope = stable_id("static-scope", class_identity) if static else class_identity
            if class_method and class_name:
                computed = language == "typescript" and name_node.type not in {"property_identifier", "private_property_identifier", "identifier"}
                unit.bind(member_scope, "*" if computed else name,
                          _Binding(kind, sym.key, conditional=conditional,
                                                       line=node.start_point[0] + 1,
                                                       column=node.start_point[1] + 1,
                                                       counter_evidence=binding_counter | (frozenset({E.NO_BINDING_PROOF}) if computed else frozenset())))
            elif node.type in {"function_declaration", "generator_function_declaration"} or (variable and variable.type == "identifier"):
                unit.bind(previous_scope, _text(variable, data) if variable else name,
                          _Binding(kind, sym.key, conditional=conditional, line=node.start_point[0] + 1,
                                   column=node.start_point[1] + 1, counter_evidence=binding_counter))
            if go_value:
                unit.bind(previous_scope, go_value, _Binding("callable", sym.key,
                          conditional=conditional, line=node.start_point[0] + 1, column=node.start_point[1] + 1))
            owner, conditional = sym, False
            scope = sym.key
            if node.type in {"function_expression", "generator_function"} and internal_name:
                # The expression's self name lives inside it; the receiving
                # variable name lives in the enclosing scope.
                unit.bind(sym.key, internal_name, _Binding("self_callable", sym.key, counter_evidence=binding_counter))
            for parameter in _pattern_names(node.child_by_field_name("parameters"), data):
                unit.bind(sym.key, parameter)
            for parameter in _pattern_names(node.child_by_field_name("parameter"), data):
                unit.bind(sym.key, parameter)
            for parameter in _pattern_names(node.child_by_field_name("result"), data):
                unit.bind(sym.key, parameter)
            # JavaScript's this is lexical in arrows and rebound in ordinary functions.
            if language == "typescript" and node.type != "arrow_function":
                unit.bind(sym.key, "this", _Binding("receiver", receiver_class=class_identity)
                          if class_method and class_name and not static else _Binding())
            if language == "go" and node.type == "method_declaration":
                names = _pattern_names(node.child_by_field_name("receiver"), data)
                if len(names) == 1:
                    unit.bind(sym.key, names[0], _Binding("receiver", receiver_class=class_identity))
        unit.node_scopes[node] = scope
        if node.type == "variable_declarator":
            name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if not (name and name.type == "identifier" and value and value.type in _FUNCTION_TYPES):
                from actenon_scan.repository.semantic_frontends import literal_pattern_aliases
                literal_aliases = literal_pattern_aliases(name, value, data)
                for identifier in _pattern_names(name, data):
                    alias_name = literal_aliases.get(identifier) or (_text(value, data) if value and value.type in {"identifier", "this", "member_expression"} and re.fullmatch(r"[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*", _text(value,data)) and name.type == "identifier" else None)
                    unit.bind(scope, identifier, _Binding("alias" if alias_name else "unknown",
                              conditional=conditional, line=node.start_point[0] + 1, column=node.start_point[1] + 1,
                              alias_name=alias_name,
                              alias_scope=scope,
                              capture_sources=tuple(sorted({_text(c,data) for c in _walk(value)
                                if c.type in {'identifier','this','member_expression','subscript_expression'}}))
                                if value and not alias_name and value.type not in _FUNCTION_TYPES else ()))
        if node.type in {"short_var_declaration", "range_clause", "for_in_statement", "type_switch_statement"}:
            left = node.child_by_field_name("alias") if node.type == "type_switch_statement" else node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            names = _pattern_names(left, data)
            alias = right.named_children[0] if right and len(right.named_children) == 1 and right.named_children[0].type == "identifier" else None
            is_declaration = (node.type == "type_switch_statement" or node.type == "short_var_declaration" or
                any(c.type in {":=", "let", "const", "var"} for c in node.children))
            literal = bool(right and len(right.named_children) == 1 and right.named_children[0].type == "func_literal")
            for identifier in names if is_declaration and not literal else []:
                unit.bind(scope, identifier, _Binding("alias" if alias and len(names) == 1 else "unknown",
                          conditional=conditional, line=node.start_point[0] + 1, column=node.start_point[1] + 1,
                          alias_name=_text(alias, data) if alias else None, alias_scope=scope))
        if node.type in {"var_spec", "const_spec", "type_spec"}:
            for i, child in enumerate(node.children):
                if node.field_name_for_child(i) == "name":
                    value = node.child_by_field_name("value")
                    alias = value.named_children[0] if value and len(value.named_children) == 1 and value.named_children[0].type == "identifier" else None
                    if value and len(value.named_children) == 1 and value.named_children[0].type == "func_literal":
                        continue
                    unit.bind(scope, _text(child, data), _Binding("alias" if alias else "unknown",
                              conditional=conditional, line=node.start_point[0] + 1, column=node.start_point[1] + 1,
                              alias_name=_text(alias, data) if alias else None, alias_scope=scope))
        if node.type == "import_spec" and language == "go":
            name = _text(node.child_by_field_name("name"), data)
            if name:
                unit.bind(scope, "*" if name == "." else name)
        if node.type == "catch_clause":
            for identifier in _pattern_names(node.child_by_field_name("parameter"), data):
                unit.bind(scope, identifier, _Binding(conditional=conditional))
        if node.type == "import_statement":
            specifier = _text(node.child_by_field_name("source"), data).strip("\"'")
            for child in _walk(node):
                if child.type == "import_specifier":
                    imported = child.child_by_field_name("name")
                    local = child.child_by_field_name("alias") or imported
                    unit.bind(scope, _text(local, data), _Binding("ts_import", module=specifier,
                              member=_text(imported, data), conditional=conditional))
                elif child.type in {"import_clause", "namespace_import"}:
                    for identifier in child.named_children:
                        if identifier.type == "identifier":
                            unit.bind(scope, _text(identifier, data), _Binding("ts_import", module=specifier,
                                      member="default" if child.type == "import_clause" else None,
                                      conditional=conditional))
        for child in node.named_children:
            if child not in definition_children:
                visit(child, owner, class_name, conditional, class_identity, scope)

    visit(tree, module_sym)
    if language == "typescript":
        for node in tree.named_children:
            if node.type == "export_statement" and not any(c.type == "default" for c in node.children):
                declaration = node.child_by_field_name("declaration")
                if declaration:
                    name = declaration.child_by_field_name("name")
                    if name:
                        unit.exports.add(_text(name, data))
                    for child in declaration.named_children:
                        if child.type == "variable_declarator":
                            unit.exports.update(_pattern_names(child.child_by_field_name("name"), data))
    if enumerate_calls:
        _construct_execution_ownership(unit)
    return unit


def _construct_execution_ownership(unit):
    """Pass 2: attribute each invocation to its separately constructed body.

    Nested callable syntax is enumerated in its own execution region. It is
    never collected as outgoing syntax of the lexical enclosing callable.
    """
    from actenon_scan.repository.semantic_frontends import lower_semantics
    lower_semantics(unit, _Site)
    from actenon_scan.repository.lexical_environments import construct_environments
    construct_environments(unit)


def _registered_roots(unit, index, symbols, units):
    """Use existing registration vocabulary; extract handler arguments structurally."""
    from actenon_scan.repository.cross_language_reach import _TS_REGISTRATION_CALLEES, _GO_REGISTRATION_CALLEES
    vocabulary = _TS_REGISTRATION_CALLEES if unit.language == "typescript" else _GO_REGISTRATION_CALLEES
    data = unit.source.encode()
    by_position = {(n.start_byte, n.end_byte): key for key, n in unit.nodes.items()}
    for node in _walk(unit.tree):
        if node.type not in {"call_expression", "new_expression"}:
            continue
        func = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        callee = _text(func, data).rsplit(".", 1)[-1]
        if callee not in vocabulary:
            continue
        arguments = node.child_by_field_name("arguments")
        if not arguments or not arguments.named_children:
            continue
        handler = arguments.named_children[-1]
        if handler.type in {"object", "object_literal"}:
            handlers = []
            for prop in handler.named_children:
                key = prop.child_by_field_name("key")
                value = prop.child_by_field_name("value")
                if _text(key, data) in {"func", "execute", "handler"} and value:
                    handlers.append(value)
        else:
            handlers = [handler]
        for handler in handlers:
            key = by_position.get((handler.start_byte, handler.end_byte))
            if key:
                unit.discovered[key] = ("tool_registration:" + callee,)
                continue
            registration = next((s for s in unit.sites if s.line == node.start_point[0] + 1
                                 and s.column == node.start_point[1] + 1), None)
            if registration:
                reference = _Site(registration.owner, handler.start_point[0] + 1,
                                  handler.start_point[1] + 1, _text(handler, data), handler,
                                  lexical_scope=registration.lexical_scope, region=registration.region)
                certainty, targets, _ = _resolve(unit, reference, index, symbols, units)
                if certainty == ResolutionCertainty.RESOLVED:
                    (selected,) = targets
                    unit.discovered[selected.callable_key] = ("tool_registration:" + callee,)


def _lexical_bindings(unit, scope, name):
    seen = set()
    while scope and scope not in seen:
        seen.add(scope)
        bindings = unit.bindings.get(scope, {})
        if name in bindings or "*" in bindings:
            return scope, bindings.get(name, []) + bindings.get("*", [])
        environment = unit.environments.get(scope)
        scope = environment.lookup_parent if environment else unit.scope_parents.get(scope, "")
    return unit.module_key, unit.bindings.get(unit.module_key, {}).get(name, [])


def _apply_namespace_writes(units, indexes):
    """Complete pass 1 writes after all lexical declarations are available.

    Exact receiver/module aliases identify destinations. Unknown object writes
    conservatively destabilize matching local member namespaces (and Python
    modules, which are mutable objects), without guessing a receiver identity.
    """
    def namespaces(unit, scope, name, seen=frozenset()):
        coordinate = (unit.file, scope, name)
        if coordinate in seen or len(seen) >= 32:
            return []
        seen = seen | {coordinate}
        parts = name.split(".")
        _, bindings = _lexical_bindings(unit, scope, parts[0])
        destinations = []
        for binding in bindings:
            if binding.kind == "receiver" and len(parts) == 1:
                destinations.append((unit.file, _receiver_scope(unit, binding)))
            elif binding.kind == "alias" and binding.alias_name:
                destinations.extend(namespaces(unit, binding.alias_scope or scope,
                    ".".join([binding.alias_name] + parts[1:]), seen))
            elif binding.kind == "import" and unit.language == "python":
                module = indexes[unit.language]._resolve_module_dotted(
                    ".".join(x for x in [binding.module, binding.member, *parts[1:]] if x), binding.level, unit.file)
                destinations.extend((other.file, other.module_key) for other in units
                                    if other.language == "python" and other.module == module)
        return destinations

    invalidations = set()
    by_file = {u.file: u for u in units}
    receiver_namespaces = {
        (u.file, _receiver_scope(u, binding))
        for u in units if u.language in {"python", "typescript"}
        for names in u.bindings.values() for declarations in names.values()
        for binding in declarations if binding.kind == "receiver"
    }
    mutated_callables = set()
    for unit in units:
        for event in unit.write_events:
            if event.target_kind not in {TargetKind.MEMBER, TargetKind.NAMESPACE_MEMBER}:
                continue
            scope, receiver, member = event.scope, event.base, event.member
            # Mutating a callable object (including an imported/captured one)
            # is outside our body-identity model. Preserve its candidate while
            # opening stability. This is object identity, not a catalogue of
            # special member names such as __code__.
            parts = receiver.split(".")
            origin, declarations = _lexical_bindings(unit, scope, parts[0])
            language_units = [u for u in units if u.language == unit.language]
            symbols = [s for u in language_units for s in u.symbols]
            if re.fullmatch(r"[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*", receiver):
                for length in range(len(parts)):
                    possible = _binding_provenance(unit, origin, parts[0], declarations, parts[1:length+1],
                        indexes[unit.language], language_units, symbols)
                    mutated_callables.update(possible.targets)
                if declarations and declarations[0].kind == "receiver" and len(parts) > 1:
                    namespace = _receiver_scope(unit, declarations[0])
                    members = unit.bindings.get(namespace, {})
                    possible = _binding_provenance(unit, namespace, parts[1], members.get(parts[1], []), [],
                        indexes[unit.language], language_units, symbols)
                    mutated_callables.update(possible.targets)
            else:
                certificate = unit.certificates.get(scope)
                if certificate:
                    certificate.open(("lexical_writes_complete", "member_writes_complete"), "unresolved write base: " + receiver)
                    unit.semantic_gaps.add((unit.file, "unresolved write base: " + receiver))
            destinations = namespaces(unit, scope, receiver)
            if not destinations:
                certificate = unit.certificates.get(scope)
                if certificate:
                    certificate.open(("lexical_writes_complete", "member_writes_complete"),
                                     "unresolved namespace write destination")
                    unit.semantic_gaps.add((unit.file, "unresolved namespace write destination"))
                for other in units:
                    if other.language != unit.language:
                        continue
                    if unit.language == "python":
                        destinations.append((other.file, other.module_key))
                    receiver_scopes = {_receiver_scope(other, b) for names in other.bindings.values()
                                       for declarations in names.values() for b in declarations if b.kind == "receiver"}
                    destinations.extend((other.file, namespace) for namespace in receiver_scopes)
            invalidations.update((file, namespace, member) for file, namespace in destinations)
            for file, namespace in destinations:
                if (file, namespace) in receiver_namespaces:
                    # Knowing the lvalue's member is not a proof that a store
                    # leaves receiver dispatch stable. Setters and mutable
                    # lookup/identity can affect other members in these
                    # languages; this bounded frontend proves no such frame.
                    certificate = by_file[file].certificates.get(namespace)
                    if certificate:
                        reason = "receiver mutation lacks dispatch-stability proof"
                        certificate.open(("receiver_semantics_complete",), reason)
                        by_file[file].semantic_gaps.add((file, reason))
    for other in units:
        for scope, names in other.bindings.items():
            for name, declarations in names.items():
                if any(b.callable_key in mutated_callables for b in declarations):
                    invalidations.add((other.file, scope, name))
                    certificate = other.certificates.get(scope)
                    if certificate:
                        certificate.open(("lexical_writes_complete",), "callable object stability not modeled")
                        other.semantic_gaps.add((other.file, "callable object stability not modeled"))
    # Compute all destinations first: writes cannot change another write's lookup.
    for file, scope, name in sorted(invalidations):
        by_file[file].bind(scope, name, _Binding("write", counter_evidence=frozenset({E.REASSIGNMENT_WRITE})))


def _apply_lexical_writes(units):
    """Consume normalized stores against lexical destinations, never raw AST."""
    invalidations = set()
    by_file = {u.file: u for u in units}
    for unit in units:
        for event in unit.write_events:
            if event.target_kind == TargetKind.UNKNOWN_TARGET:
                # Open syntax is not an empty write set. Its certificate was
                # opened during lowering and will be required by provenance.
                continue
            if event.target_kind != TargetKind.LEXICAL_BINDING or event.operation == WriteOperation.DECLARE:
                continue
            destination, declarations = _lexical_bindings(unit, event.scope, event.binding)
            # Python assignment introduces a function-local name unless a
            # global/nonlocal directive says otherwise (already collected).
            # An exact initializer is the initial store, not a later write.
            initial = (unit.language == "python" and
                event.operation == WriteOperation.ASSIGN and len(declarations) == 1 and
                declarations[0].line == event.line and declarations[0].kind not in {"receiver", "write"})
            if initial:
                continue
            if declarations:
                invalidations.add((unit.file, destination, event.binding))
                # Existing conservative block summaries can describe several
                # lexical destinations; a store must account for each one.
                while declarations and all(b.conditional for b in declarations):
                    parent = unit.scope_parents.get(destination, "")
                    if not parent:
                        break
                    destination, declarations = _lexical_bindings(unit, parent, event.binding)
                    if declarations:
                        invalidations.add((unit.file, destination, event.binding))
    for file, scope, name in sorted(invalidations):
        by_file[file].bind(scope, name, _Binding("write", counter_evidence=frozenset({E.REASSIGNMENT_WRITE})))


def _receiver_scope(unit, binding):
    return unit.class_scopes.get(binding.receiver_class, binding.receiver_class)


def _apply_escape_events(units, indexes):
    """Normalize identities, then apply the kernel's non-mutation frame rule.

    No unknown argument is guessed to be a particular receiver. Only identities
    used by supported local dispatch/import/callable binding enter this ledger.
    Unknown aliases to those identities retain every possible destination.
    """
    by_file = {u.file:u for u in units}
    symbols = [s for u in units for s in u.symbols]
    remaining = [0]
    memo = {}
    def destinations(unit, scope, spelling, seen=frozenset()):
        remaining[0] -= 1
        coordinate = (unit.file,scope,spelling)
        if coordinate in memo:return set(memo[coordinate])
        if coordinate in seen or len(seen)>=32 or remaining[0]<0:
            unit.semantic_gaps.add((unit.file,'escape identity resolution bound reached'))
            return {(other.file,namespace) for other in units if other.language==unit.language
                for namespace in other.certificates}
        seen = seen | {coordinate}
        if spelling.startswith('@callable:'):
            return callable_captures(unit,spelling.removeprefix('@callable:'),seen)
        parts = spelling.split('.')
        origin, declarations = _lexical_bindings(unit,scope,parts[0])
        found = set()
        for b in declarations:
            if b.kind in {'receiver','class_object'}:found.add((unit.file,_receiver_scope(unit,b)))
            elif b.capture_sources:
                for source in b.capture_sources:
                    # Subscript bases are included as possible identities;
                    # inability to prove a key cannot hide a namespace escape.
                    found.update(destinations(unit,b.alias_scope or origin,source,seen))
            elif b.kind == 'alias' and b.alias_name:
                found.update(destinations(unit,b.alias_scope or origin,'.'.join([b.alias_name]+parts[1:]),seen))
            elif b.kind == 'import' and unit.language=='python':
                module = indexes['python']._resolve_module_dotted(
                    '.'.join(x for x in [b.module,b.member,*parts[1:]] if x),b.level,unit.file)
                found.update((u.file,u.module_key) for u in units if u.language=='python' and u.module==module)
                # A captured from-import callable is also a mutable object.
                if not found and b.member:
                    candidates = _binding_provenance(unit,origin,parts[0],[b],parts[1:],indexes['python'],
                        [u for u in units if u.language=='python'],[s for s in symbols if s.language=='python'])
                    for key in candidates.targets:
                        for other in units:
                            found.update((other.file,ns) for ns,names in other.bindings.items()
                                if any(d.callable_key==key for ds in names.values() for d in ds))
            elif b.kind in {'callable','self_callable','coroutine_callable'}:
                if unit.language=='python':found.add((unit.file,origin))
                found.update(callable_captures(unit,b.callable_key,seen))
            elif b.kind=='ts_import':
                relative=posixpath.normpath(posixpath.join(posixpath.dirname(unit.file),b.module))
                if Path(relative).suffix in TS_SUFFIXES:relative=str(Path(relative).with_suffix(''))
                imported_units=[u for u in units if u.language=='typescript'
                    and str(Path(u.file).with_suffix(''))==relative]
                if b.member:
                    provenance=_binding_provenance(unit,origin,parts[0],[b],[],indexes['typescript'],
                        [u for u in units if u.language=='typescript'],[s for s in symbols if s.language=='typescript'])
                    if len(provenance.targets)==1 and not provenance.counter:
                        for symbol in provenance.targets.values():
                            found.update(callable_captures(by_file[symbol.file],symbol.key,seen))
                        continue
                found.update((u.file,u.module_key) for u in imported_units)
        if remaining[0]>=0:memo[coordinate]=frozenset(found)
        return found

    def callable_captures(unit, key, seen):
        node=unit.nodes.get(key)
        if node is None:return set()
        nodes=ast.walk(node) if unit.language=='python' else _walk(node)
        found=set()
        for child in nodes:
            if unit.node_scopes.get(child)!=key:continue
            if (isinstance(child,ast.Name) if unit.language=='python' else child.type in {'identifier','this'}):
                spelling=child.id if unit.language=='python' else _text(child,unit.source.encode())
                # Function objects in JS/Go cannot have their executable body
                # replaced through own properties. Their captured mutable
                # receiver/namespace can still escape through the callable.
                origin,declarations=_lexical_bindings(unit,key,spelling)
                if any(b.kind in {'receiver','class_object','import','ts_import','alias','capture_alias'} or b.capture_sources for b in declarations):
                    found.update(destinations(unit,key,spelling,seen))
        return found

    def intrinsic_origin(unit, scope, spelling, seen=frozenset()):
        coordinate = (scope,spelling)
        if coordinate in seen or len(seen)>=32 or remaining[0]<0:return ''
        parts=spelling.split('.')
        origin, bindings=_lexical_bindings(unit,scope,parts[0])
        if not bindings:
            return spelling if kernel.intrinsic_capabilities(unit.language,spelling) else ''
        if len(bindings)!=1:return ''
        binding=bindings[0]
        if binding.kind!='alias' or binding.conditional or binding.counter_evidence:return ''
        return intrinsic_origin(unit,binding.alias_scope or origin,
            '.'.join([binding.alias_name]+parts[1:]),seen|{coordinate})

    def invoked_captures(unit, scope, spelling, seen=frozenset()):
        """Invoking a value exposes its captures, not the value as an argument.

        A bare function/constructor call does not pass its declaration namespace
        to itself. A captured member or closure can nevertheless carry a mutable
        receiver. Keep this distinct from the explicit argument escape ledger.
        """
        coordinate=(unit.file,scope,spelling)
        if coordinate in seen or len(seen)>=32:
            return destinations(unit,scope,spelling)
        seen=seen|{coordinate}
        origin,bindings=_lexical_bindings(unit,scope,spelling)
        found=set()
        for binding in bindings:
            if binding.capture_sources:
                for source in binding.capture_sources:
                    found.update(destinations(unit,binding.alias_scope or origin,source))
            elif binding.kind=='alias' and binding.alias_name:
                name=binding.alias_name
                if '.' in name:
                    found.update(destinations(unit,binding.alias_scope or origin,name))
                else:
                    found.update(invoked_captures(unit,binding.alias_scope or origin,name,seen))
            elif binding.kind in {'callable','self_callable','coroutine_callable'}:
                found.update(callable_captures(unit,binding.callable_key,frozenset()))
            elif binding.kind=='receiver':
                found.add((unit.file,_receiver_scope(unit,binding)))
        return found

    def frame(unit,site):
        parts=site.spelling.split('.')
        scope, bindings=_lexical_bindings(unit,site.lexical_scope,parts[0])
        try:
            if len(parts)==2 and len(bindings)==1 and bindings[0].kind=='receiver':
                scope=_receiver_scope(unit,bindings[0]);bindings=unit.bindings.get(scope,{}).get(parts[1],[])
                tail=[];name=parts[1]
            else:tail=parts[1:];name=parts[0]
            p=_binding_provenance(unit,scope,name,bindings,tail,indexes[unit.language],
                [u for u in units if u.language==unit.language],[s for s in symbols if s.language==unit.language],
                resumes_coroutine=site.resumes_coroutine)
        except Exception:
            return kernel.CalleeFrame.EXTERNAL_OR_UNKNOWN,False
        if p.counter or len(p.targets)!=1:
            return kernel.CalleeFrame.AMBIGUOUS if p.targets else kernel.CalleeFrame.EXTERNAL_OR_UNKNOWN,False
        symbol=next(iter(p.targets.values()));other=by_file[symbol.file];node=other.nodes[symbol.key]
        body=node.body if other.language=='python' else node.child_by_field_name('body')
        statements=(body if isinstance(body,list) else [body]) if other.language=='python' else (body.named_children if body else [node])
        kinds=[]
        for statement in statements:
            if other.language=='python':
                kinds.append('PASS' if isinstance(statement,ast.Pass) else 'RETURN_CONSTANT' if
                    isinstance(statement,ast.Return) and (statement.value is None or isinstance(statement.value,ast.Constant)) else 'UNKNOWN')
            else:kinds.append('UNKNOWN')
        return kernel.CalleeFrame.LOCAL_PROVEN,kernel.non_mutating_frame(kinds,exact=True)

    for unit in units:
        for site in unit.sites:
            remaining[0] = 512
            kind,safe=frame(unit,site)
            intrinsic=intrinsic_origin(unit,site.lexical_scope,site.spelling)
            operands={operand:destinations(unit,site.lexical_scope,operand) for operand in site.arguments}
            # Unknown bound member calls also expose their captured receiver.
            # Proven local bodies have their own globally collected writes and
            # explicit captures; an unexplained bound call has no such frame.
            if kind!=kernel.CalleeFrame.LOCAL_PROVEN:
                from actenon_scan.repository.semantic_frontends import callable_operands
                for operand in callable_operands(unit,site.node):
                    captured=(invoked_captures(unit,site.lexical_scope,operand)
                        if operand==site.spelling else destinations(unit,site.lexical_scope,operand))
                    operands.setdefault(operand,set()).update(captured)
            for operand in sorted(operands):
                target=tuple(sorted(operands[operand]))
                if not target:continue
                event=kernel.EscapeEvent(operand,unit.file,site.lexical_scope,
                    stable_id('escape',unit.file,site.line,site.column,operand),site.line,kind,
                    kernel.MutationGuarantee.NON_MUTATING_PROVEN if safe else kernel.MutationGuarantee.MUTATION_POSSIBLE,
                    target,(unit.file+':'+str(site.line)+':'+str(site.column),'normalized-call-operands'),
                    intrinsic,kernel.intrinsic_capabilities(unit.language,intrinsic))
                unit.escape_events.append(event)
                if not kernel.escape_opens_closure(event):continue
                for file,namespace in target:
                    other=by_file[file];certificate=other.certificates.get(namespace)
                    if certificate:
                        reason='mutable identity escaped without non-mutation frame: '+operand
                        env=other.environments.get(namespace)
                        certificate.open(kernel.escape_facets(other.language,env.construct_kind if env else 'UNKNOWN'),reason)
                        other.semantic_gaps.add((file,reason))


def _propagate_open_certificates(units):
    """An unmodeled store cannot disappear at a lexical/namespace boundary."""
    for unit in units:
        for scope, certificate in list(unit.certificates.items()):
            open_facets = [f for f in ("lexical_writes_complete", "member_writes_complete",
                          "import_semantics_complete", "receiver_semantics_complete")
                          if certificate.state(f) != S.SUPPORTED]
            if not open_facets:
                continue
            parent = unit.scope_parents.get(scope, "")
            seen = set()
            while parent and parent not in seen:
                seen.add(parent)
                if parent in unit.certificates:
                    unit.certificates[parent].open(open_facets, "open nested semantic scope: " + scope)
                parent = unit.scope_parents.get(parent, "")
            if "member_writes_complete" in open_facets:
                # A namespace alias not modeled by the frontend may refer to
                # another workspace module or receiver. Do not claim closure
                # from the failure to identify its destination.
                for other in units:
                    if other.language != unit.language:
                        continue
                    for target in other.certificates.values():
                        target.open(("member_writes_complete",), "open workspace namespace mutation: " + unit.file)
            if "receiver_semantics_complete" in open_facets:
                # Workspace inheritance/custom lookup can introduce competing
                # receiver implementations. This model proves no hierarchy or
                # dynamic descriptor identity, so it declines receiver closure.
                for other in units:
                    if other.language == unit.language:
                        for target in other.certificates.values():
                            target.open(("receiver_semantics_complete",), "open workspace receiver dispatch: " + unit.file)


@dataclass
class _Provenance:
    """Accumulate facts across every possible binding path; never overwrite."""
    targets: dict[str, CallableSymbol] = field(default_factory=dict)
    positive: dict[str, set[E]] = field(default_factory=dict)
    counter: set[E] = field(default_factory=set)
    steps: set = field(default_factory=set)
    closure: list[S] = field(default_factory=list)
    certificates: set[str] = field(default_factory=set)
    import_closure: list[S] = field(default_factory=list)
    receiver_closure: list[S] = field(default_factory=list)

    def certificate(self, unit, scope, *, member=False, imported=False):
        certificate = unit.certificates.get(scope)
        self.certificates.add(unit.file + ":" + scope)
        self.steps.add(kernel.ResolutionStep(kernel.ResolutionStepKind.LEXICAL_LOOKUP,
            scope, unit.file + ':' + scope))
        self.closure.append(certificate.state("lexical_writes_complete") if certificate else S.UNKNOWN)
        if member:
            self.closure.append(certificate.state("member_writes_complete") if certificate else S.UNKNOWN)
        if imported:
            self.steps.add(kernel.ResolutionStep(kernel.ResolutionStepKind.IMPORT_HOP,
                scope, unit.file + ':' + scope))
            self.import_closure.append(certificate.state("import_semantics_complete") if certificate else S.UNKNOWN)

    def add(self, symbol, evidence):
        self.targets[symbol.key] = symbol
        self.positive.setdefault(symbol.key, set()).update(evidence)
        self.steps.add(kernel.ResolutionStep(kernel.ResolutionStepKind.CALLABLE_SELF_BINDING
            if E.CALLABLE_SELF_BINDING in evidence else kernel.ResolutionStepKind.DECLARATION,
            symbol.key, symbol.file + ':' + str(symbol.line)))

    def merge(self, other, evidence=()):
        self.counter.update(other.counter)
        self.steps.update(other.steps)
        self.closure.extend(other.closure)
        self.import_closure.extend(other.import_closure)
        self.receiver_closure.extend(other.receiver_closure)
        self.certificates.update(other.certificates)
        for key, symbol in other.targets.items():
            self.add(symbol, other.positive[key] | set(evidence))


def _python_namespace_provenance(module, tail, index, units, symbols, seen,
                                 resumes_coroutine, implicit_import=""):
    """Read one namespace member at a time, accumulating every prefix's facts.

    A module file is not evidence that a package attribute is bound. Only an
    explicit import can supply an implicit submodule declaration. Completed
    lexical declarations and writes still counter that original provenance.
    """
    result = _Provenance()
    owners = [u for u in units if u.language == "python" and u.module == module]
    if len(owners) != 1 or not tail:
        result.counter.add(E.UNRESOLVED_IMPORT)
    for other in owners:
        if not tail:
            continue
        member = tail[0]
        namespace = other.bindings.get(other.module_key, {})
        declarations = namespace.get(member, []) + namespace.get("*", [])
        submodule = ".".join(x for x in (module, member) if x)
        if (len(tail) > 1 and (implicit_import == submodule or implicit_import.startswith(submodule + "."))
                and not any(b.kind != "write" for b in declarations)):
            # Preserve the loaded module candidate even if this attribute has
            # possible later writes. The writes feed the same BindingClaim.
            declarations = [_Binding("import", module=submodule,
                                     qualified_import=implicit_import)] + declarations
        child = _binding_provenance(other, other.module_key, member, declarations, tail[1:],
                                    index, units, symbols, seen, resumes_coroutine, implicit_import)
        result.merge(child, {E.IMPORT_PROVENANCE})
    return result


def _binding_provenance(unit, scope, name, bindings, tail, index, units, symbols,
                        seen=frozenset(), resumes_coroutine=False, implicit_import=""):
    """Pass 3: bounded, set-valued lexical evidence, independent of sink rules."""
    coordinate = (unit.file, scope, name, tuple(tail), implicit_import)
    result = _Provenance()
    # Python function objects have mutable body/descriptor identity. Unknown
    # object writes therefore also defeat their local body-stability proof.
    result.certificate(unit, scope, member=unit.language == "python")
    if coordinate in seen:
        result.counter.add(E.UNRESOLVED_ALIAS)
        return result
    if len(seen) >= 32:
        raise RuntimeError("max_lexical_binding_depth reached (32)")
    seen = seen | {coordinate}
    if len(bindings) > 1 and any(b.kind in {"unknown", "write", "alias"} for b in bindings):
        result.counter.add(E.REASSIGNMENT_WRITE)
    if len(bindings) != 1:
        result.counter.add(E.AMBIGUOUS_DECLARATION if bindings else E.NO_BINDING_PROOF)
    for binding in bindings:
        result.counter.update(binding.counter_evidence)
        if binding.conditional:
            result.counter.add(E.CONDITIONAL_IMPORT if binding.kind in {"import", "ts_import"} else E.CONDITIONAL_DECLARATION)
        if binding.kind in {"callable", "self_callable", "coroutine_callable"} and not tail:
            found = [s for s in symbols if s.key == binding.callable_key]
            for symbol in found:
                result.add(symbol, {E.CALLABLE_SELF_BINDING if binding.kind == "self_callable" else E.LEXICAL_DECLARATION})
            if len(found) != 1:
                result.counter.add(E.AMBIGUOUS_DECLARATION)
            if binding.kind == "coroutine_callable" and not resumes_coroutine:
                result.counter.add(E.DEFERRED_EXECUTION)
        elif binding.kind == "alias" and binding.alias_name:
            result.steps.add(kernel.ResolutionStep(kernel.ResolutionStepKind.ALIAS_HOP,
                unit.file + ':' + scope + ':' + name, unit.file + ':' + str(binding.line)))
            origin, declarations = _lexical_bindings(unit, binding.alias_scope or scope, binding.alias_name)
            # Alias initializer execution must itself have a stable target.
            if any((b.line, b.column) > (binding.line, binding.column) for b in declarations):
                result.counter.add(E.INITIALIZATION_NOT_ESTABLISHED)
            child = _binding_provenance(unit, origin, binding.alias_name, declarations, tail,
                                        index, units, symbols, seen, resumes_coroutine, implicit_import)
            result.merge(child, {E.STRUCTURALLY_EXACT_ALIAS})
            if not child.targets:
                result.counter.add(E.UNRESOLVED_ALIAS)
        elif binding.kind in {"import", "ts_import"}:
            result.certificate(unit, scope, member=True, imported=True)
            modules, member = [], binding.member
            if unit.language == "python":
                module = index._resolve_module_dotted(binding.module, binding.level, unit.file)
                loaded = binding.qualified_import or implicit_import
                members = ([member] if member is not None else []) + tail
                if member is not None and tail and module is not None:
                    submodule = ".".join(x for x in (module, member) if x)
                    if scope == unit.module_key and module == unit.module and name == member:
                        # A package's `from . import child` loads child before
                        # binding its own name. Do not recurse into itself or
                        # skip counter-facts already gathered for that binding.
                        module, members = submodule, tail
                    elif not (loaded == submodule or loaded.startswith(submodule + ".")):
                        loaded = submodule  # explicit `from package import child`
                child = _python_namespace_provenance(module, members, index, units, symbols,
                                                      seen, resumes_coroutine, loaded)
                result.merge(child, {E.IMPORT_PROVENANCE})
                continue
            elif binding.kind == "ts_import" and binding.module.startswith(("./", "../")):
                relative = posixpath.normpath(posixpath.join(posixpath.dirname(unit.file), binding.module))
                if Path(relative).suffix in TS_SUFFIXES:
                    relative = str(Path(relative).with_suffix(""))
                modules = [u for u in units if str(Path(u.file).with_suffix("")) == relative]
                if member is None and len(tail) == 1:
                    member = tail[0]
                elif tail:
                    modules = []
            if len(modules) != 1 or member in {None, "*", "default"}:
                result.counter.add(E.UNRESOLVED_IMPORT)
            for other in modules:
                if unit.language == "typescript" and member not in other.exports:
                    result.counter.add(E.UNRESOLVED_IMPORT)
                declarations = other.bindings.get(other.module_key, {}).get(member, []) + other.bindings.get(other.module_key, {}).get("*", [])
                child = _binding_provenance(other, other.module_key, member, declarations, [],
                                            index, units, symbols, seen, resumes_coroutine)
                result.merge(child, {E.IMPORT_PROVENANCE})
        else:
            result.counter.add(E.REASSIGNMENT_WRITE if binding.kind == "write" else E.NO_BINDING_PROOF)
    if len(result.targets) > 1:
        result.counter.add(E.AMBIGUOUS_DECLARATION)
    return result


def _resolve_binding_claims(unit, site, identity, index, symbols, units):
    # This pass consumes lowered sites/declarations/certificates only. Parser
    # diagnostics are executed separately, never used as binding authority.
    simple = bool(re.fullmatch(r"[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*", site.spelling))
    parts = site.spelling.split(".")
    head, name = parts[0], parts[-1]
    lexical_scope = site.lexical_scope or site.owner.key
    scope, bindings = _lexical_bindings(unit, lexical_scope, head)
    result = _Provenance()
    result.certificate(unit, lexical_scope)
    if simple and len(parts) == 2 and len(bindings) == 1 and bindings[0].kind == "receiver":
        receiver = bindings[0]
        class_scope = _receiver_scope(unit, receiver)
        members = unit.bindings.get(class_scope, {})
        declarations = members.get(name, []) + members.get("*", [])
        result = _binding_provenance(unit, class_scope, name, declarations, [], index, units, symbols,
                                     resumes_coroutine=site.resumes_coroutine)
        result.certificate(unit, lexical_scope, member=True)
        result.certificate(unit, class_scope, member=True)
        result.steps.add(kernel.ResolutionStep(kernel.ResolutionStepKind.RECEIVER_DISPATCH,
            class_scope, unit.file + ':' + lexical_scope))
        receiver_certificate = unit.certificates.get(lexical_scope)
        result.receiver_closure.append(receiver_certificate.state("receiver_semantics_complete") if receiver_certificate else S.UNKNOWN)
        class_certificate = unit.certificates.get(class_scope)
        result.receiver_closure.append(class_certificate.state("receiver_semantics_complete") if class_certificate else S.UNKNOWN)
        for evidence in result.positive.values():
            evidence.add(E.RECEIVER_IDENTITY)
        if receiver.conditional:
            result.counter.add(E.UNESTABLISHED_RECEIVER)
        # Known static members are incompatible with an instance receiver.
        if not declarations and unit.language == "typescript":
            static_scope = stable_id("static-scope", class_scope)
            incompatible = unit.bindings.get(static_scope, {}).get(name, [])
            excluded = _binding_provenance(unit, static_scope, name, incompatible, [], index, units, symbols)
            result.merge(excluded)
            if incompatible:
                result.counter.add(E.INCOMPATIBLE_RECEIVER)
    elif simple and unit.language == "go" and len(parts) == 1 and scope == unit.module_key:
        result.steps.add(kernel.ResolutionStep(kernel.ResolutionStepKind.PACKAGE_LOOKUP,
            unit.package_name, unit.file))
        package_units = [u for u in units if Path(u.file).parent == Path(unit.file).parent
                         and u.package_name == unit.package_name]
        active = [(u, u.bindings.get(u.module_key, {}).get(head, [])) for u in package_units]
        active = [(u, b) for u, b in active if b]
        if len(active) != 1:
            result.counter.add(E.AMBIGUOUS_DECLARATION if active else E.NO_BINDING_PROOF)
        for other, declarations in active:
            result.merge(_binding_provenance(other, other.module_key, head, declarations, [], index, units, symbols))
    elif simple and bindings:
        result = _binding_provenance(unit, scope, head, bindings, parts[1:], index, units, symbols,
                                     resumes_coroutine=site.resumes_coroutine)
        if scope != unit.module_key and any((b.line, b.column) > (site.line, site.column) for b in bindings):
            result.counter.add(E.INITIALIZATION_NOT_ESTABLISHED)
    else:
        result.counter.add(E.NO_BINDING_PROOF)
    if simple and not bindings and not result.targets:
        for symbol in symbols:
            if symbol.symbol.rsplit(".", 1)[-1] == name:
                result.add(symbol, ())
        result.counter.add(E.NO_BINDING_PROOF)
    excluded = _Provenance()
    if simple and len(parts) == 1 and bindings and not result.targets and scope != unit.module_key:
        parent = unit.scope_parents.get(scope, unit.module_key)
        outer_scope, outer = _lexical_bindings(unit, parent, head)
        excluded = _binding_provenance(unit, outer_scope, head, outer, [], index, units, symbols)
        if excluded.targets:
            result.counter.add(E.LEXICAL_SHADOW)
    targets = [ImplementationTarget.local(s) for s in result.targets.values()]
    # The executing scope's closure is needed even when lookup finds an outer
    # binding: reflection or an unmodeled store in this scope can affect it.
    result.certificate(unit, lexical_scope)
    result.certificate(unit, scope)
    region = site.region
    from actenon_scan.repository.lexical_environments import compiler_reference
    lexical_state, lexical_provenance = compiler_reference(unit, site, head, scope)
    # The kernel, not the target resolver, derives semantic states and witnesses.
    def proof_for(target, evidence, counter):
        declaration = next((d for d in unit.proof_inventory.declarations if d.callable_key==target.callable_key), None)
        context = kernel.ResolutionContext(identity, target.candidate_id, unit.language, unit.file,
            site.spelling, lexical_scope, region.region_id if region else '',
            site.owner.key, target.file, target.callable_key,
            tuple(sorted(result.steps, key=lambda s:(s.kind.value,s.identity,s.provenance))),
            frozenset(e.value for e in evidence), declaration.namespace if declaration else '',
            declaration.kind if declaration else 'UNKNOWN',site.line,site.column,site.ordinal)
        classification = ('BOUNDED_LEXICAL' if unit.language != 'python' else
            next((p.rsplit(':',1)[-1] for p in lexical_provenance if p.startswith('compiler-reference:')), 'UNKNOWN'))
        observation = kernel.LookupObservation(lexical_scope, scope,
            classification if lexical_state == S.SUPPORTED else 'UNKNOWN', lexical_provenance)
        return kernel.evaluate(context=context, inventory=unit.proof_inventory, lookup=observation,
            candidates=[t.candidate_id for t in targets], counter_evidence=counter)
    claims = []
    for target in targets:
        evidence = frozenset(result.positive[target.callable_key])
        proof = proof_for(target, evidence, result.counter)
        counter = set(result.counter)
        if not proof.authorizes(identity,target.candidate_id,evidence):
            counter.add(E.SEMANTIC_CLOSURE_UNKNOWN)
        claims.append(BindingClaim(identity,target.candidate_id,evidence,frozenset(counter),True,proof))
    for symbol in excluded.targets.values():
        target = ImplementationTarget.local(symbol)
        targets.append(target)
        claims.append(BindingClaim(identity, target.candidate_id, frozenset(excluded.positive[symbol.key]),
                                   frozenset(excluded.counter | {E.LEXICAL_SHADOW}), True))
    exact = [b for b in claims if b.state == BindingState.ESTABLISHED]
    if len(exact) == len(claims) == 1:
        return ResolutionCertainty.RESOLVED, tuple(targets), False, tuple(claims)
    if len(exact) > 0:
        # Unique authority is a global constraint, not a candidate ordering rule.
        claims = [b.with_evidence(counter={E.AMBIGUOUS_DECLARATION}) for b in claims]
    dynamic = site.dynamic or bool(bindings) or bool(targets)
    opaque = ImplementationTarget(stable_id("candidate", site.owner.key, site.line, site.column, "unknown"),
                                  opaque=not dynamic, dynamic=dynamic)
    targets.append(opaque)
    claims.append(BindingClaim(identity, opaque.candidate_id, counter_evidence=frozenset(result.counter)))
    certainty = ResolutionCertainty.HEURISTIC if result.targets else ResolutionCertainty.UNRESOLVED
    return certainty, tuple(sorted(targets, key=lambda t: t.candidate_id)), None, tuple(sorted(claims, key=lambda b: b.candidate_id))


def _resolve(unit, site, index, symbols, units):
    """Compatibility projection for existing registration vocabulary only."""
    certainty, targets, leaves, claims = _resolve_binding_claims(unit, site, "registration", index, symbols, units)
    # Root selection identifies the source callable registered as a capability;
    # it grants no traversal authority. A captured receiver's unknown stability
    # remains a frontier in the actual call graph. Never discard lexical
    # shadow/write/decorator ambiguity to select a registration candidate.
    local = [t for t in targets if t.callable_key]
    if len(local) == 1:
        binding = next((b for b in claims if b.candidate_id == local[0].candidate_id), None)
        if binding and binding.positive_evidence and binding.counter_evidence <= {E.SEMANTIC_CLOSURE_UNKNOWN}:
            return ResolutionCertainty.RESOLVED, tuple(local), leaves
    return certainty, targets, leaves


def build_invocation_graph(target: Path, *, entrypoints: tuple[Entrypoint, ...],
                           discover_roots: bool, reachability_cfg: dict, limits: GraphLimits,
                           include_globs=None, exclude_globs=None, matched_rule_ids=None):
    graph = InvocationGraph(roots_supplied=len(entrypoints))
    root_dir = target if target.is_dir() else target.parent
    if not target.exists():
        graph.analysis_errors.append((str(target), "scan target does not exist"))
        return graph
    indexes = {"python": RepositoryIndex(root_dir)}
    units = []
    bytes_read = 0
    files = _collect_sources(target, entrypoints, include_globs, exclude_globs)
    # Pass 1: construct completed lexical scopes, declarations and writes.
    for i, path in enumerate(files):
        file = path.relative_to(root_dir).as_posix()
        if not path.resolve().is_relative_to(root_dir.resolve()):
            graph.coverage_gaps.append((file, "source path leaves workspace"))
            continue
        if i >= limits.max_files:
            graph.coverage_gaps.append((file, "max_files reached"))
            break
        language = "python" if path.suffix == ".py" else (
            "typescript" if path.suffix in TS_SUFFIXES else "go" if path.suffix == ".go" else None)
        if not language:
            graph.unsupported_files.append((file, _UNSUPPORTED_SUFFIXES.get(path.suffix, (path.suffix,))[0]))
            continue
        try:
            size = path.stat().st_size
            if bytes_read + size > limits.max_bytes:
                graph.coverage_gaps.append((file, "max_bytes reached"))
                continue
            source = path.read_text(encoding="utf-8-sig")
            bytes_read += size
            if language == "python":
                tree = ast.parse(source, filename=file)
                indexes[language].add_file(file, source, tree)
                unit = _python_unit(file, source, tree, indexes[language], reachability_cfg, enumerate_calls=False)
            else:
                if language == "typescript":
                    from actenon_scan.repository.ts_symbol_index import TSRepositoryIndex, _parser_for
                    indexes.setdefault(language, TSRepositoryIndex(root_dir))
                    parser = _parser_for(file)
                else:
                    from tree_sitter import Parser
                    from actenon_scan.repository.go_symbol_index import GoRepositoryIndex, _ensure_language
                    indexes.setdefault(language, GoRepositoryIndex(root_dir))
                    parser = Parser(_ensure_language())
                tree = parser.parse(source.encode()).root_node
                if tree.has_error:
                    raise SyntaxError("parser reported ERROR or missing syntax")
                indexes[language].add_file(file, source)
                if file not in indexes[language].files:
                    raise RuntimeError("repository index did not retain parsed file")
                unit = _tree_unit(language, file, source, tree, indexes[language], enumerate_calls=False)
            units.append(unit)
        except ImportError:
            graph.unsupported_files.append((file, language))
        except Exception as exc:
            graph.analysis_errors.append((file, f"{type(exc).__name__}: {exc}"))
    failed_indexes = set()
    for language, index in indexes.items():
        try:
            index.finalize()
        except Exception as exc:
            failed_indexes.add(language)
            graph.analysis_errors.append((language, f"index finalization: {exc}"))
    units = [u for u in units if u.language not in failed_indexes]
    # Pass 2 is independent of binding resolution and repository-name lookup.
    owned_units = []
    for unit in units:
        try:
            _construct_execution_ownership(unit)
            owned_units.append(unit)
        except Exception as exc:
            graph.analysis_errors.append((unit.file, f"execution ownership: {exc}"))
    units = owned_units
    if graph.analysis_errors or any(reason.startswith(("max_files", "max_bytes", "source path"))
                                    for _, reason in graph.coverage_gaps):
        # A truncated/failed inventory is not a complete search for workspace
        # writes. Keep known sites/candidates, but decline closure authority.
        for unit in units:
            for certificate in unit.certificates.values():
                certificate.open(("lexical_writes_complete", "member_writes_complete",
                                  "import_semantics_complete"), "workspace source inventory incomplete")
            unit.semantic_gaps.add((unit.file, "workspace source inventory incomplete"))
    try:
        _apply_lexical_writes(units)
        _apply_namespace_writes(units, indexes)
        _apply_escape_events(units, indexes)
        _propagate_open_certificates(units)
    except Exception as exc:
        graph.analysis_errors.append(("semantic construction", f"write closure: {type(exc).__name__}: {exc}"))
        units = []
    # Snapshot the completed common IR once. Missing inventories never seal.
    from actenon_scan.repository.semantic_frontends import classify_node
    import hashlib
    import json
    audits = []
    for observed in units:
        nodes = list(ast.walk(observed.tree) if observed.language == 'python' else _walk(observed.tree))
        for key, env in observed.environments.items():
            certificate = observed.certificates.get(key)
            grammar = tuple(sorted({(type(n).__name__ if observed.language == 'python' else n.type,
                classify_node(observed.language,type(n).__name__ if observed.language == 'python' else n.type))
                for n in nodes if observed.node_scopes.get(n,observed.node_regions.get(n).lexical_scope
                    if observed.node_regions.get(n) else observed.module_key) == key}))
            if not grammar:
                anchor = observed.scope_nodes.get(key,observed.tree)
                name = type(anchor).__name__ if observed.language == 'python' else anchor.type
                grammar = ((name,classify_node(observed.language,name)),)
            audits.append(kernel.ScopeAudit(env, tuple(sorted(certificate.facets.items())) if certificate else (),
                tuple(sorted(certificate.limitations)) if certificate else ('missing audit',),
                tuple(e for e in observed.write_events if e.scope==key),
                hashlib.sha256(observed.source.encode()).hexdigest(), observed.grammar_digest, grammar))
    declarations = {}
    for observed in units:
        for namespace,names in observed.bindings.items():
            for declared_name,entries in names.items():
                for binding in entries:
                    if not binding.callable_key or binding.kind not in {'callable','coroutine_callable','self_callable'}:continue
                    kind = ('STATIC_METHOD' if namespace.startswith('static-scope-') else
                        'INSTANCE_METHOD' if namespace in observed.class_scopes.values() or observed.scope_constructs.get(namespace)=='class'
                        else 'SELF' if binding.kind=='self_callable' else 'FUNCTION')
                    # A named function expression has both a receiving variable
                    # and an inner self-binding. Its original declaration is
                    # canonical; inner lookup remains a separate path step.
                    if kind=='SELF' and binding.callable_key in declarations:continue
                    declarations[binding.callable_key] = kernel.CallableDeclaration(binding.callable_key,
                        namespace,observed.file,kind,declared_name,binding.line,(observed.file+':'+str(binding.line),))
    binding_observations=[]
    for observed in units:
        for namespace,names in observed.bindings.items():
            for name,entries in names.items():
                for binding in entries:
                    imported=[]
                    if binding.kind=='import':
                        module=indexes['python']._resolve_module_dotted(binding.module,binding.level,observed.file)
                        imported=[u.module_key for u in units if u.language=='python' and u.module==module]
                    elif binding.kind=='ts_import' and binding.module.startswith(('./','../')):
                        relative=posixpath.normpath(posixpath.join(posixpath.dirname(observed.file),binding.module))
                        if Path(relative).suffix in TS_SUFFIXES:relative=str(Path(relative).with_suffix(''))
                        imported=[u.module_key for u in units if u.language=='typescript' and str(Path(u.file).with_suffix(''))==relative]
                    binding_observations.append(kernel.BindingDeclaration(namespace,name,binding.kind,
                        binding.callable_key or '',binding.alias_scope or '',binding.alias_name or '',
                        _receiver_scope(observed,binding) if binding.kind=='receiver' else '',
                        tuple(sorted(imported)),binding.member,binding.qualified_import,binding.conditional,
                        tuple(sorted(e.value for e in binding.counter_evidence))))
    binding_observations.sort(key=lambda b:json.dumps(vars(b),sort_keys=True))
    invocation_observations=[]
    for observed in units:
        coordinates=Counter()
        for site in observed.sites:
            site.ordinal=coordinates[(site.line,site.column)]
            coordinates[(site.line,site.column)]+=1
            invocation_observations.append(kernel.InvocationObservation(
                stable_id('invocation',observed.language,observed.file,site.line,site.column,site.ordinal),
                observed.language,observed.file,site.spelling,site.line,site.column,site.ordinal,
                site.lexical_scope or site.owner.key,site.owner.key,site.region.region_id if site.region else '',
                site.resumes_coroutine))
    inventory = kernel.SemanticInventory(tuple(audits),tuple(r for u in units for r in u.regions.values()),
        tuple(e for u in units for e in u.escape_events),tuple(declarations.values()),
        bindings=tuple(binding_observations),namespaces=tuple(kernel.NamespaceObservation(
            u.module_key,u.language,u.file,u.module,u.package_name,frozenset(u.exports)) for u in units),
        sites=tuple(invocation_observations))
    inventory = kernel.audit_inventory(inventory,{u.file:u.source for u in units})
    if not kernel._inventory_valid(inventory):
        graph.coverage_gaps.append(('semantic inventory','kernel provenance audit incomplete'))
    for unit in units:
        unit.proof_inventory = inventory
        graph.coverage_gaps.extend(sorted(unit.semantic_gaps))
        graph.frontend_facts[unit.file] = {
            "lexical_environments": [e.to_dict() for _, e in sorted(unit.environments.items())],
            "escape_events": [e.to_dict() for e in unit.escape_events],
            "grammar_digest": unit.grammar_digest,
            "binding_declarations": [vars(b) for b in binding_observations if b.namespace in unit.environments],
            "invocation_observations": [vars(s) for s in invocation_observations if s.file==unit.file],
            "certificates": [c.to_dict() for _, c in sorted(unit.certificates.items())],
            "write_events": [e.to_dict() for e in unit.write_events],
            "execution_regions": [r.to_dict() for _, r in sorted(unit.regions.items())],
        }
    symbols = [s for u in units for s in u.symbols]
    roots = {}
    for unit in units:
        if discover_roots and unit.language != "python":
            try:
                _registered_roots(unit, indexes[unit.language], [s for s in symbols if s.language == unit.language],
                                  [u for u in units if u.language == unit.language])
            except Exception as exc:
                graph.analysis_errors.append((unit.file, f"root discovery: {exc}"))
    if discover_roots:
        discovered = {key: provenance for unit in units for key, provenance in unit.discovered.items()}
        for symbol in symbols:
            if symbol.key in discovered:
                root = _root(symbol, RootKind.MODEL_CALLABLE, discovered[symbol.key])
                roots[root.root_id] = root
    graph.roots_discovered = len(roots)
    for ep in entrypoints:
        matches = [s for s in symbols if s.file == ep.path and
                   (s.symbol == ep.symbol or s.symbol.endswith("." + ep.symbol))]
        if len(matches) != 1:
            graph.analysis_errors.append((ep.path, f"entrypoint {ep.symbol!r}: expected one callable, found {len(matches)}"))
            continue
        root = _root(matches[0], ep.kind, ("explicit_entrypoint",))
        previous = roots.get(root.root_id)
        if previous:
            root = InvocationRoot(root.root_id, root.language, root.file, root.symbol, root.kind,
                                  root.callable_key, previous.provenance + root.provenance)
        roots[root.root_id] = root
    graph.roots = sorted(roots.values(), key=lambda r: r.root_id)
    # Pass 3: resolve BindingClaims before any graph traversal.
    calls = []
    for unit in units:
        language_symbols = [s for s in symbols if s.language == unit.language]
        at_coordinate = Counter()
        for site in unit.sites:
            # Lexical preorder distinguishes call-on-call sites independently
            # of callee spelling, candidate order and root kind.
            ordinal = at_coordinate[(site.line, site.column)]
            at_coordinate[(site.line, site.column)] += 1
            site.ordinal = ordinal
            identity = stable_id("invocation", unit.language, unit.file, site.line, site.column, ordinal)
            error = None
            binding_claims = ()
            try:
                # Existing index diagnostics are retained as error accounting.
                # Their result is never passed to binding claim resolution.
                indexes[unit.language].resolve_call_target(
                    site.node if unit.language == "python" else site.spelling, in_module=unit.file)
                certainty, candidates, leaves, binding_claims = _resolve_binding_claims(
                    unit, site, identity, indexes[unit.language], language_symbols,
                    [u for u in units if u.language == unit.language])
            except Exception as exc:
                error = f"resolution at {site.line}:{site.column}: {type(exc).__name__}: {exc}"
                graph.analysis_errors.append((unit.file, error))
                certainty, leaves = ResolutionCertainty.UNRESOLVED, None
                candidates = (ImplementationTarget(stable_id("candidate", site.owner.key, site.line, site.column), dynamic=True),)
            rules = tuple(sorted(set((matched_rule_ids or {}).get((unit.file, site.line, site.column), ()))))
            resolved_identity = None
            if certainty == ResolutionCertainty.RESOLVED:
                (selected,) = candidates
                resolved_identity = selected.symbol
            calls.append(InvocationNode(identity, unit.language, unit.file, site.line, site.column,
                                        site.owner.symbol, site.owner.key, site.spelling, certainty, candidates,
                                        resolved_identity,
                                        leaves, rules, error, binding_claims=binding_claims,
                                        lexical_scope_id=site.lexical_scope or site.owner.key,
                                        execution_region=site.region))
    graph.traverse(calls, limits)
    return graph


def _root(symbol, kind, provenance):
    return InvocationRoot(stable_id("root", symbol.key, kind.value), symbol.language,
                          symbol.file, symbol.symbol, kind, symbol.key, provenance)
