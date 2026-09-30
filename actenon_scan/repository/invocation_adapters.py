"""Repository-index adapters for the common invocation graph.

Indexes supply import/local-call resolution. Lexical collectors repair the
indexes' intentional omissions (nested functions and anonymous callbacks),
without changing the legacy index consumers or learning effect semantics.
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

TS_SUFFIXES = {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
_FUNCTION_TYPES = {"function_declaration", "function_expression", "arrow_function",
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


@dataclass
class _Binding:
    """A lexical declaration, never a repository-wide name match."""
    kind: str = "unknown"
    callable_key: str | None = None
    module: str = ""
    member: str | None = None
    level: int = 0
    receiver_class: str | None = None
    conditional: bool = False
    line: int = 0


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
    package_name: str = ""
    exports: set[str] = field(default_factory=set)
    discovered: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def module_key(self):
        return CallableSymbol(self.language, self.file, self.module or "<module>", 1, 1).key

    def bind(self, scope, name, binding=None):
        if name and name != "_":
            self.bindings.setdefault(scope, {}).setdefault(name, []).append(binding or _Binding())

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


def _python_unit(file, source, tree, index, cfg):
    from actenon_scan.detectors.reachability import _reachability_for_func
    module = index._module_qualified_name(file)
    unit = _Unit("python", file, source, tree, module)
    module_sym = CallableSymbol("python", file, module or "<module>", 1, 1)

    class Collector(ast.NodeVisitor):
        owner = module_sym
        conditional = False
        # A method's lexical parent skips the class namespace.
        class_context = None
        execution_owner = None

        def bind(self, name, **values):
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
            self.bind(node.name, kind="callable", callable_key=sym.key, line=node.lineno)
            unit.scope_parents[sym.key] = context[1].key if context else previous.key
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
            self.bind(node.name, line=node.lineno)
            name = previous.symbol + "." + node.name if previous.symbol != "<module>" else node.name
            cls = CallableSymbol("python", file, name, node.lineno, node.col_offset + 1)
            unit.class_scopes[name] = cls.key
            caller = execution or previous
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
            unit.scope_parents[self.owner.key] = context[1].key if context else previous.key
            self.conditional, self.class_context, self.execution_owner = False, None, None
            self.parameters(node.args)
            self.visit(node.body)
            self.owner, self.conditional, self.class_context, self.execution_owner = previous, conditional, context, execution

        def visit_Name(self, node):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                self.bind(node.id, line=node.lineno)

        def visit_Attribute(self, node):
            if isinstance(node.ctx, (ast.Store, ast.Del)) and isinstance(node.value, ast.Name):
                _, bindings = _lexical_bindings(unit, self.owner.key, node.value.id)
                if len(bindings) == 1 and bindings[0].kind == "receiver":
                    unit.bind(_receiver_scope(unit, bindings[0]), node.attr)
            self.generic_visit(node)

        def visit_ExceptHandler(self, node):
            if node.name:
                self.bind(node.name, line=node.lineno)
            self.generic_visit(node)

        def visit_Import(self, node):
            for alias in node.names:
                self.bind(alias.asname or alias.name.split(".")[0], kind="import",
                          module=alias.name if alias.asname else alias.name.split(".")[0], line=node.lineno)

        def visit_ImportFrom(self, node):
            for alias in node.names:
                self.bind(alias.asname or alias.name, kind="import", module=node.module or "",
                          member=alias.name, level=node.level, line=node.lineno)

        def visit_Global(self, node):
            # Cross-scope stores are not proven by this bounded lexical model.
            for name in node.names:
                self.bind(name, line=node.lineno)
                unit.bind(unit.module_key, name)

        def visit_Nonlocal(self, node):
            for name in node.names:
                self.bind(name, line=node.lineno)
                unit.bind(unit.scope_parents.get(self.owner.key, unit.module_key), name)

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
            unit.sites.append(_Site(self.execution_owner or self.owner, node.lineno, node.col_offset + 1,
                                    ast.unparse(node.func), node.func,
                                    not isinstance(node.func, (ast.Name, ast.Attribute)), self.owner.key))
            self.generic_visit(node)

    Collector().visit(tree)
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


def _tree_unit(language, file, source, tree, index):
    module = (index._module_qualified_name(file) if language == "typescript"
              else index._package_qualified_name(file))
    unit = _Unit(language, file, source, tree, module)
    data = source.encode()
    module_sym = CallableSymbol(language, file, module or "<module>", 1, 1)
    if language == "go":
        package = next((n for n in tree.named_children if n.type == "package_clause"), None)
        unit.package_name = _text(package.named_children[0], data) if package and package.named_children else ""

    def class_scope(name):
        if name not in unit.class_scopes:
            unit.class_scopes[name] = stable_id("class-scope", language, file, name)
        return unit.class_scopes[name]

    def visit(node, owner, class_name="", conditional=False):
        if node.type in {"if_statement", "for_statement", "while_statement", "do_statement",
                         "try_statement", "switch_statement", "switch_case", "conditional_expression"}:
            conditional = True
        if node.type in {"statement_block", "block"} and (not node.parent or node.parent.type not in _FUNCTION_TYPES):
            # Block scopes are summarized conservatively, so declarations in
            # a nested block cannot establish an edge from outside that block.
            conditional = True
        if node.type in {"class_declaration", "class"}:
            name = _text(node.child_by_field_name("name"), data)
            unit.bind(owner.key, name, _Binding(conditional=conditional, line=node.start_point[0] + 1))
            class_name = ".".join(x for x in (module, name) if x)
            class_scope(class_name)
        if node.type in _FUNCTION_TYPES:
            previous = owner
            name = _text(node.child_by_field_name("name"), data)
            declarator = node.parent if node.parent and node.parent.type == "variable_declarator" else None
            variable = declarator.child_by_field_name("name") if declarator else None
            if not name and variable and variable.type == "identifier":
                name = _text(variable, data)
            method = node.type in {"method_definition", "method_declaration"}
            if language == "go" and node.type == "method_declaration":
                from actenon_scan.repository.go_symbol_index import _receiver_type_name
                class_name = ".".join(x for x in (module, _receiver_type_name(node, data)) if x)
            prefix = class_name or (owner.symbol if owner != module_sym else module)
            if not name:
                name = f"<callback@{node.start_point[0] + 1}:{node.start_point[1] + 1}>"
            sym = unit.symbol(".".join(x for x in (prefix, name) if x), node, owner.symbol)
            unit.scope_parents[sym.key] = previous.key
            if method and class_name:
                unit.bind(class_scope(class_name), name, _Binding("callable", sym.key, conditional=conditional,
                                                                 line=node.start_point[0] + 1))
            elif node.type == "function_declaration" or (variable and variable.type == "identifier"):
                unit.bind(previous.key, _text(variable, data) if variable else name,
                          _Binding("callable", sym.key, conditional=conditional, line=node.start_point[0] + 1))
            owner, conditional = sym, False
            for parameter in _pattern_names(node.child_by_field_name("parameters"), data):
                unit.bind(sym.key, parameter)
            for parameter in _pattern_names(node.child_by_field_name("parameter"), data):
                unit.bind(sym.key, parameter)
            # JavaScript's this is lexical in arrows and rebound in ordinary functions.
            if language == "typescript" and node.type != "arrow_function":
                static = any(child.type == "static" for child in node.children)
                unit.bind(sym.key, "this", _Binding("receiver", receiver_class=class_name)
                          if method and class_name and not static else _Binding())
            if language == "go" and node.type == "method_declaration":
                names = _pattern_names(node.child_by_field_name("receiver"), data)
                if len(names) == 1:
                    unit.bind(sym.key, names[0], _Binding("receiver", receiver_class=class_name))
        if node.type in {"call_expression", "new_expression"}:
            callee = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            if callee:
                spelling = _text(callee, data)
                unit.sites.append(_Site(owner, node.start_point[0] + 1, node.start_point[1] + 1,
                                        spelling, callee, bool(re.search(r"[\[\]()?]", spelling))))
        if node.type == "variable_declarator":
            name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if not (name and name.type == "identifier" and value and value.type in _FUNCTION_TYPES):
                for identifier in _pattern_names(name, data):
                    unit.bind(owner.key, identifier)
        if node.type in {"assignment_expression", "augmented_assignment_expression", "short_var_declaration",
                         "assignment_statement", "range_clause", "for_in_statement"}:
            left = node.child_by_field_name("left")
            for identifier in _pattern_names(left, data):
                unit.bind(owner.key, identifier)
            if left and left.type == "member_expression":
                receiver = left.child_by_field_name("object")
                _, bindings = _lexical_bindings(unit, owner.key, _text(receiver, data))
                if len(bindings) == 1 and bindings[0].kind == "receiver":
                    unit.bind(_receiver_scope(unit, bindings[0]), _text(left.child_by_field_name("property"), data))
        if node.type in {"var_spec", "type_spec"}:
            for i, child in enumerate(node.children):
                if node.field_name_for_child(i) == "name":
                    unit.bind(owner.key, _text(child, data))
        if node.type == "import_spec" and language == "go":
            name = _text(node.child_by_field_name("name"), data)
            if name:
                unit.bind(owner.key, "*" if name == "." else name)
        if node.type == "catch_clause":
            for identifier in _pattern_names(node.child_by_field_name("parameter"), data):
                unit.bind(owner.key, identifier)
        if node.type in {"public_field_definition", "field_definition"} and class_name:
            unit.bind(class_scope(class_name), _text(node.child_by_field_name("name"), data))
        if node.type == "import_statement":
            specifier = _text(node.child_by_field_name("source"), data).strip("\"'")
            for child in _walk(node):
                if child.type == "import_specifier":
                    imported = child.child_by_field_name("name")
                    local = child.child_by_field_name("alias") or imported
                    unit.bind(owner.key, _text(local, data), _Binding("ts_import", module=specifier,
                              member=_text(imported, data), conditional=conditional))
                elif child.type in {"import_clause", "namespace_import"}:
                    for identifier in child.named_children:
                        if identifier.type == "identifier":
                            unit.bind(owner.key, _text(identifier, data), _Binding("ts_import", module=specifier,
                                      member="default" if child.type == "import_clause" else None,
                                      conditional=conditional))
        for child in node.named_children:
            visit(child, owner, class_name, conditional)

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
    return unit


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
                                  handler.start_point[1] + 1, _text(handler, data), handler)
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
        scope = unit.scope_parents.get(scope, "")
    return unit.module_key, unit.bindings.get(unit.module_key, {}).get(name, [])


def _receiver_scope(unit, binding):
    return unit.class_scopes.get(binding.receiver_class, binding.receiver_class)


def _binding_targets(unit, scope, name, bindings, tail, index, units, symbols, seen=frozenset()):
    """Follow declaration/import provenance, never flattened binding dictionaries."""
    coordinate = (unit.file, scope, name, tuple(tail))
    if coordinate in seen:
        return [], False
    if len(seen) >= 32:
        raise RuntimeError("max_lexical_binding_depth reached (32)")
    seen = seen | {coordinate}
    targets, complete = [], bool(bindings)
    for binding in bindings:
        complete &= not binding.conditional
        if binding.kind == "callable" and not tail:
            found = [s for s in symbols if s.key == binding.callable_key]
            targets.extend(found)
            complete &= len(found) == 1
        elif binding.kind in {"import", "ts_import"}:
            modules, member = [], binding.member
            if unit.language == "python":
                if member is not None and not tail:
                    module = index._resolve_module_dotted(binding.module, binding.level, unit.file)
                elif member is None and tail:
                    module = index._resolve_module_dotted(".".join([binding.module] + tail[:-1]), binding.level, unit.file)
                    member = tail[-1]
                elif member is not None and tail:
                    base = index._resolve_module_dotted(binding.module, binding.level, unit.file)
                    owners = [u for u in units if u.module == base] if base is not None else []
                    bound_owners = [u for u in owners if member in u.bindings.get(u.module_key, {})
                                    or "*" in u.bindings.get(u.module_key, {})]
                    if bound_owners:
                        complete &= len(owners) == 1
                        for other in bound_owners:
                            declarations = other.bindings[other.module_key].get(member, []) + other.bindings[other.module_key].get("*", [])
                            found, exact = _binding_targets(other, other.module_key, member, declarations, tail,
                                                            index, units, symbols, seen)
                            targets.extend(found)
                            complete &= exact
                        continue
                    # `from . import module; module.run()` is a submodule binding.
                    module = index._resolve_module_dotted(".".join(x for x in (binding.module, member, *tail[:-1]) if x),
                                                          binding.level, unit.file)
                    member = tail[-1]
                else:
                    module = None
                modules = [u for u in units if u.module == module] if module is not None else []
            elif binding.kind == "ts_import" and binding.module.startswith(("./", "../")):
                relative = posixpath.normpath(posixpath.join(posixpath.dirname(unit.file), binding.module))
                if Path(relative).suffix in TS_SUFFIXES:
                    relative = str(Path(relative).with_suffix(""))
                modules = [u for u in units if str(Path(u.file).with_suffix("")) == relative]
                if member is None and len(tail) == 1:
                    member = tail[0]
                elif tail:
                    modules = []
            complete &= len(modules) == 1 and member not in {None, "*", "default"}
            for other in modules:
                if unit.language == "typescript" and member not in other.exports:
                    complete = False
                other_bindings = other.bindings.get(other.module_key, {}).get(member, [])
                if "*" in other.bindings.get(other.module_key, {}):
                    other_bindings = other_bindings + other.bindings[other.module_key]["*"]
                found, exact = _binding_targets(other, other.module_key, member, other_bindings, [],
                                                index, units, symbols, seen)
                targets.extend(found)
                complete &= exact
        else:
            complete = False
    unique = {s.key: s for s in targets}
    return list(unique.values()), complete and len(bindings) == 1


def _resolve(unit, site, index, symbols, units):
    """RESOLVED means one structurally justified lexical target."""
    # Retain the index/resolver failure path, but never trust its flattened
    # import/name binding as proof of a lexical edge.
    if unit.language == "python":
        index.resolve_call_target(site.node, in_module=unit.file)
    else:
        index.resolve_call_target(site.spelling, in_module=unit.file)
    simple = bool(re.fullmatch(r"[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*", site.spelling))
    parts = site.spelling.split(".")
    head, name = parts[0], parts[-1]
    lexical_scope = site.lexical_scope or site.owner.key
    scope, bindings = _lexical_bindings(unit, lexical_scope, head)
    candidates, complete = [], False
    if simple and len(parts) == 2 and len(bindings) == 1 and bindings[0].kind == "receiver":
        receiver = bindings[0]
        class_scope = _receiver_scope(unit, receiver)
        member_bindings = unit.bindings.get(class_scope, {}).get(name, [])
        candidates, complete = _binding_targets(unit, class_scope, name, member_bindings, [],
                                                index, units, symbols)
        complete &= not receiver.conditional
    elif simple and unit.language == "go" and len(parts) == 1 and scope == unit.module_key:
        # Package-level names span files, but not distinct package clauses.
        package_units = [u for u in units if Path(u.file).parent == Path(unit.file).parent
                         and u.package_name == unit.package_name]
        package_bindings = [(u, u.bindings.get(u.module_key, {}).get(head, [])) for u in package_units]
        active = [(u, b) for u, b in package_bindings if b]
        complete = len(active) == 1
        for other, declarations in active:
            found, exact = _binding_targets(other, other.module_key, head, declarations, [], index, units, symbols)
            candidates.extend(found)
            complete &= exact
    elif simple and bindings:
        candidates, complete = _binding_targets(unit, scope, head, bindings, parts[1:], index, units, symbols)
        # A declaration later in the same callable/class has not executed yet.
        if scope == lexical_scope and scope != unit.module_key and any(b.line > site.line for b in bindings):
            complete = False
    if complete and len(candidates) == 1:
        return ResolutionCertainty.RESOLVED, (ImplementationTarget.local(candidates[0]),), False
    if simple and not bindings and not candidates:
        candidates = [s for s in symbols if s.symbol.rsplit(".", 1)[-1] == name]
    candidates = list({s.key: s for s in candidates}.values())
    certainty = ResolutionCertainty.HEURISTIC if candidates else ResolutionCertainty.UNRESOLVED
    targets = [ImplementationTarget.local(s) for s in candidates]
    dynamic = site.dynamic or bool(bindings) or bool(candidates)
    targets.append(ImplementationTarget(stable_id("candidate", site.owner.key, site.line, site.column, "unknown"),
                                         opaque=not dynamic, dynamic=dynamic))
    return certainty, tuple(sorted(targets, key=lambda t: t.candidate_id)), None


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
                unit = _python_unit(file, source, tree, indexes[language], reachability_cfg)
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
                unit = _tree_unit(language, file, source, tree, indexes[language])
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
    calls = []
    for unit in units:
        language_symbols = [s for s in symbols if s.language == unit.language]
        at_coordinate = Counter()
        for site in unit.sites:
            error = None
            try:
                certainty, candidates, leaves = _resolve(unit, site, indexes[unit.language], language_symbols,
                                                         [u for u in units if u.language == unit.language])
            except Exception as exc:
                error = f"resolution at {site.line}:{site.column}: {type(exc).__name__}: {exc}"
                graph.analysis_errors.append((unit.file, error))
                certainty, leaves = ResolutionCertainty.UNRESOLVED, None
                candidates = (ImplementationTarget(stable_id("candidate", site.owner.key, site.line, site.column), dynamic=True),)
            # factory().method() has two calls at one start coordinate.
            # Lexical preorder distinguishes them without depending on the
            # callee text or its length, preserving rename invariance.
            ordinal = at_coordinate[(site.line, site.column)]
            at_coordinate[(site.line, site.column)] += 1
            identity = stable_id("invocation", unit.language, unit.file, site.line, site.column, ordinal)
            rules = tuple(sorted(set((matched_rule_ids or {}).get((unit.file, site.line, site.column), ()))))
            resolved_identity = None
            if certainty == ResolutionCertainty.RESOLVED:
                (selected,) = candidates
                resolved_identity = selected.symbol
            calls.append(InvocationNode(identity, unit.language, unit.file, site.line, site.column,
                                        site.owner.symbol, site.owner.key, site.spelling, certainty, candidates,
                                        resolved_identity,
                                        leaves, rules, error))
    graph.traverse(calls, limits)
    return graph


def _root(symbol, kind, provenance):
    return InvocationRoot(stable_id("root", symbol.key, kind.value), symbol.language,
                          symbol.file, symbol.symbol, kind, symbol.key, provenance)
