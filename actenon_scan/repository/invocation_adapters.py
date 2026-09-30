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
    scopes: dict[str, set[str]] = field(default_factory=dict)
    discovered: dict[str, tuple[str, ...]] = field(default_factory=dict)
    import_scopes: dict[str, set[str]] = field(default_factory=dict)
    receiver_scopes: dict[str, str] = field(default_factory=dict)

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

        def visit_FunctionDef(self, node):
            # Definition-time expressions belong to the enclosing callable.
            for expression in node.decorator_list + node.args.defaults + [x for x in node.args.kw_defaults if x]:
                self.visit(expression)
            previous = self.owner
            name = previous.symbol + "." + node.name if previous.symbol != "<module>" else node.name
            sym = unit.symbol(name, node, previous.symbol)
            signal = _reachability_for_func(tree, node, cfg, None, node.lineno)
            if signal.confidence == "high":
                unit.discovered[sym.key] = tuple(signal.signals)
            self.owner = sym
            # Parameters/local stores shadow module/import bindings.
            args = node.args
            shadows = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
            shadows.update(a.arg for a in (args.vararg, args.kwarg) if a)
            unit.scopes[sym.key] = shadows
            for statement in node.body:
                self.visit(statement)
            self.owner = previous

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            for expression in node.decorator_list + node.bases + [k.value for k in node.keywords]:
                self.visit(expression)
            previous = self.owner
            name = previous.symbol + "." + node.name if previous.symbol != "<module>" else node.name
            # Class definition bodies execute in the enclosing caller, but
            # method identities include the class, and method bodies don't.
            for statement in node.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    self.owner = CallableSymbol("python", file, name, node.lineno, node.col_offset + 1)
                    self.visit(statement)
                    self.owner = previous
                else:
                    self.visit(statement)

        def visit_Lambda(self, node):
            previous = self.owner
            name = f"{previous.symbol}.<lambda@{node.lineno}:{node.col_offset + 1}>"
            self.owner = unit.symbol(name, node, previous.symbol)
            self.visit(node.body)
            self.owner = previous

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Store):
                unit.scopes.setdefault(self.owner.key, set()).add(node.id)

        def visit_Import(self, node):
            names = {a.asname or a.name.split(".")[0] for a in node.names}
            unit.import_scopes.setdefault(self.owner.key, set()).update(names)

        def visit_ImportFrom(self, node):
            names = {a.asname or a.name for a in node.names}
            unit.import_scopes.setdefault(self.owner.key, set()).update(names)

        def visit_Call(self, node):
            unit.sites.append(_Site(self.owner, node.lineno, node.col_offset + 1,
                                    ast.unparse(node.func), node.func,
                                    not isinstance(node.func, (ast.Name, ast.Attribute))))
            self.generic_visit(node)

    Collector().visit(tree)
    return unit


def _tree_unit(language, file, source, tree, index):
    module = (index._module_qualified_name(file) if language == "typescript"
              else index._package_qualified_name(file))
    unit = _Unit(language, file, source, tree, module)
    data = source.encode()
    module_sym = CallableSymbol(language, file, module or "<module>", 1, 1)

    def visit(node, owner, class_name=""):
        if node.type in {"class_declaration", "class"}:
            name = _text(node.child_by_field_name("name"), data)
            class_name = ".".join(x for x in (module, name) if x)
        if node.type in _FUNCTION_TYPES:
            name = _text(node.child_by_field_name("name"), data)
            if not name and node.parent and node.parent.type == "variable_declarator":
                name = _text(node.parent.child_by_field_name("name"), data)
            if language == "go" and node.type == "method_declaration":
                from actenon_scan.repository.go_symbol_index import _receiver_type_name
                class_name = ".".join(x for x in (module, _receiver_type_name(node, data)) if x)
            prefix = class_name or (owner.symbol if owner != module_sym else module)
            if not name:
                name = f"<callback@{node.start_point[0] + 1}:{node.start_point[1] + 1}>"
            sym = unit.symbol(".".join(x for x in (prefix, name) if x), node, owner.symbol)
            owner = sym
            if language == "go" and node.type == "method_declaration":
                receiver = node.child_by_field_name("receiver")
                names = [_text(n, data) for n in _walk(receiver) if n.type == "identifier"] if receiver else []
                if len(names) == 1:
                    unit.receiver_scopes[sym.key] = names[0]
            params = node.child_by_field_name("parameters")
            unit.scopes[sym.key] = {
                _text(n, data) for n in _walk(params) if n.type in {"identifier", "shorthand_property_identifier_pattern"}
            } if params else set()
        if node.type in {"call_expression", "new_expression"}:
            callee = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            if callee:
                spelling = _text(callee, data)
                unit.sites.append(_Site(owner, node.start_point[0] + 1, node.start_point[1] + 1,
                                        spelling, callee,
                                        bool(re.search(r"[\[\]()?]", spelling))))
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name and name.type == "identifier" and (value is None or value.type not in _FUNCTION_TYPES):
                unit.scopes.setdefault(owner.key, set()).add(_text(name, data))
        for child in node.named_children:
            visit(child, owner, class_name)

    visit(tree, module_sym)
    return unit


def _registered_roots(unit, index, symbols):
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
                certainty, targets, _ = _resolve(unit, reference, index, symbols)
                if certainty == ResolutionCertainty.RESOLVED:
                    (selected,) = targets
                    unit.discovered[selected.callable_key] = ("tool_registration:" + callee,)


def _resolve(unit, site, index, symbols):
    """Retain name candidates; only scoped, exact local bindings get followed."""
    if unit.language == "python":
        sym, certainty, _ = index.resolve_call_target(site.node, in_module=unit.file)
    else:
        sym, certainty, _ = index.resolve_call_target(site.spelling, in_module=unit.file)
    candidates = []
    exact = []
    name = site.spelling.rsplit(".", 1)[-1]
    simple = bool(re.fullmatch(r"[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*", site.spelling))
    head = site.spelling.split(".", 1)[0]
    scope_chain = [site.owner]
    seen_scopes = {site.owner.symbol}
    while scope_chain[-1].scope:
        parents = [s for s in unit.symbols if s.symbol == scope_chain[-1].scope]
        if len(parents) != 1 or parents[0].symbol in seen_scopes:
            break
        (parent,) = parents
        scope_chain.append(parent)
        seen_scopes.add(parent.symbol)
    module_key = CallableSymbol(unit.language, unit.file, unit.module or "<module>", 1, 1).key
    shadowed = head in unit.scopes.get(module_key, set()) or any(
        head in unit.scopes.get(s.key, set()) for s in scope_chain)
    if unit.language == "python":
        # The legacy Python index collects imports from nested functions in
        # the module namespace. Such imports cannot bind sibling functions.
        accessible_imports = unit.import_scopes.get(module_key, set()).union(
            *(unit.import_scopes.get(s.key, set()) for s in scope_chain))
        if any(head in names for names in unit.import_scopes.values()) and head not in accessible_imports:
            shadowed = True
    # self/this is only resolved against the actual caller class, never a
    # uniquely named method from a different class in the same file.
    if site.spelling.startswith(("self.", "this.")) or (
            unit.language == "go" and "." in site.spelling
            and head == unit.receiver_scopes.get(site.owner.key)):
        parent = site.owner.symbol.rsplit(".", 1)[0]
        exact = [s for s in unit.symbols if s.symbol == parent + "." + name]
    elif simple and not shadowed:
        # Nested definitions have a lexical owner; indexes omit some of them.
        exact = [s for s in unit.symbols if s.scope == site.owner.symbol and s.symbol.endswith("." + site.spelling)]
        if not exact and sym is not None and certainty == ResolutionCertainty.RESOLVED:
            exact = [s for s in symbols if s.file == sym.location.file and s.symbol == sym.qualified_name]
        # Go's legacy index groups declarations per file; same-package
        # functions in other files are still exact local bindings.
        if not exact and unit.language == "go" and "." not in site.spelling:
            exact = [s for s in symbols if Path(s.file).parent == Path(unit.file).parent
                     and s.symbol == ".".join(x for x in (unit.module, name) if x)]
    if len(exact) == 1:
        (selected,) = exact
        return ResolutionCertainty.RESOLVED, (ImplementationTarget.local(selected),), False
    if simple and not shadowed:
        candidates = [s for s in symbols if s.symbol.rsplit(".", 1)[-1] == name]
    certainty = ResolutionCertainty.HEURISTIC if candidates else ResolutionCertainty.UNRESOLVED
    targets = [ImplementationTarget.local(s) for s in candidates]
    # Open-world ambiguity retains the unknown alternative, even with a
    # single heuristic name match. It never establishes implementation.
    dynamic = site.dynamic or (shadowed and "." not in site.spelling) or bool(candidates)
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
                _registered_roots(unit, indexes[unit.language], [s for s in symbols if s.language == unit.language])
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
                certainty, candidates, leaves = _resolve(unit, site, indexes[unit.language], language_symbols)
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
