"""Repository-level symbol index.

A ``RepositoryIndex`` represents everything the analyser knows about a
repository's Python source files: the files themselves, the symbols they
define, the imports they make, and the call sites they contain. It is
the substrate on which the interprocedural call graph, effect
propagation, taint analysis, and cross-file guard resolution are built.

Resolution model
----------------

Python imports are resolved conservatively. We distinguish:

- :data:`ResolutionCertainty.RESOLVED` — the import statement unambiguously
  identifies a single local target. ``from localmod import fn`` resolves
  to ``localmod.fn`` if ``localmod`` exists in the repository.

- :data:`ResolutionCertainty.HEURISTIC` — the import could be local or
  third-party and we have no symbol evidence either way (e.g.
  ``import os`` with no local ``os.py``).

- :data:`ResolutionCertainty.UNRESOLVED` — a dynamic import form
  (``importlib.import_module(name)``, ``__import__(...)``) where the
  target name is not a string literal.

The third state is *explicit*. Nothing labelled ``UNRESOLVED`` is ever
silently treated as either local or external.

What this module deliberately does NOT do:

- Resolve arbitrary dynamic imports (``getattr(mod, name)()``).
- Infer return-type-based dispatch (decorator factories, plugin
  registries).
- Walk ``setup.py`` / ``pyproject.toml`` entry points.
- Inspect packages outside the repository root.

Each of these is a documented limitation in ``docs/COVERAGE.md``.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# Source locations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceLocation:
    """A precise position in a source file.

    ``file`` is the path *relative to the repository root* (or the
    basename when scanning a single file). Kept relative so that
    indices remain valid across checkouts / CI runs.
    """

    file: str
    line: int
    col: int = 0

    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.col}"


# ---------------------------------------------------------------------------
# Symbols
# ---------------------------------------------------------------------------


class SymbolKind(str, Enum):
    """What kind of Python symbol this is.

    Values are strings so that they serialise to JSON naturally.
    """

    MODULE = "module"
    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    CLASS = "class"
    METHOD = "method"
    ASYNC_METHOD = "async_method"
    # An imported binding — the symbol exists in another module but the
    # current module binds a name to it. Tracked separately so that the
    # call graph can resolve ``from foo import bar`` calls to the actual
    # ``bar`` definition.
    IMPORTED = "imported"


@dataclass(frozen=True)
class Symbol:
    """A Python symbol defined in the repository.

    ``qualified_name`` is the canonical dotted path
    (``pkg.mod.ClassName.method_name``). It is the key the call graph
    uses to resolve call sites.
    """

    name: str
    kind: SymbolKind
    qualified_name: str
    location: SourceLocation
    # For methods: the enclosing class qualified name. For functions: empty.
    enclosing_class: str = ""
    # For decorated functions: the decorators as their textual form. This
    # is used by the reachability layer to detect @tool etc. without
    # re-parsing. Each decorator is ``ast.unparse(decorator_node)``.
    decorators: tuple[str, ...] = field(default_factory=tuple)
    # Whether the function/method is decorated with something that
    # already-known reachability config recognises as a tool boundary
    # (populated by the engine when reachability config is available;
    # empty tuple means "not yet classified").
    tool_boundary_decorators: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_function_like(self) -> bool:
        return self.kind in (
            SymbolKind.FUNCTION,
            SymbolKind.ASYNC_FUNCTION,
            SymbolKind.METHOD,
            SymbolKind.ASYNC_METHOD,
        )


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------


class ImportKind(str, Enum):
    """How an imported name was bound."""

    # ``import a``           — binds name `a`
    PLAIN = "plain"
    # ``import a.b.c``       — binds name `a` (with attribute access for b.c)
    PLAIN_DOTTED = "plain_dotted"
    # ``import a as b``      — binds name `b` to module `a`
    ALIASED = "aliased"
    # ``from a import b``    — binds name `b` from module `a`
    FROM_IMPORT = "from_import"
    # ``from a import b as c`` — binds name `c` to `a.b`
    FROM_IMPORT_ALIASED = "from_import_aliased"
    # ``from . import b``    — relative; binds name `b` from the package
    FROM_RELATIVE = "from_relative"
    # ``from .mod import b`` — relative with explicit module
    FROM_RELATIVE_MOD = "from_relative_mod"
    # ``importlib.import_module("x")`` — dynamic; not statically resolvable
    DYNAMIC = "dynamic"


class ResolutionCertainty(str, Enum):
    """How certain we are about an import's target.

    - ``RESOLVED`` — the import unambiguously resolves to a single
      repository-local target. Used by the call graph as a *strong* edge.
    - ``HEURISTIC`` — we made a best-effort match (e.g. name collision
      with a local module) but cannot prove it. Used as a *weak* edge.
    - ``UNRESOLVED`` — the import is dynamic or out-of-repo. Explicitly
      marked so that downstream analysis never silently treats it as
      local or external.
    """

    RESOLVED = "resolved"
    HEURISTIC = "heuristic"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class Import:
    """An import statement in a module."""

    kind: ImportKind
    # The literal module name as it appears in the import. For
    # ``from a.b import c``, this is ``"a.b"``. For relative imports,
    # this is the part after the dots (may be empty for ``from . import x``).
    module: str
    # The bound name in the current module's namespace.
    bound_name: str
    # The original imported name (for ``from a import b as c``, this is ``"b"``).
    imported_name: str
    location: SourceLocation
    # How many leading dots on a relative import (0 for absolute).
    relative_level: int = 0
    # The resolved target, if any. None until ``RepositoryIndex.resolve_import``
    # has been called. The resolution *certainty* is on the import itself
    # (because resolution can be done lazily, but certainty is intrinsic
    # to the import form).
    resolved_target: "ResolvedTarget | None" = None


@dataclass(frozen=True)
class ResolvedTarget:
    """Where an import actually points.

    For repository-local imports, ``qualified_name`` is the canonical
    dotted path of the bound symbol (``pkg.mod.ClassName``) and
    ``symbol`` is the matching :class:`Symbol` (or ``None`` if the
    target module exists but the symbol inside it could not be located —
    e.g. ``from foo import bar`` where ``foo`` exists but ``bar`` is
    dynamically defined).
    """

    qualified_name: str
    certainty: ResolutionCertainty
    symbol: Symbol | None = None
    # The canonical module path (without the symbol inside it). For
    # ``from pkg.mod import cls`` → ``"pkg.mod"``.
    module_path: str = ""


# ---------------------------------------------------------------------------
# Call sites
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CallSite:
    """A single call expression observed in a function body.

    The call graph builder converts these into :class:`CallEdge`s after
    attempting to resolve the callee.
    """

    location: SourceLocation
    # The textual callee (e.g. ``"layer_one"``, ``"self.client.execute"``,
    # ``"obj.run"``). Used for diagnostics.
    callee_text: str
    # The qualified name of the function that *contains* this call site.
    caller_qualified_name: str
    # The arg expressions as text, for downstream taint analysis.
    arg_texts: tuple[str, ...] = field(default_factory=tuple)
    # The keyword args as (name, text) pairs.
    kwarg_pairs: tuple[tuple[str, str], ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Repository index
# ---------------------------------------------------------------------------


@dataclass
class _ModuleInfo:
    """Per-module bookkeeping in the index."""

    path: str
    qualified_name: str
    # The bound names in this module's namespace → what they resolve to.
    # Key = local bound name (e.g. ``"run_cmd"`` for ``from helpers import run_cmd``).
    # Value = the resolved target.
    bindings: dict[str, ResolvedTarget] = field(default_factory=dict)
    # Map from local symbol name (within this module) to the Symbol.
    local_symbols: dict[str, Symbol] = field(default_factory=dict)
    # Map from full qualified name to Symbol (for cross-module lookups).
    # Mostly redundant with ``RepositoryIndex._symbols_by_qname`` but kept
    # per-module for fast module-local lookups during call resolution.
    symbols_by_qname: dict[str, Symbol] = field(default_factory=dict)


class RepositoryIndex:
    """A repository-level index of Python source files.

    Build one with :meth:`build` (or :meth:`add_file` incrementally), then
    use :meth:`resolve_call_target` to translate an AST call node's
    callee into a :class:`Symbol` (or ``None``, with explicit certainty).
    """

    def __init__(self, root: Path | str | None = None) -> None:
        # The repository root. May be ``None`` when scanning a single
        # file (in which case all symbols live in the file's basename).
        self.root: Path | None = Path(root) if root is not None else None

        # file relative path → _ModuleInfo
        self._modules: dict[str, _ModuleInfo] = {}

        # qualified_name → Symbol  (the canonical index)
        self._symbols_by_qname: dict[str, Symbol] = {}

        # local_name → list of Symbols   (for bare-name call resolution)
        # Multiple modules can define a function called ``run`` — a bare
        # ``run()`` call inside a module is resolved by consulting the
        # *current module's* bindings first, then by heuristic on
        # unqualified names that match exactly one repository symbol.
        self._symbols_by_local_name: dict[str, list[Symbol]] = {}

        # call sites, keyed by caller qualified name
        self._call_sites_by_caller: dict[str, list[CallSite]] = {}

        # raw ASTs, kept for downstream taint / CFG analysis
        # (file → (source_str, ast.Module))
        self._ast_cache: dict[str, tuple[str, ast.Module]] = {}

        # Pending import nodes, resolved in finalize(). Keyed by
        # (file_rel, module_qname) → list of (ast_node, _ModuleInfo).
        # We must defer resolution so that imports in main.py can see
        # symbols in srv.py regardless of file-add order.
        self._pending_imports: list[
            tuple[ast.Import | ast.ImportFrom, str, str, "_ModuleInfo"]
        ] = []
        self._finalized: bool = False

    # ── properties ───────────────────────────────────────────────────

    @property
    def files(self) -> list[str]:
        """All files in the index, sorted for determinism."""
        return sorted(self._modules.keys())

    @property
    def symbols(self) -> list[Symbol]:
        """All symbols in the index (insertion order preserved by dict)."""
        return list(self._symbols_by_qname.values())

    @property
    def call_sites(self) -> list[CallSite]:
        out: list[CallSite] = []
        for sites in self._call_sites_by_caller.values():
            out.extend(sites)
        return out

    @property
    def imports(self) -> list[Import]:
        """All imports across all modules (deterministic order)."""
        out: list[Import] = []
        for mod in self._modules.values():
            for binding in mod.bindings.values():
                # Each binding corresponds to one Import statement; reconstruct
                # a minimal Import for reporting.
                out.append(Import(
                    kind=ImportKind.FROM_IMPORT,  # placeholder; real kind tracked in _imports_per_module
                    module=binding.module_path,
                    bound_name="",  # not retained separately; the binding key is the local name
                    imported_name=binding.qualified_name.split(".")[-1]
                    if binding.qualified_name else "",
                    location=SourceLocation(file=mod.path, line=0, col=0),
                    resolved_target=binding,
                ))
        return out

    # ── building ──────────────────────────────────────────────────────

    def add_file(self, file_rel: str, source: str, tree: ast.Module | None = None) -> None:
        """Index a single Python file.

        ``file_rel`` is the path relative to the repository root (or the
        basename when there is no root). ``source`` is the file's text.
        ``tree`` is an optional pre-parsed AST; if omitted, the source
        is parsed with :func:`ast.parse`.

        Symbols are registered immediately. Import resolution is deferred
        to :meth:`finalize` so that cross-file imports (e.g. ``main.py``
        importing from ``srv.py``) resolve correctly regardless of the
        order files were added.
        """
        if tree is None:
            tree = ast.parse(source, filename=file_rel)
        self._ast_cache[file_rel] = (source, tree)
        self._finalized = False

        module_qname = self._module_qualified_name(file_rel)
        info = _ModuleInfo(path=file_rel, qualified_name=module_qname)
        self._modules[file_rel] = info

        # Walk top-level statements
        for node in tree.body:
            self._index_top_level(node, file_rel, module_qname, info, source)

        # Also walk class bodies to register methods (methods are
        # first-class symbols for the call graph).
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                self._index_class_body(node, file_rel, module_qname, info, source)

        # Defer import resolution — collect the raw nodes for finalize().
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self._pending_imports.append((node, file_rel, module_qname, info))

        # Index call sites (resolved at finalize time after imports).
        self._index_call_sites(tree, file_rel, module_qname, info)

    def finalize(self) -> None:
        """Resolve all deferred imports.

        After this is called, ``ModuleInfo.bindings`` is populated and
        cross-file resolution works. Idempotent — calling twice is a
        no-op. ``RepositoryIndex.build`` calls this automatically before
        returning.
        """
        if self._finalized:
            return
        for node, file_rel, module_qname, info in self._pending_imports:
            self._index_import(node, file_rel, module_qname, info)
        self._pending_imports.clear()
        self._finalized = True

    def _index_top_level(
        self,
        node: ast.stmt,
        file_rel: str,
        module_qname: str,
        info: _ModuleInfo,
        source: str,
    ) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sym = self._make_function_symbol(node, file_rel, module_qname, enclosing="")
            self._register_symbol(sym, info)
        elif isinstance(node, ast.ClassDef):
            cls_qname = f"{module_qname}.{node.name}" if module_qname else node.name
            cls_sym = Symbol(
                name=node.name,
                kind=SymbolKind.CLASS,
                qualified_name=cls_qname,
                location=SourceLocation(file_rel, node.lineno, node.col_offset),
                decorators=tuple(self._decorator_text(d) for d in node.decorator_list),
            )
            self._register_symbol(cls_sym, info)

    def _index_class_body(
        self,
        cls_node: ast.ClassDef,
        file_rel: str,
        module_qname: str,
        info: _ModuleInfo,
        source: str,
    ) -> None:
        cls_qname = f"{module_qname}.{cls_node.name}" if module_qname else cls_node.name
        for child in cls_node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                sym = self._make_function_symbol(
                    child, file_rel, module_qname, enclosing=cls_qname
                )
                # Override kind to METHOD / ASYNC_METHOD
                if sym.kind == SymbolKind.FUNCTION:
                    sym = Symbol(
                        name=sym.name,
                        kind=SymbolKind.METHOD,
                        qualified_name=sym.qualified_name,
                        location=sym.location,
                        enclosing_class=sym.enclosing_class,
                        decorators=sym.decorators,
                        tool_boundary_decorators=sym.tool_boundary_decorators,
                    )
                elif sym.kind == SymbolKind.ASYNC_FUNCTION:
                    sym = Symbol(
                        name=sym.name,
                        kind=SymbolKind.ASYNC_METHOD,
                        qualified_name=sym.qualified_name,
                        location=sym.location,
                        enclosing_class=sym.enclosing_class,
                        decorators=sym.decorators,
                        tool_boundary_decorators=sym.tool_boundary_decorators,
                    )
                self._register_symbol(sym, info)

    def _make_function_symbol(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_rel: str,
        module_qname: str,
        enclosing: str,
    ) -> Symbol:
        if enclosing:
            qname = f"{enclosing}.{node.name}"
        else:
            qname = f"{module_qname}.{node.name}" if module_qname else node.name
        kind = (
            SymbolKind.ASYNC_FUNCTION
            if isinstance(node, ast.AsyncFunctionDef)
            else SymbolKind.FUNCTION
        )
        return Symbol(
            name=node.name,
            kind=kind,
            qualified_name=qname,
            location=SourceLocation(file_rel, node.lineno, node.col_offset),
            enclosing_class=enclosing,
            decorators=tuple(self._decorator_text(d) for d in node.decorator_list),
        )

    def _decorator_text(self, dec: ast.AST) -> str:
        try:
            return ast.unparse(dec)
        except Exception:
            return ""

    def _register_symbol(self, sym: Symbol, info: _ModuleInfo) -> None:
        self._symbols_by_qname[sym.qualified_name] = sym
        info.symbols_by_qname[sym.qualified_name] = sym
        info.local_symbols[sym.name] = sym
        self._symbols_by_local_name.setdefault(sym.name, []).append(sym)

    def _index_import(
        self,
        node: ast.Import | ast.ImportFrom,
        file_rel: str,
        module_qname: str,
        info: _ModuleInfo,
    ) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                kind = (
                    ImportKind.ALIASED
                    if alias.asname
                    else (
                        ImportKind.PLAIN_DOTTED
                        if "." in alias.name
                        else ImportKind.PLAIN
                    )
                )
                target = self._resolve_module_import(alias.name)
                rt = ResolvedTarget(
                    qualified_name=alias.name if target else alias.name,
                    certainty=(
                        ResolutionCertainty.RESOLVED
                        if target
                        else ResolutionCertainty.HEURISTIC
                    ),
                    symbol=None,
                    module_path=alias.name,
                )
                info.bindings[bound] = rt
        elif isinstance(node, ast.ImportFrom):
            mod_name = node.module or ""
            level = node.level or 0
            for alias in node.names:
                if alias.name == "*":
                    # Star import — explicitly unresolvable to a single target
                    rt = ResolvedTarget(
                        qualified_name=f"{mod_name}.*",
                        certainty=ResolutionCertainty.UNRESOLVED,
                        symbol=None,
                        module_path=mod_name,
                    )
                    bound = mod_name.split(".")[-1] if mod_name else ""
                    info.bindings.setdefault(bound or "*", rt)
                    continue
                bound = alias.asname or alias.name
                kind = (
                    ImportKind.FROM_IMPORT_ALIASED
                    if alias.asname
                    else (
                        ImportKind.FROM_RELATIVE_MOD
                        if level and mod_name
                        else ImportKind.FROM_RELATIVE
                        if level
                        else ImportKind.FROM_IMPORT
                    )
                )
                target_sym = self._resolve_from_import(mod_name, alias.name, level, file_rel)
                if target_sym is not None:
                    rt = ResolvedTarget(
                        qualified_name=target_sym.qualified_name,
                        certainty=ResolutionCertainty.RESOLVED,
                        symbol=target_sym,
                        module_path=self._module_qname_for_symbol(target_sym),
                    )
                else:
                    # Could be external, or local-but-not-found.
                    # If the module is local but the symbol isn't found,
                    # we still mark as RESOLVED to the module (the symbol
                    # may be dynamically defined). Otherwise HEURISTIC.
                    target_module = self._resolve_module_dotted(
                        mod_name, level, file_rel
                    )
                    if target_module is not None:
                        rt = ResolvedTarget(
                            qualified_name=f"{target_module}.{alias.name}"
                            if target_module
                            else alias.name,
                            certainty=ResolutionCertainty.HEURISTIC,
                            symbol=None,
                            module_path=target_module,
                        )
                    else:
                        rt = ResolvedTarget(
                            qualified_name=f"{mod_name}.{alias.name}"
                            if mod_name
                            else alias.name,
                            certainty=ResolutionCertainty.HEURISTIC,
                            symbol=None,
                            module_path=mod_name,
                        )
                info.bindings[bound] = rt

    def _resolve_module_import(self, dotted_name: str) -> Symbol | None:
        """Resolve ``import a.b`` to a local module symbol, if it exists."""
        # Try the dotted name directly (a.b → module a.b)
        sym = self._symbols_by_qname.get(dotted_name)
        if sym is not None and sym.kind == SymbolKind.MODULE:
            return sym
        # Try the top-level package
        top = dotted_name.split(".")[0]
        sym = self._symbols_by_qname.get(top)
        if sym is not None and sym.kind == SymbolKind.MODULE:
            return sym
        return None

    def _resolve_from_import(
        self,
        module: str,
        name: str,
        level: int,
        current_file: str,
    ) -> Symbol | None:
        """Resolve ``from module import name`` to a local symbol."""
        # Resolve the module part to a local module qualified name.
        target_module_qname = self._resolve_module_dotted(module, level, current_file)
        if target_module_qname is None:
            return None
        # Try the qualified lookup: target_module_qname . name
        candidate_qname = (
            f"{target_module_qname}.{name}" if target_module_qname else name
        )
        sym = self._symbols_by_qname.get(candidate_qname)
        if sym is not None:
            return sym
        # Some symbols (methods) are registered under class-qualified names
        # but a from-import might bind the class itself. Try as a class.
        # Already covered by the qualified lookup above.
        return None

    def _resolve_module_dotted(
        self,
        module: str,
        level: int,
        current_file: str,
    ) -> str | None:
        """Resolve a possibly-relative module reference to a repository-local
        qualified module name.

        Returns ``None`` if the module is not in the repository.
        """
        if level > 0:
            # Relative import. Compute the current package from current_file.
            # ``from . import x`` → same package as current_file
            # ``from .mod import x`` → package + mod
            current_pkg = self._package_of_file(current_file)
            if not current_pkg:
                # We're at the root; relative imports are not resolvable.
                return None
            # Walk up `level-1` packages
            parts = current_pkg.split(".")
            if level - 1 > 0 and level - 1 >= len(parts):
                return None
            base = ".".join(parts[: len(parts) - (level - 1)]) if level > 1 else current_pkg
            if module:
                return f"{base}.{module}" if base else module
            return base or None
        # Absolute: look up the module directly.
        if not module:
            return None
        # Check if the module is in the repository (as a MODULE symbol or
        # as a file).
        if module in self._symbols_by_qname and self._symbols_by_qname[module].kind == SymbolKind.MODULE:
            return module
        # Check by file path: a file ``foo/bar.py`` corresponds to module
        # ``foo.bar``.
        candidate_file = module.replace(".", "/") + ".py"
        candidate_pkg_file = module.replace(".", "/") + "/__init__.py"
        for f in self._modules:
            if f == candidate_file or f == candidate_pkg_file:
                return module
        return None

    def _package_of_file(self, file_rel: str) -> str:
        """Compute the Python package name of a file.

        ``foo/bar/baz.py`` → ``foo.bar``
        ``foo/bar/__init__.py`` → ``foo.bar``

        Returns ``""`` if the file is at the repository root.
        """
        # Normalise to forward slashes
        f = file_rel.replace("\\", "/")
        if f.startswith("./"):
            f = f[2:]
        # Strip the file extension
        if f.endswith("/__init__.py"):
            f = f[: -len("/__init__.py")]
        elif f.endswith(".py"):
            f = f[:-3]
        elif f.endswith("/__init__.pyi"):
            f = f[: -len("/__init__.pyi")]
        elif f.endswith(".pyi"):
            f = f[:-4]
        # Convert path separators to dots
        return f.replace("/", ".")

    def _module_qualified_name(self, file_rel: str) -> str:
        """The module qualified name for a file (matches ``_package_of_file``)."""
        return self._package_of_file(file_rel)

    def _module_qname_for_symbol(self, sym: Symbol) -> str:
        """The module qualified name that a symbol lives in."""
        # If the symbol has an enclosing class, strip the class and the
        # method name off; otherwise strip the symbol name off.
        qname = sym.qualified_name
        if sym.enclosing_class:
            # qualified_name = module_qname.ClassName.method
            if sym.enclosing_class + "." + sym.name == qname:
                # Strip ClassName.method
                idx = qname.rfind("." + sym.name)
                if idx > 0:
                    cls_qname = qname[:idx]
                    idx2 = cls_qname.rfind(".")
                    if idx2 > 0:
                        return cls_qname[:idx2]
                    return ""
            return sym.enclosing_class.rsplit(".", 1)[0] if "." in sym.enclosing_class else ""
        # No enclosing class: qualified_name = module_qname.name
        idx = qname.rfind(".")
        if idx > 0:
            return qname[:idx]
        return ""

    # ── call-site indexing ────────────────────────────────────────────

    def _index_call_sites(
        self,
        tree: ast.Module,
        file_rel: str,
        module_qname: str,
        info: _ModuleInfo,
    ) -> None:
        # Build a parent map ONCE per file. Without this, the per-call-site
        # enclosing-function search would be O(N²) per file (N = AST size).
        parent_map: dict[int, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parent_map[id(child)] = parent
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            caller = self._enclosing_function_qualified_name(
                node, tree, module_qname, parent_map
            )
            if caller is None:
                # Call at module level — record with a synthetic caller
                # so we can still track entrypoint→sink at module scope.
                caller = module_qname or "<module>"
            try:
                callee_text = ast.unparse(node.func)
            except Exception:
                callee_text = "<unknown>"
            arg_texts: list[str] = []
            for a in node.args:
                try:
                    arg_texts.append(ast.unparse(a))
                except Exception:
                    arg_texts.append("<unknown>")
            kwarg_pairs: list[tuple[str, str]] = []
            for kw in node.keywords:
                if kw.arg is None:
                    continue
                try:
                    kwarg_pairs.append((kw.arg, ast.unparse(kw.value)))
                except Exception:
                    kwarg_pairs.append((kw.arg, "<unknown>"))
            site = CallSite(
                location=SourceLocation(file_rel, node.lineno, node.col_offset),
                callee_text=callee_text,
                caller_qualified_name=caller,
                arg_texts=tuple(arg_texts),
                kwarg_pairs=tuple(kwarg_pairs),
            )
            self._call_sites_by_caller.setdefault(caller, []).append(site)

    def _enclosing_function_qualified_name(
        self,
        target: ast.AST,
        tree: ast.Module,
        module_qname: str,
        parent_map: dict[int, ast.AST] | None = None,
    ) -> str | None:
        """Find the qualified name of the function enclosing ``target``.

        If ``parent_map`` is provided (mapping ``id(node)`` to its parent
        in ``tree``), the lookup is O(depth) instead of O(N).
        """
        target_line = getattr(target, "lineno", None)
        if target_line is None:
            return None

        candidate: ast.FunctionDef | ast.AsyncFunctionDef | None = None
        if parent_map is not None:
            # Walk up the parent chain — pick the first FunctionDef /
            # AsyncFunctionDef ancestor (which is the innermost enclosing
            # function).
            current: ast.AST | None = target
            while current is not None:
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    candidate = current
                    break
                current = parent_map.get(id(current))
        else:
            # Fallback: linear scan over the tree (O(N) per call).
            best_range: tuple[int, int] | None = None
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                start = node.lineno
                end = getattr(node, "end_lineno", None) or start
                if start <= target_line <= end:
                    # Pick the innermost (smallest range).
                    if best_range is None or (end - start) < (best_range[1] - best_range[0]):
                        candidate = node
                        best_range = (start, end)
        if candidate is None:
            return None
        # Build the qualified name. Find enclosing classes by walking up
        # the parent chain (or linear scan if no parent map).
        class_chain: list[str] = []
        if parent_map is not None:
            current = parent_map.get(id(candidate))
            while current is not None:
                if isinstance(current, ast.ClassDef):
                    class_chain.append(current.name)
                current = parent_map.get(id(current))
            # parent_map gives innermost-first; reverse for outer-to-inner
            # (the index only uses the innermost for now).
        else:
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                start = node.lineno
                end = getattr(node, "end_lineno", None) or start
                if start <= candidate.lineno <= end and node is not candidate:
                    class_chain.append(node.name)
        if class_chain:
            innermost = class_chain[0]
            qname = (
                f"{module_qname}.{innermost}.{candidate.name}"
                if module_qname
                else f"{innermost}.{candidate.name}"
            )
        else:
            qname = (
                f"{module_qname}.{candidate.name}" if module_qname else candidate.name
            )
        return qname

    # ── resolution API ────────────────────────────────────────────────

    def resolve_call_target(
        self,
        callee_node: ast.AST,
        in_module: str,
    ) -> tuple[Symbol | None, ResolutionCertainty, str]:
        """Resolve a callee AST node to a symbol.

        Returns ``(symbol, certainty, qualified_name_attempt)``:

        - If the callee is a bare name (``run()``) and the module binds
          that name to a local definition or an imported symbol, returns
          ``(symbol, RESOLVED, qualified_name)``.
        - If the callee is an attribute access (``self.foo()``,
          ``obj.method()``) we resolve what we can. ``self.foo`` inside
          a class method resolves to the class's ``foo`` method
          (RESOLVED) if the class is in the index.
        - If the callee is a dynamically-computed name
          (``getattr(x, name)()``), returns
          ``(None, UNRESOLVED, "")``.
        - If the callee name matches exactly one repository symbol but
          we cannot prove it is in scope (e.g. a bare ``run()`` with no
          binding and one repository-level ``run``), returns
          ``(symbol, HEURISTIC, qualified_name)``.
        - If multiple symbols share the name, returns
          ``(None, UNRESOLVED, "")`` to avoid false positives.

        ``in_module`` is the qualified module name of the file the call
        appears in (used to look up that module's bindings).
        """
        # Lazy finalization — callers may invoke resolve_call_target
        # without going through RepositoryIndex.build.
        if not self._finalized:
            self.finalize()

        # Find the module info for `in_module`
        info: _ModuleInfo | None = None
        for mod in self._modules.values():
            if mod.qualified_name == in_module:
                info = mod
                break
        if info is None:
            # Fallback: maybe in_module is a file path
            info = self._modules.get(in_module)
        if info is None:
            return (None, ResolutionCertainty.UNRESOLVED, "")

        # Bare name call: ``run()``
        if isinstance(callee_node, ast.Name):
            name = callee_node.id
            # 1. Local binding (from imports or local definitions)
            if name in info.bindings:
                rt = info.bindings[name]
                if rt.symbol is not None:
                    return (rt.symbol, rt.certainty, rt.qualified_name)
                # The binding is to a module — the callee must be an attribute,
                # not a bare name. UNRESOLVED.
                return (None, ResolutionCertainty.UNRESOLVED, rt.qualified_name)
            # 2. Local symbol (defined in this module)
            if name in info.local_symbols:
                return (info.local_symbols[name], ResolutionCertainty.RESOLVED, info.local_symbols[name].qualified_name)
            # 3. Heuristic: exactly one repository symbol has this name
            candidates = self._symbols_by_local_name.get(name, [])
            if len(candidates) == 1:
                return (candidates[0], ResolutionCertainty.HEURISTIC, candidates[0].qualified_name)
            if len(candidates) > 1:
                # Ambiguous — cannot resolve without scope evidence.
                return (None, ResolutionCertainty.UNRESOLVED, "")
            # 4. No match — unresolved.
            return (None, ResolutionCertainty.UNRESOLVED, "")

        # Attribute call: ``self.foo()``, ``obj.method()``, ``pkg.mod.fn()``
        if isinstance(callee_node, ast.Attribute):
            attr = callee_node.attr
            value = callee_node.value
            # ``self.foo()`` inside a method → resolve to the class's method
            if isinstance(value, ast.Name) and value.id == "self":
                # We need to know the enclosing class. Look it up via the
                # call site's caller qualified name. We don't have it
                # directly here, so we search for a method with name `attr`
                # in any class in this module. If exactly one match,
                # RESOLVED; if multiple, HEURISTIC; if zero, UNRESOLVED.
                matches: list[Symbol] = []
                for sym in info.local_symbols.values():
                    if sym.name == attr and sym.enclosing_class:
                        # Only consider methods whose enclosing class lives
                        # in this module.
                        if sym.enclosing_class.startswith(info.qualified_name):
                            matches.append(sym)
                if len(matches) == 1:
                    return (matches[0], ResolutionCertainty.RESOLVED, matches[0].qualified_name)
                if len(matches) > 1:
                    return (None, ResolutionCertainty.HEURISTIC, "")
                return (None, ResolutionCertainty.UNRESOLVED, "")

            # ``obj.method()`` where obj is a Name bound to a class instance
            # via local analysis — out of scope for this version.
            # ``pkg.mod.fn()`` where pkg is imported — try to resolve.
            if isinstance(value, ast.Attribute):
                try:
                    base_text = ast.unparse(value)
                except Exception:
                    base_text = ""
                # Look for an import binding the base
                # e.g. ``import a.b`` → binding ``a`` → module a.b → method ``b.fn``
                # This is a best-effort 1-hop resolution.
                head = value
                while isinstance(head, ast.Attribute):
                    head = head.value
                if isinstance(head, ast.Name):
                    binding = info.bindings.get(head.id)
                    if binding and binding.certainty == ResolutionCertainty.RESOLVED:
                        # Build the candidate qualified name
                        parts = [binding.module_path]
                        n: ast.AST = value
                        chain: list[str] = []
                        while isinstance(n, ast.Attribute):
                            chain.append(n.attr)
                            n = n.value
                        chain.reverse()
                        candidate_qname = ".".join(parts + chain + [attr])
                        sym = self._symbols_by_qname.get(candidate_qname)
                        if sym is not None:
                            return (sym, ResolutionCertainty.RESOLVED, candidate_qname)
                        return (None, ResolutionCertainty.UNRESOLVED, candidate_qname)
            elif isinstance(value, ast.Name):
                # ``obj.fn()`` — obj is a Name. May be a local var bound
                # to a class instance (out of scope) or an imported module.
                binding = info.bindings.get(value.id)
                if binding and binding.certainty == ResolutionCertainty.RESOLVED:
                    candidate_qname = f"{binding.module_path}.{attr}"
                    sym = self._symbols_by_qname.get(candidate_qname)
                    if sym is not None:
                        return (sym, ResolutionCertainty.RESOLVED, candidate_qname)
                    return (None, ResolutionCertainty.HEURISTIC, candidate_qname)

            # ``SubprocessRunner().run()`` — receiver is a Call to a
            # constructor. We don't track receiver types here (that's
            # ``sinks.py``'s job); for call-graph purposes we treat
            # attribute calls on unresolvable receivers as UNRESOLVED.
            return (None, ResolutionCertainty.UNRESOLVED, "")

        # Subscript / other forms — UNRESOLVED
        return (None, ResolutionCertainty.UNRESOLVED, "")

    def lookup_symbol(self, qualified_name: str) -> Symbol | None:
        return self._symbols_by_qname.get(qualified_name)

    def call_sites_in(self, caller_qualified_name: str) -> list[CallSite]:
        return self._call_sites_by_caller.get(caller_qualified_name, [])

    def get_ast(self, file_rel: str) -> tuple[str, ast.Module] | None:
        return self._ast_cache.get(file_rel)

    # ── construction helpers ──────────────────────────────────────────

    @classmethod
    def build(
        cls,
        root: Path | str,
        *,
        files: list[str] | None = None,
    ) -> "RepositoryIndex":
        """Build an index by walking a repository root.

        Only ``.py`` files are indexed. ``files`` may be passed to
        restrict to a specific file list (e.g. the engine's collected
        files). Files are parsed defensively; parse errors are skipped
        silently — the index is best-effort and missing files do not
        affect resolution correctness for files that did parse.
        """
        root_path = Path(root)
        idx = cls(root=root_path)

        if files is None:
            file_paths = sorted(p for p in root_path.rglob("*.py"))
        else:
            file_paths = [Path(f) for f in files]

        for fp in file_paths:
            try:
                rel = (
                    str(fp.relative_to(root_path))
                    if root_path.is_dir()
                    else fp.name
                )
                rel = rel.replace("\\", "/")
            except ValueError:
                rel = fp.name
            try:
                source = fp.read_text(encoding="utf-8-sig")
                tree = ast.parse(source, filename=str(fp))
            except (UnicodeDecodeError, OSError, SyntaxError):
                continue
            idx.add_file(rel, source, tree)
        idx.finalize()
        return idx
