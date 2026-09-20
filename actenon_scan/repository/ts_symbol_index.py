"""TypeScript/JavaScript repository symbol index.

Mirrors the Python :class:`actenon_scan.repository.symbol_index.RepositoryIndex`
API for TS/JS source files. Uses tree-sitter-typescript (already a dependency
via the ``[typescript]`` extra — the same extra that powers
:mod:`actenon_scan.detectors.typescript`).

Scope (foundation slice only):

- Extract functions, methods, classes from TS/JS files
- Extract ESM imports (``import x from 'y'``, ``import { z } from 'y'``)
  and CJS requires (``const x = require('y')``)
- Extract call sites (callee text, caller qualified name, args)
- Resolve a callee to a symbol with explicit RESOLVED / HEURISTIC / UNRESOLVED

What this module deliberately does NOT do (future slices):

- Build the TS call graph (no :func:`build_call_graph` for TS yet)
- Compute transitive reachability over TS call sites
- Propagate effect summaries or taint across TS files
- Model TypeScript generics or overloads
- Extract decorator metadata

Resolution model
----------------

TS imports are resolved conservatively. We distinguish:

- :data:`ResolutionCertainty.RESOLVED` — the import unambiguously identifies
  a single repository-local target. ``import { g } from './mod'`` resolves to
  ``mod.g`` if ``mod.ts`` exists and defines ``g``.

- :data:`ResolutionCertainty.HEURISTIC` — the import could be local or
  external and we have no symbol evidence either way (e.g.
  ``import foo from 'react'`` with no local ``react.ts``).

- :data:`ResolutionCertainty.UNRESOLVED` — a dynamic import form
  (``await import(name)``, ``obj[name]()``) where the target name is not a
  string literal or computed statically.

The third state is *explicit*. Nothing labelled ``UNRESOLVED`` is ever
silently treated as either local or external. This is the same invariant
the Python index upholds; the TS index inherits it verbatim.
"""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator


# Re-use the same ResolutionCertainty + SourceLocation from symbol_index.
# This keeps the two indexes type-compatible (the same enum values, the
# same location shape) — the engine and call-graph layer can mix Python
# and TS symbols without translating certainty states.
from actenon_scan.repository.symbol_index import (
    ResolutionCertainty,
    SourceLocation,
)


# ---------------------------------------------------------------------------
# tree-sitter language handles (lazy)
# ---------------------------------------------------------------------------

_TS_LANGUAGE = None  # type: ignore[assignment]
_TSX_LANGUAGE = None  # type: ignore[assignment]


def _ensure_languages() -> tuple[object, object]:
    """Lazily build and cache the TS and TSX language handles.

    The ``[typescript]`` extra is required. If it is not installed, this
    raises ImportError — callers (tests, the engine) must check
    :func:`actenon_scan.detectors.typescript.is_typescript_extra_available`
    before constructing a TSRepositoryIndex.

    Note: the installed ``tree_sitter_typescript`` package only exposes
    ``language_typescript()`` and ``language_tsx()`` — there is no separate
    JavaScript grammar handle. The TypeScript grammar accepts plain
    JavaScript as a subset (the existing TS detector relies on this same
    behaviour), so ``.js``/``.jsx``/``.mjs``/``.cjs`` files are parsed with
    the TS grammar and ``.tsx``/``.jsx`` with the TSX grammar.
    """
    global _TS_LANGUAGE, _TSX_LANGUAGE
    if _TS_LANGUAGE is None:
        import tree_sitter_typescript as tsjs
        from tree_sitter import Language

        _TS_LANGUAGE = Language(tsjs.language_typescript())
        _TSX_LANGUAGE = Language(tsjs.language_tsx())
    return _TS_LANGUAGE, _TSX_LANGUAGE


def _parser_for(file_rel: str):
    """Return a configured tree-sitter Parser for the given file extension."""
    from tree_sitter import Parser

    ts_lang, tsx_lang = _ensure_languages()
    suffix = Path(file_rel).suffix.lower()
    if suffix in (".tsx", ".jsx"):
        return Parser(tsx_lang)
    # .ts, .mts, .cts, .js, .mjs, .cjs, and unknown → TS grammar.
    return Parser(ts_lang)


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


class TSSymbolKind(str, Enum):
    """What kind of TS/JS symbol this is.

    Values are strings so that they serialise to JSON naturally. Mirrors
    :class:`actenon_scan.repository.symbol_index.SymbolKind`.
    """

    MODULE = "module"
    FUNCTION = "function"
    ARROW_FUNCTION = "arrow_function"
    CLASS = "class"
    METHOD = "method"


@dataclass(frozen=True)
class TSSymbol:
    """A TS/JS symbol defined in the repository.

    ``qualified_name`` is the canonical dotted path
    (``pkg.mod.ClassName.method_name``). It is the key the future TS call
    graph will use to resolve call sites — same convention as the Python
    :class:`Symbol`.
    """

    name: str
    kind: TSSymbolKind
    qualified_name: str
    location: SourceLocation
    # For methods: the enclosing class qualified name (``module.ClassName``).
    # For functions/arrow functions/classes: empty.
    enclosing_class: str = ""
    # Decorators as textual form. Populated but not interpreted by this
    # foundation slice — left for the reachability layer.
    decorators: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_function_like(self) -> bool:
        return self.kind in (
            TSSymbolKind.FUNCTION,
            TSSymbolKind.ARROW_FUNCTION,
            TSSymbolKind.METHOD,
        )


@dataclass(frozen=True)
class TSResolvedTarget:
    """Where a TS import / CJS require / dynamic-import actually points.

    Mirrors :class:`actenon_scan.repository.symbol_index.ResolvedTarget`.
    """

    qualified_name: str
    certainty: ResolutionCertainty
    symbol: TSSymbol | None = None
    # Canonical module path (without the symbol inside it). For
    # ``import { g } from './mod'`` → ``"mod"``.
    module_path: str = ""


@dataclass(frozen=True)
class TSImport:
    """An ESM import, CJS require, or dynamic import in a TS/JS file.

    ``kind`` is one of:

    - ``"esm_default"``    — ``import foo from 'mod'``
    - ``"esm_named"``      — ``import { foo } from 'mod'`` (one per specifier)
    - ``"esm_namespace"``  — ``import * as ns from 'mod'``
    - ``"cjs"``             — ``const foo = require('mod')``
    - ``"dynamic"``        — ``await import('mod')`` (or ``import('mod')``)

    For aliased named imports (``import { foo as bar }``), ``imported_name``
    is the original (``"foo"``) and ``bound_name`` is the local (``"bar"``).
    For non-aliased forms, ``imported_name == bound_name``.
    """

    kind: str
    # The literal module specifier as it appears in the import. For
    # ``import { g } from './mod'`` this is ``"./mod"`` (NOT resolved).
    module: str
    # The local bound name in the importing module's namespace.
    bound_name: str
    # The original imported name. For named imports this is the source-side
    # name; for default / namespace / cjs / dynamic it equals bound_name.
    imported_name: str
    location: SourceLocation
    resolved_target: TSResolvedTarget | None = None


@dataclass(frozen=True)
class TSCallSite:
    """A single call expression observed in a TS/JS function body.

    Mirrors :class:`actenon_scan.repository.symbol_index.CallSite` shape
    (subset — TS doesn't need separate kwarg tracking at the foundation
    slice; kwargs are flattened into ``arg_texts``).
    """

    location: SourceLocation
    # The textual callee (e.g. ``"g"``, ``"this.foo"``, ``"obj.method"``,
    # ``"obj[name]"``). Used for diagnostics and for
    # :meth:`TSRepositoryIndex.resolve_call_target` input.
    callee_text: str
    # The qualified name of the function that *contains* this call site.
    caller_qualified_name: str
    # The argument expressions as text, for downstream taint analysis.
    arg_texts: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Per-module bookkeeping
# ---------------------------------------------------------------------------


@dataclass
class _TSModuleInfo:
    """Per-module bookkeeping in the index.

    Mirrors :class:`actenon_scan.repository.symbol_index._ModuleInfo`.
    """

    path: str
    qualified_name: str
    # bound name → resolved target (covers local defs, ESM/CJS imports,
    # and dynamic imports). Bare-name call resolution consults this first.
    bindings: dict[str, TSResolvedTarget] = field(default_factory=dict)
    # local symbol name → Symbol (for same-module bare-name resolution)
    local_symbols: dict[str, TSSymbol] = field(default_factory=dict)
    # qualified_name → Symbol (cross-module lookups)
    symbols_by_qname: dict[str, TSSymbol] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# TSRepositoryIndex
# ---------------------------------------------------------------------------


class TSRepositoryIndex:
    """A repository-level index of TS/JS source files.

    Build one with :meth:`build` (or :meth:`add_file` incrementally), then
    use :meth:`resolve_call_target` to translate a callee's textual form
    into a :class:`TSSymbol` (or ``None``, with explicit certainty).
    """

    def __init__(self, root: Path | str | None = None) -> None:
        # The repository root. May be ``None`` when scanning a single
        # file (in which case all symbols live in the file's basename).
        self.root: Path | None = Path(root) if root is not None else None

        # file_rel → _TSModuleInfo
        self._modules: dict[str, _TSModuleInfo] = {}

        # qualified_name → TSSymbol (canonical index)
        self._symbols_by_qname: dict[str, TSSymbol] = {}

        # local_name → list of TSSymbol (for bare-name call resolution)
        self._symbols_by_local_name: dict[str, list[TSSymbol]] = {}

        # call sites (in insertion order)
        self._call_sites: list[TSCallSite] = []

        # imports (in insertion order)
        self._imports: list[TSImport] = []

        # Pending imports → (TSImport, _TSModuleInfo). Resolved in finalize()
        # so that cross-file imports resolve regardless of file-add order
        # (mirrors the Python index's deferred-resolution design).
        self._pending_imports: list[tuple[TSImport, _TSModuleInfo]] = []
        self._finalized: bool = False

    # ── properties ───────────────────────────────────────────────────

    @property
    def files(self) -> list[str]:
        """All files in the index, sorted for determinism."""
        return sorted(self._modules.keys())

    @property
    def symbols(self) -> list[TSSymbol]:
        """All symbols in the index (insertion order preserved by dict)."""
        return list(self._symbols_by_qname.values())

    @property
    def call_sites(self) -> list[TSCallSite]:
        """All call sites in insertion order."""
        return list(self._call_sites)

    @property
    def imports(self) -> list[TSImport]:
        """All imports in insertion order."""
        return list(self._imports)

    # ── building ──────────────────────────────────────────────────────

    def add_file(self, file_rel: str, source: str) -> None:
        """Parse a TS/JS file with tree-sitter-typescript and index it.

        ``file_rel`` is the path relative to the repository root (or the
        basename when there is no root). ``source`` is the file's text.

        Symbols and call sites are registered immediately. Import
        resolution is deferred to :meth:`finalize` so that cross-file
        imports (e.g. ``main.ts`` importing from ``./mod``) resolve
        correctly regardless of the order files were added.
        """
        parser = _parser_for(file_rel)
        source_bytes = source.encode("utf-8")
        tree = parser.parse(source_bytes)
        self._finalized = False

        module_qname = self._module_qualified_name(file_rel)
        info = _TSModuleInfo(path=file_rel, qualified_name=module_qname)
        self._modules[file_rel] = info

        # Walk the CST once, extracting symbols, imports, and call sites.
        # We track the enclosing class context via parent pointers (TS
        # tree-sitter nodes expose .parent) for method qualified names.
        self._index_symbols(tree.root_node, file_rel, module_qname, info, source_bytes)
        self._index_imports(tree.root_node, file_rel, module_qname, info, source_bytes)
        self._index_call_sites(tree.root_node, file_rel, module_qname, info, source_bytes)

    def finalize(self) -> None:
        """Resolve all deferred imports.

        After this is called, each module's ``bindings`` map is fully
        populated and cross-file resolution works. Idempotent — calling
        twice is a no-op. :meth:`build` calls this automatically before
        returning.
        """
        if self._finalized:
            return
        for imp, info in self._pending_imports:
            self._resolve_import(imp, info)
        # Update each TSImport with its resolved target for diagnostics.
        for imp, info in self._pending_imports:
            bound = imp.bound_name
            if bound and bound in info.bindings:
                # Frozen dataclass → rebuild.
                object.__setattr__(imp, "resolved_target", info.bindings[bound])
        self._pending_imports.clear()
        self._finalized = True

    # ── symbol indexing ───────────────────────────────────────────────

    def _index_symbols(
        self,
        root_node,
        file_rel: str,
        module_qname: str,
        info: _TSModuleInfo,
        source_bytes: bytes,
    ) -> None:
        """Walk the CST and register functions, classes, methods, arrows."""
        for node in _walk(root_node):
            if node.type == "function_declaration":
                name = _first_child_text(node, "identifier", source_bytes)
                if not name:
                    continue
                # A function_declaration inside a class body is rare in TS
                # (methods are method_definition), but be defensive.
                enclosing = self._enclosing_class_qname(node, module_qname, source_bytes)
                if enclosing:
                    qname = f"{enclosing}.{name}"
                    kind = TSSymbolKind.METHOD
                else:
                    qname = f"{module_qname}.{name}" if module_qname else name
                    kind = TSSymbolKind.FUNCTION
                self._register_symbol(
                    TSSymbol(
                        name=name,
                        kind=kind,
                        qualified_name=qname,
                        location=_loc(file_rel, node),
                        enclosing_class=enclosing,
                    ),
                    info,
                )
            elif node.type == "class_declaration":
                cls_name = _class_name(node, source_bytes)
                if not cls_name:
                    continue
                qname = (
                    f"{module_qname}.{cls_name}" if module_qname else cls_name
                )
                self._register_symbol(
                    TSSymbol(
                        name=cls_name,
                        kind=TSSymbolKind.CLASS,
                        qualified_name=qname,
                        location=_loc(file_rel, node),
                    ),
                    info,
                )
            elif node.type == "method_definition":
                name = _first_child_text(node, "property_identifier", source_bytes)
                if not name:
                    continue
                enclosing = self._enclosing_class_qname(node, module_qname, source_bytes)
                qname = f"{enclosing}.{name}" if enclosing else (
                    f"{module_qname}.{name}" if module_qname else name
                )
                self._register_symbol(
                    TSSymbol(
                        name=name,
                        kind=TSSymbolKind.METHOD,
                        qualified_name=qname,
                        location=_loc(file_rel, node),
                        enclosing_class=enclosing,
                    ),
                    info,
                )
            elif node.type == "variable_declarator":
                # `const f = () => {}` → ARROW_FUNCTION symbol named f.
                value = node.child_by_field_name("value")
                if value is None or value.type != "arrow_function":
                    continue
                name_node = node.child_by_field_name("name")
                if name_node is None or name_node.type != "identifier":
                    continue
                name = _node_text(name_node, source_bytes)
                if not name:
                    continue
                # Arrow functions assigned inside a class body are rare;
                # treat them as METHODS if inside a class, ARROW_FUNCTION
                # otherwise.
                enclosing = self._enclosing_class_qname(node, module_qname, source_bytes)
                if enclosing:
                    qname = f"{enclosing}.{name}"
                    kind = TSSymbolKind.METHOD
                else:
                    qname = (
                        f"{module_qname}.{name}" if module_qname else name
                    )
                    kind = TSSymbolKind.ARROW_FUNCTION
                self._register_symbol(
                    TSSymbol(
                        name=name,
                        kind=kind,
                        qualified_name=qname,
                        location=_loc(file_rel, node),
                        enclosing_class=enclosing,
                    ),
                    info,
                )

    def _enclosing_class_qname(
        self,
        node,
        module_qname: str,
        source_bytes: bytes,
    ) -> str:
        """Walk up parents to find the enclosing class's qualified name.

        Returns ``""`` if the node is not inside a class body.
        """
        parent = node.parent
        while parent is not None:
            if parent.type == "class_declaration":
                cls_name = _class_name(parent, source_bytes)
                if cls_name:
                    return (
                        f"{module_qname}.{cls_name}" if module_qname else cls_name
                    )
            # Also handle anonymous class expressions assigned to a
            # const: `const C = class { ... }`. The class itself has no
            # name; we use the bound name.
            if parent.type == "class":
                # Walk up to find a variable_declarator that gives it a name.
                gp = parent.parent
                if gp is not None and gp.type == "variable_declarator":
                    name_node = gp.child_by_field_name("name")
                    if name_node is not None and name_node.type == "identifier":
                        bound = _node_text(name_node, source_bytes)
                        return (
                            f"{module_qname}.{bound}" if module_qname else bound
                        )
            parent = parent.parent
        return ""

    def _register_symbol(self, sym: TSSymbol, info: _TSModuleInfo) -> None:
        self._symbols_by_qname[sym.qualified_name] = sym
        info.symbols_by_qname[sym.qualified_name] = sym
        # local_symbols keys by simple name — last-writer wins, which is
        # the same convention as the Python index. Multiple definitions
        # of the same name in one module are uncommon and tracked by the
        # global _symbols_by_local_name map for ambiguity detection.
        info.local_symbols[sym.name] = sym
        self._symbols_by_local_name.setdefault(sym.name, []).append(sym)

    # ── import indexing ──────────────────────────────────────────────

    def _index_imports(
        self,
        root_node,
        file_rel: str,
        module_qname: str,
        info: _TSModuleInfo,
        source_bytes: bytes,
    ) -> None:
        """Walk the CST and register ESM imports, CJS requires, dynamic imports."""
        for node in _walk(root_node):
            if node.type == "import_statement":
                self._index_esm_import(node, file_rel, module_qname, info, source_bytes)
            elif node.type in ("lexical_declaration", "variable_declaration"):
                self._index_var_decl_imports(node, file_rel, module_qname, info, source_bytes)
            elif node.type == "call_expression":
                # Dynamic import: `import('mod')` parses as call_expression
                # with function=import keyword.
                self._index_dynamic_import_call(node, file_rel, module_qname, info, source_bytes)

    def _index_esm_import(
        self,
        node,
        file_rel: str,
        module_qname: str,
        info: _TSModuleInfo,
        source_bytes: bytes,
    ) -> None:
        # import_statement children: [import, import_clause?, from, string, ;]
        # The string child is the module specifier.
        module = ""
        for c in node.children:
            if c.type == "string":
                module = _strip_string_literal(_node_text(c, source_bytes))
                break
        clause = None
        for c in node.children:
            if c.type == "import_clause":
                clause = c
                break
        if clause is None:
            return
        line = node.start_point[0] + 1
        col = node.start_point[1]
        for child in clause.children:
            if child.type == "identifier":
                # import foo from 'mod' — default import.
                bound = _node_text(child, source_bytes)
                imp = TSImport(
                    kind="esm_default",
                    module=module,
                    bound_name=bound,
                    imported_name=bound,
                    location=SourceLocation(file_rel, line, col),
                )
                self._imports.append(imp)
                self._pending_imports.append((imp, info))
            elif child.type == "namespace_import":
                # import * as ns from 'mod'
                bound = ""
                for sub in child.children:
                    if sub.type == "identifier":
                        bound = _node_text(sub, source_bytes)
                        break
                if not bound:
                    continue
                imp = TSImport(
                    kind="esm_namespace",
                    module=module,
                    bound_name=bound,
                    imported_name=bound,
                    location=SourceLocation(file_rel, line, col),
                )
                self._imports.append(imp)
                self._pending_imports.append((imp, info))
            elif child.type == "named_imports":
                # import { foo } from 'mod'  /  import { foo as bar } from 'mod'
                for sub in child.children:
                    if sub.type != "import_specifier":
                        continue
                    idents = [s for s in sub.children if s.type == "identifier"]
                    if not idents:
                        continue
                    if len(idents) == 1:
                        imported = bound = _node_text(idents[0], source_bytes)
                    else:
                        # import_specifier: imported_name (first ident), `as`, bound_name (second ident)
                        imported = _node_text(idents[0], source_bytes)
                        bound = _node_text(idents[1], source_bytes)
                    imp = TSImport(
                        kind="esm_named",
                        module=module,
                        bound_name=bound,
                        imported_name=imported,
                        location=SourceLocation(file_rel, line, col),
                    )
                    self._imports.append(imp)
                    self._pending_imports.append((imp, info))

    def _index_var_decl_imports(
        self,
        node,
        file_rel: str,
        module_qname: str,
        info: _TSModuleInfo,
        source_bytes: bytes,
    ) -> None:
        """Handle `const x = require('mod')` and `const x = await import('mod')`.

        The latter is the dynamic-import form bound to a name; we record it
        with kind="dynamic" and resolve to UNRESOLVED (the dynamic import
        target cannot be statically known — even when the module spec is a
        literal string, ES module exports are resolved at runtime, and the
        bound name is to a Promise, not to a single symbol).
        """
        for decl in node.children:
            if decl.type != "variable_declarator":
                continue
            name_node = decl.child_by_field_name("name")
            if name_node is None or name_node.type != "identifier":
                continue
            bound = _node_text(name_node, source_bytes)
            value = decl.child_by_field_name("value")
            if value is None:
                continue
            # Unwrap await_expression (for `await import(...)`). The
            # await_expression's named child is the awaited expression.
            inner = value
            if inner.type == "await_expression":
                inner = None
                for c in value.children:
                    if c.type != "await":
                        inner = c
                        break
            if inner is None or inner.type != "call_expression":
                continue
            func = inner.child_by_field_name("function")
            if func is None:
                continue
            func_text = _node_text(func, source_bytes)
            if func_text == "require":
                # CJS: const x = require('mod')
                module = _first_string_arg(inner, source_bytes)
                if module is None:
                    continue
                imp = TSImport(
                    kind="cjs",
                    module=module,
                    bound_name=bound,
                    imported_name=bound,
                    location=SourceLocation(file_rel, decl.start_point[0] + 1, decl.start_point[1]),
                )
                self._imports.append(imp)
                self._pending_imports.append((imp, info))
            elif func.type == "import":
                # Dynamic: const x = (await) import('mod')
                module = _first_string_arg(inner, source_bytes)
                module_str = module if module is not None else ""
                imp = TSImport(
                    kind="dynamic",
                    module=module_str,
                    bound_name=bound,
                    imported_name=bound,
                    location=SourceLocation(file_rel, decl.start_point[0] + 1, decl.start_point[1]),
                )
                self._imports.append(imp)
                self._pending_imports.append((imp, info))

    def _index_dynamic_import_call(
        self,
        node,
        file_rel: str,
        module_qname: str,
        info: _TSModuleInfo,
        source_bytes: bytes,
    ) -> None:
        """Handle a bare `import('mod')` not assigned to a binding.

        E.g. ``import('mod').then(m => m.foo())``. We record the import
        with bound_name="" (no local binding) — so a call to ``foo`` later
        in the same file still resolves as UNRESOLVED (the binding doesn't
        enter the module's namespace).
        """
        func = node.child_by_field_name("function")
        if func is None or func.type != "import":
            return
        # If this dynamic import is the value (directly or via
        # await_expression) of a variable_declarator, it was already
        # recorded by _index_var_decl_imports — don't double-count.
        parent = node.parent
        if parent is not None and parent.type == "await_expression":
            parent = parent.parent
        if parent is not None and parent.type == "variable_declarator":
            return
        module = _first_string_arg(node, source_bytes)
        module_str = module if module is not None else ""
        imp = TSImport(
            kind="dynamic",
            module=module_str,
            bound_name="",  # no local binding
            imported_name="",
            location=SourceLocation(file_rel, node.start_point[0] + 1, node.start_point[1]),
        )
        self._imports.append(imp)
        # No pending import — no binding to populate.

    def _resolve_import(self, imp: TSImport, info: _TSModuleInfo) -> None:
        """Populate ``info.bindings[bound_name]`` for one import.

        Called by :meth:`finalize` after all files are indexed.
        """
        if not imp.bound_name:
            # Dynamic import with no binding — nothing to populate.
            return
        if imp.kind == "dynamic":
            # Dynamic imports are ALWAYS UNRESOLVED, even when the module
            # specifier is a literal string. This is the explicit
            # "no false assurance" invariant: a dynamic import's target
            # is determined at runtime, not at static-analysis time.
            info.bindings[imp.bound_name] = TSResolvedTarget(
                qualified_name=imp.module or "",
                certainty=ResolutionCertainty.UNRESOLVED,
                symbol=None,
                module_path=imp.module,
            )
            return
        # ESM/CJS: try to resolve the module spec to a local file.
        module_qname = self._resolve_module_path(imp.module, info.path)
        if module_qname is None:
            # External (e.g. "react", "child_process") or unresolvable
            # relative path. HEURISTIC — we cannot prove it's local or
            # external without package metadata, and we never silently
            # treat it as local.
            info.bindings[imp.bound_name] = TSResolvedTarget(
                qualified_name=imp.module,
                certainty=ResolutionCertainty.HEURISTIC,
                symbol=None,
                module_path=imp.module,
            )
            return
        # Module is local. For named imports, look up the imported_name
        # in the target module's symbols. For default/namespace/cjs, the
        # binding is to the module itself (we cannot statically resolve
        # the default export to a single symbol).
        if imp.kind == "esm_named":
            target_sym = self._find_symbol_in_module(module_qname, imp.imported_name)
            if target_sym is not None:
                info.bindings[imp.bound_name] = TSResolvedTarget(
                    qualified_name=target_sym.qualified_name,
                    certainty=ResolutionCertainty.RESOLVED,
                    symbol=target_sym,
                    module_path=module_qname,
                )
            else:
                # Local module but symbol not found (could be dynamically
                # defined, re-exported, or genuinely missing). HEURISTIC
                # to the qualified name.
                info.bindings[imp.bound_name] = TSResolvedTarget(
                    qualified_name=f"{module_qname}.{imp.imported_name}"
                    if module_qname else imp.imported_name,
                    certainty=ResolutionCertainty.HEURISTIC,
                    symbol=None,
                    module_path=module_qname,
                )
        else:
            # esm_default, esm_namespace, cjs — bind to the module.
            info.bindings[imp.bound_name] = TSResolvedTarget(
                qualified_name=module_qname,
                certainty=ResolutionCertainty.HEURISTIC,
                symbol=None,
                module_path=module_qname,
            )

    def _find_symbol_in_module(self, module_qname: str, name: str) -> TSSymbol | None:
        """Look for a symbol named ``name`` whose qualified_name starts with
        ``module_qname.`` and ends with ``.name`` (or is exactly ``name``).
        """
        prefix = f"{module_qname}." if module_qname else ""
        for sym in self._symbols_by_qname.values():
            if sym.name != name:
                continue
            if prefix and sym.qualified_name == f"{prefix}{name}":
                return sym
            # Also accept class.method matches where sym is a method whose
            # enclosing_class is module_qname.ClassName (qualified_name =
            # module_qname.ClassName.name). The prefix check covers that.
            if prefix and sym.qualified_name.startswith(prefix):
                # Ensure the LAST segment is `name`.
                if sym.qualified_name.rsplit(".", 1)[-1] == name:
                    return sym
        return None

    def _resolve_module_path(self, module_spec: str, in_file_rel: str) -> str | None:
        """Resolve a TS module specifier to a local module qualified name.

        Handles ``./x``, ``../x``, ``/x`` (rare in TS) — anything else
        (``"react"``, ``"child_process"``) is treated as external.

        Returns ``None`` if the module is not present in the index.
        """
        if not module_spec:
            return None
        if module_spec.startswith("./"):
            rel = module_spec[2:]
        elif module_spec.startswith("../"):
            # Compute by joining with the importer's directory and normalising.
            importer_dir = posixpath.dirname(in_file_rel.replace("\\", "/"))
            rel = posixpath.normpath(posixpath.join(importer_dir, module_spec))
        elif module_spec.startswith("/"):
            rel = module_spec.lstrip("/")
        else:
            # Bare specifier — external (node_modules / npm package).
            return None
        # Normalise: strip any remaining leading ./  and convert / to .
        rel = rel.replace("\\", "/")
        if rel.startswith("./"):
            rel = rel[2:]
        # Look up by module_qname (file_rel → qname strips the extension).
        candidate_qname = rel.replace("/", ".")
        # Direct lookup: does a module with this qname exist?
        for info in self._modules.values():
            if info.qualified_name == candidate_qname:
                return info.qualified_name
        # Also try suffix matches (e.g. an index.ts in a directory).
        # We don't model TS path resolution fully (moduleResolution config);
        # this is a foundation slice. Direct match is sufficient for the
        # tests we need to pass and the foundation contract.
        return None

    # ── call-site indexing ───────────────────────────────────────────

    def _index_call_sites(
        self,
        root_node,
        file_rel: str,
        module_qname: str,
        info: _TSModuleInfo,
        source_bytes: bytes,
    ) -> None:
        """Walk the CST and register every call_expression.

        Skips call_expressions whose function is the ``import`` keyword
        (those are dynamic imports, recorded separately by
        :meth:`_index_imports`).
        """
        for node in _walk(root_node):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None:
                continue
            # Skip dynamic import calls — they're imports, not calls.
            if func.type == "import":
                continue
            # Skip CJS require() calls — they're imports, recorded separately
            # by _index_var_decl_imports (when bound to a name) and don't
            # represent an interprocedural call.
            if func.type == "identifier" and _node_text(func, source_bytes) == "require":
                continue
            callee_text = _callee_text(func, source_bytes)
            caller = self._enclosing_function_qualified_name(
                node, module_qname, source_bytes
            )
            if caller is None:
                # Module-level call — synthetic caller so we still track
                # entrypoint→sink at module scope (mirrors Python index).
                caller = module_qname or "<module>"
            arg_texts = _arg_texts(node, source_bytes)
            self._call_sites.append(
                TSCallSite(
                    location=_loc(file_rel, node),
                    callee_text=callee_text,
                    caller_qualified_name=caller,
                    arg_texts=arg_texts,
                )
            )

    def _enclosing_function_qualified_name(
        self,
        node,
        module_qname: str,
        source_bytes: bytes,
    ) -> str | None:
        """Find the qualified name of the function enclosing ``node``.

        Walks up the parent chain (tree-sitter nodes expose ``.parent``)
        and returns the first enclosing ``function_declaration``,
        ``method_definition``, or named arrow function's qualified name.
        Returns ``None`` for module-level calls.
        """
        parent = node.parent
        while parent is not None:
            if parent.type == "function_declaration":
                name = _first_child_text(parent, "identifier", source_bytes)
                if not name:
                    return None
                enclosing = self._enclosing_class_qname(parent, module_qname, source_bytes)
                if enclosing:
                    return f"{enclosing}.{name}"
                return f"{module_qname}.{name}" if module_qname else name
            if parent.type == "method_definition":
                name = _first_child_text(parent, "property_identifier", source_bytes)
                if not name:
                    return None
                enclosing = self._enclosing_class_qname(parent, module_qname, source_bytes)
                if enclosing:
                    return f"{enclosing}.{name}"
                return f"{module_qname}.{name}" if module_qname else name
            if parent.type == "arrow_function":
                # Named arrow: `const f = () => { g(); }`. The arrow's parent
                # is a variable_declarator whose name is `f`.
                gp = parent.parent
                if gp is not None and gp.type == "variable_declarator":
                    name_node = gp.child_by_field_name("name")
                    if name_node is not None and name_node.type == "identifier":
                        name = _node_text(name_node, source_bytes)
                        enclosing = self._enclosing_class_qname(parent, module_qname, source_bytes)
                        if enclosing:
                            return f"{enclosing}.{name}"
                        return f"{module_qname}.{name}" if module_qname else name
                # Anonymous arrow function — skip; keep walking up so we
                # find the enclosing named function (or fall off to module).
            parent = parent.parent
        return None

    # ── resolution API ───────────────────────────────────────────────

    def resolve_call_target(
        self,
        callee_text: str,
        in_module: str,
    ) -> tuple[TSSymbol | None, ResolutionCertainty, str]:
        """Resolve a callee (textual form) to a symbol.

        Returns ``(symbol, certainty, qualified_name_attempt)``:

        - If the callee is a bare name (``g``) and the module binds that
          name to a local definition or an imported symbol, returns
          ``(symbol, RESOLVED, qualified_name)``.
        - If the callee is ``this.method()`` or ``obj.method()``, we resolve
          what we can. ``this.foo`` inside a method of a class resolves to
          the class's ``foo`` method (RESOLVED) if the class is in the index.
        - If the callee is a dynamically-computed form (subscript
          ``obj[name]()`` or any form containing ``[``), returns
          ``(None, UNRESOLVED, "")``.
        - If the callee name matches exactly one repository symbol but we
          cannot prove it is in scope, returns
          ``(symbol, HEURISTIC, qualified_name)``.
        - If multiple symbols share the name, returns
          ``(None, UNRESOLVED, "")`` to avoid false positives.

        ``in_module`` is the qualified module name of the file the call
        appears in (used to look up that module's bindings). May also be
        a file path — the resolver falls back to path lookup.
        """
        # Lazy finalize so callers can resolve without going through build().
        if not self._finalized:
            self.finalize()

        info = self._module_info(in_module)
        if info is None:
            return (None, ResolutionCertainty.UNRESOLVED, "")

        if not callee_text:
            return (None, ResolutionCertainty.UNRESOLVED, "")

        # Dynamic / computed-key forms: subscript_expression callee
        # ``obj[name]()`` → callee_text contains "[".
        if "[" in callee_text:
            return (None, ResolutionCertainty.UNRESOLVED, "")

        # Bare-name call: ``g()``
        if "." not in callee_text:
            name = callee_text
            # 1. Local binding (from imports or local definitions)
            if name in info.bindings:
                rt = info.bindings[name]
                if rt.symbol is not None:
                    return (rt.symbol, rt.certainty, rt.qualified_name)
                # Binding is to a module or dynamic — bare-name call cannot
                # invoke a module. UNRESOLVED.
                return (None, ResolutionCertainty.UNRESOLVED, rt.qualified_name)
            # 2. Local symbol defined in this module
            if name in info.local_symbols:
                sym = info.local_symbols[name]
                return (sym, ResolutionCertainty.RESOLVED, sym.qualified_name)
            # 3. Heuristic: exactly one repository symbol has this name.
            candidates = self._symbols_by_local_name.get(name, [])
            if len(candidates) == 1:
                return (candidates[0], ResolutionCertainty.HEURISTIC, candidates[0].qualified_name)
            if len(candidates) > 1:
                # Ambiguous — never silently resolve.
                return (None, ResolutionCertainty.UNRESOLVED, "")
            # 4. No match.
            return (None, ResolutionCertainty.UNRESOLVED, "")

        # Dotted callee: ``this.foo``, ``obj.method``, ``pkg.mod.fn``
        parts = callee_text.split(".")
        head = parts[0]
        attr = parts[-1]
        # ``this.foo()`` inside a method → resolve to a method on a class
        # in this module whose enclosing class lives in this module.
        if head == "this":
            matches: list[TSSymbol] = []
            for sym in info.local_symbols.values():
                if sym.name == attr and sym.enclosing_class:
                    if not info.qualified_name or sym.enclosing_class.startswith(
                        info.qualified_name + "."
                    ) or sym.enclosing_class == info.qualified_name:
                        matches.append(sym)
            if len(matches) == 1:
                return (matches[0], ResolutionCertainty.RESOLVED, matches[0].qualified_name)
            if len(matches) > 1:
                return (None, ResolutionCertainty.HEURISTIC, "")
            return (None, ResolutionCertainty.UNRESOLVED, "")

        # Other dotted forms: ``obj.method``, ``pkg.mod.fn``.
        # If head is bound to an import / module, attempt resolution.
        if head in info.bindings:
            binding = info.bindings[head]
            if binding.certainty == ResolutionCertainty.RESOLVED and binding.symbol is not None:
                # Direct binding to a symbol — but a dotted call on a symbol
                # is unusual; only useful for static class methods. Treat
                # the qualified_name as binding.qualified_name + remaining parts.
                remaining = ".".join(parts[1:])
                candidate_qname = (
                    f"{binding.qualified_name}.{remaining}"
                    if binding.qualified_name and remaining
                    else binding.qualified_name or remaining
                )
                sym = self._symbols_by_qname.get(candidate_qname)
                if sym is not None:
                    return (sym, ResolutionCertainty.RESOLVED, candidate_qname)
                return (None, ResolutionCertainty.UNRESOLVED, candidate_qname)
            if binding.module_path:
                # Build a candidate qualified_name from the module path +
                # the dotted tail.
                remaining = ".".join(parts[1:])
                candidate_qname = (
                    f"{binding.module_path}.{remaining}"
                    if binding.module_path and remaining
                    else binding.module_path or remaining
                )
                sym = self._symbols_by_qname.get(candidate_qname)
                if sym is not None:
                    return (sym, ResolutionCertainty.RESOLVED, candidate_qname)
                # Module resolved but symbol not found → HEURISTIC.
                if binding.certainty == ResolutionCertainty.HEURISTIC:
                    return (None, ResolutionCertainty.HEURISTIC, candidate_qname)
                return (None, ResolutionCertainty.UNRESOLVED, candidate_qname)
        # Head is an unbound identifier — could be a local var, a global,
        # or an object. We don't track receiver types in this foundation
        # slice. Fall back to a repository-wide name match for the final
        # segment (HEURISTIC) when exactly one symbol shares that name.
        candidates = self._symbols_by_local_name.get(attr, [])
        if len(candidates) == 1:
            return (candidates[0], ResolutionCertainty.HEURISTIC, candidates[0].qualified_name)
        return (None, ResolutionCertainty.UNRESOLVED, "")

    def lookup_symbol(self, qualified_name: str) -> TSSymbol | None:
        """Look up a symbol by its qualified name."""
        return self._symbols_by_qname.get(qualified_name)

    def call_sites_in(self, caller_qualified_name: str) -> list[TSCallSite]:
        """All call sites whose caller has this qualified name.

        Mirrors :meth:`RepositoryIndex.call_sites_in` from the Python index.
        """
        return [s for s in self._call_sites if s.caller_qualified_name == caller_qualified_name]

    # ── helpers ──────────────────────────────────────────────────────

    def _module_info(self, in_module: str) -> _TSModuleInfo | None:
        """Find the _TSModuleInfo for a qualified name or file path."""
        for info in self._modules.values():
            if info.qualified_name == in_module:
                return info
        # Fallback: maybe in_module is a file path.
        return self._modules.get(in_module)

    def _module_qualified_name(self, file_rel: str) -> str:
        """Compute the module qualified name for a file.

        ``src/mod.ts`` → ``src.mod``
        ``index.ts``    → ``index``

        Mirrors :meth:`RepositoryIndex._module_qualified_name` (Python's
        equivalent strips ``.py`` and converts ``/`` to ``.``).
        """
        f = file_rel.replace("\\", "/")
        if f.startswith("./"):
            f = f[2:]
        # Strip known TS/JS extensions.
        for ext in (".tsx", ".ts", ".mts", ".cts", ".jsx", ".js", ".mjs", ".cjs"):
            if f.endswith(ext):
                f = f[: -len(ext)]
                break
        return f.replace("/", ".")

    # ── construction helpers ──────────────────────────────────────────

    @classmethod
    def build(
        cls,
        root: Path | str,
        *,
        files: list[Path] | None = None,
    ) -> "TSRepositoryIndex":
        """Build an index by walking a repository root.

        Only TS/JS files are indexed (``.ts``, ``.tsx``, ``.js``, ``.jsx``,
        ``.mts``, ``.cts``, ``.mjs``, ``.cjs``). ``files`` may be passed to
        restrict to a specific file list. Files are parsed defensively;
        parse errors are skipped silently — the index is best-effort.
        """
        root_path = Path(root)
        idx = cls(root=root_path)
        exts = {".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"}

        if files is None:
            file_paths = sorted(
                p for p in root_path.rglob("*") if p.suffix.lower() in exts
            )
        else:
            file_paths = [Path(f) for f in files]

        for fp in file_paths:
            try:
                rel = (
                    str(fp.relative_to(root_path))
                    if root_path.is_dir() else fp.name
                )
                rel = rel.replace("\\", "/")
            except ValueError:
                rel = fp.name
            try:
                source = fp.read_text(encoding="utf-8-sig")
            except (UnicodeDecodeError, OSError):
                continue
            try:
                idx.add_file(rel, source)
            except Exception:
                # Parse error — skip this file, keep indexing others.
                continue
        idx.finalize()
        return idx


# ---------------------------------------------------------------------------
# Tree-walk / text-extraction helpers (module-level)
# ---------------------------------------------------------------------------


def _walk(node) -> Iterator:
    """Pre-order generator: yield node then all descendants."""
    yield node
    for child in node.children:
        yield from _walk(child)


def _node_text(node, source_bytes: bytes) -> str:
    """Decode a node's byte range from source."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _first_child_text(node, type_: str, source_bytes: bytes) -> str:
    """Text of the first direct child of ``type_``, or empty string."""
    for c in node.children:
        if c.type == type_:
            return _node_text(c, source_bytes)
    return ""


def _class_name(node, source_bytes: bytes) -> str:
    """Extract the name of a class_declaration or class node."""
    # Try field access first (TS grammar: class_declaration has a `name` field).
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return _node_text(name_node, source_bytes)
    # Fallback: scan children for type_identifier / identifier.
    for c in node.children:
        if c.type in ("type_identifier", "identifier"):
            return _node_text(c, source_bytes)
    return ""


def _strip_string_literal(text: str) -> str:
    """Strip quotes from a string literal text."""
    t = text.strip()
    if len(t) >= 2 and t[0] in "\"'`" and t[-1] == t[0]:
        return t[1:-1]
    return t


def _first_string_arg(call_node, source_bytes: bytes) -> str | None:
    """Return the first string argument's literal value, or None."""
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return None
    for child in args.children:
        if child.type == "string":
            return _strip_string_literal(_node_text(child, source_bytes))
    return None


def _arg_texts(call_node, source_bytes: bytes) -> tuple[str, ...]:
    """Extract the textual form of each argument of a call_expression."""
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return ()
    out: list[str] = []
    for child in args.children:
        if child.type in ("(", ")", ","):
            continue
        out.append(_node_text(child, source_bytes))
    return tuple(out)


def _callee_text(func_node, source_bytes: bytes) -> str:
    """Compute the textual callee from a call_expression's function child.

    - ``identifier`` (bare name)         → ``"g"``
    - ``member_expression`` (``this.foo``, ``obj.method``) → dotted
    - ``subscript_expression`` (``obj[name]``)             → literal text
    - ``call_expression`` (``foo()()``)                    → literal text
    """
    if func_node.type == "identifier":
        return _node_text(func_node, source_bytes)
    if func_node.type == "member_expression":
        # Build a dotted form: object.property or chain thereof.
        return _member_expression_dotted(func_node, source_bytes)
    # Fallback: literal text of the callee node.
    return _node_text(func_node, source_bytes)


def _member_expression_dotted(node, source_bytes: bytes) -> str:
    """Build a dotted callee text from a member_expression.

    ``this.foo``           → ``"this.foo"``
    ``obj.method``         → ``"obj.method"``
    ``stripe.refunds.create`` → ``"stripe.refunds.create"``
    ``obj["x"]``           → handled by subscript branch (not member_expression).
    """
    parts: list[str] = []
    current = node
    while current is not None and current.type == "member_expression":
        prop_node = current.child_by_field_name("property")
        obj_node = current.child_by_field_name("object")
        if prop_node is None or obj_node is None:
            break
        # property is a property_identifier (or similar) — its text is the name.
        parts.insert(0, _node_text(prop_node, source_bytes))
        if obj_node.type == "identifier":
            parts.insert(0, _node_text(obj_node, source_bytes))
            current = None
        elif obj_node.type == "member_expression":
            current = obj_node
            continue
        elif obj_node.type == "this":
            parts.insert(0, "this")
            current = None
        else:
            # Complex receiver (call_expression, subscript_expression, etc.)
            # — prepend its literal text and stop.
            parts.insert(0, _node_text(obj_node, source_bytes))
            current = None
    return ".".join(parts)


def _loc(file_rel: str, node) -> SourceLocation:
    """Build a SourceLocation for a tree-sitter node."""
    return SourceLocation(
        file=file_rel,
        line=node.start_point[0] + 1,  # 1-indexed, like the Python index
        col=node.start_point[1],
    )


__all__ = [
    "TSSymbolKind",
    "TSSymbol",
    "TSImport",
    "TSResolvedTarget",
    "TSCallSite",
    "TSRepositoryIndex",
]
