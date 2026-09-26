"""Go repository symbol index.

Mirrors the TypeScript :class:`actenon_scan.repository.ts_symbol_index.TSRepositoryIndex`
API for Go source files. Uses tree-sitter-go (already a dependency via
the ``[go]`` extra — the same extra that powers
:mod:`actenon_scan.detectors.go`).

Scope (cross-file reachability slice only):

- Parse ``.go`` files with tree-sitter-go.
- Index package-level functions (``function_declaration``) and
  receiver methods (``method_declaration``).
- Index call sites (callee text, caller qualified name, args).
- Resolve a callee to a symbol with explicit RESOLVED / HEURISTIC /
  UNRESOLVED certainty.

What this module deliberately does NOT do (future slices):

- Build a full Go call graph (no ``build_call_graph`` for Go yet).
- Track receiver variable types precisely. For ``m.ExecThing(...)``
  calls, we resolve by method-name match across the index (HEURISTIC
  when exactly one method with that name exists in the package; this
  is the same shape as the TS index's dotted-call resolution).
- Model Go generics or interfaces.
- Track Go build tags or cgo.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator

# Re-use the same ResolutionCertainty + SourceLocation from symbol_index
# so the Go index is type-compatible with the Python and TS indexes.
from actenon_scan.repository.symbol_index import (
    ResolutionCertainty,
    SourceLocation,
)


# ---------------------------------------------------------------------------
# tree-sitter language handles (lazy)
# ---------------------------------------------------------------------------

_GO_LANGUAGE = None  # type: ignore[assignment]


def _ensure_language() -> object:
    """Lazily build and cache the Go language handle.

    The ``[go]`` extra is required. Callers must check
    :func:`actenon_scan.detectors.go.is_go_extra_available` before
    constructing a GoRepositoryIndex.
    """
    global _GO_LANGUAGE
    if _GO_LANGUAGE is None:
        import tree_sitter_go as tsgo
        from tree_sitter import Language

        _GO_LANGUAGE = Language(tsgo.language())
    return _GO_LANGUAGE


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


class GoSymbolKind(str, Enum):
    FUNCTION = "function"
    METHOD = "method"


@dataclass(frozen=True)
class GoSymbol:
    """A Go symbol defined in the repository.

    ``qualified_name`` is ``"<package>.<func_name>`` for package-level
    functions and ``"<package>.<ReceiverType>.<method_name>"`` for
    methods. The package is derived from the file's relative path
    (mirrors the TS index's module-qualified-name convention).
    """

    name: str
    kind: GoSymbolKind
    qualified_name: str
    location: SourceLocation
    # For methods: the receiver type name (e.g. ``"Manager"``). For
    # functions: empty.
    receiver_type: str = ""
    # The file (relative path) this symbol lives in.
    file: str = ""

    @property
    def is_function_like(self) -> bool:
        return self.kind in (GoSymbolKind.FUNCTION, GoSymbolKind.METHOD)


@dataclass(frozen=True)
class GoCallSite:
    """A single call expression observed in a Go function body.

    Mirrors :class:`TSCallSite` shape (callee text, caller qname, args).
    """

    location: SourceLocation
    callee_text: str
    caller_qualified_name: str
    arg_texts: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Per-package bookkeeping
# ---------------------------------------------------------------------------


@dataclass
class _GoPackageInfo:
    """Per-package bookkeeping (mirrors _TSModuleInfo)."""

    path: str
    qualified_name: str
    # local symbol name → list of GoSymbol (for same-package bare-name
    # call resolution — Go permits multiple methods with the same name
    # across different receivers in the same package).
    local_symbols: dict[str, list[GoSymbol]] = field(default_factory=dict)
    # qualified_name → GoSymbol (cross-package lookups)
    symbols_by_qname: dict[str, GoSymbol] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# GoRepositoryIndex
# ---------------------------------------------------------------------------


class GoRepositoryIndex:
    """A repository-level index of Go source files.

    Build one with :meth:`build` (or :meth:`add_file` incrementally),
    then use :meth:`resolve_call_target` to translate a callee's textual
    form into a :class:`GoSymbol` (or ``None``, with explicit certainty).
    """

    def __init__(self, root: Path | str | None = None) -> None:
        self.root: Path | None = Path(root) if root is not None else None
        # file_rel → _GoPackageInfo
        self._packages: dict[str, _GoPackageInfo] = {}
        # qualified_name → GoSymbol (canonical index)
        self._symbols_by_qname: dict[str, GoSymbol] = {}
        # method name → list of GoSymbol (for dotted-call resolution by
        # method-name-only match — the same HEURISTIC pattern the TS
        # index uses for dotted callees).
        self._methods_by_name: dict[str, list[GoSymbol]] = {}
        # function name → list of GoSymbol (for bare-name call resolution
        # within the same package).
        self._functions_by_name: dict[str, list[GoSymbol]] = {}
        # call sites (in insertion order)
        self._call_sites: list[GoCallSite] = []
        self._finalized: bool = False

    # ── properties ───────────────────────────────────────────────────

    @property
    def files(self) -> list[str]:
        return sorted(self._packages.keys())

    @property
    def symbols(self) -> list[GoSymbol]:
        return list(self._symbols_by_qname.values())

    @property
    def call_sites(self) -> list[GoCallSite]:
        return list(self._call_sites)

    # ── construction ──────────────────────────────────────────────────

    def add_file(self, file_rel: str, source: str | bytes) -> None:
        """Index a single Go source file.

        ``file_rel`` is the file's path relative to the repository root
        (using forward slashes). ``source`` is the file's text or bytes.
        """
        if isinstance(source, str):
            source_bytes = source.encode("utf-8")
        else:
            source_bytes = source
            source = source.decode("utf-8", errors="replace")

        try:
            lang = _ensure_language()
            from tree_sitter import Parser
            parser = Parser(lang)
            tree = parser.parse(source_bytes)
        except Exception:
            # Defensive: any parse error is non-fatal.
            return

        package_qname = self._package_qualified_name(file_rel)
        info = _GoPackageInfo(path=file_rel, qualified_name=package_qname)
        self._packages[file_rel] = info

        # Index symbols (functions + methods).
        self._index_symbols(tree.root_node, file_rel, package_qname, info, source_bytes)
        # Index call sites.
        self._index_call_sites(tree.root_node, file_rel, package_qname, info, source_bytes)

    def finalize(self) -> None:
        """Mark the index as finalized. Currently a no-op since Go
        imports are package paths (not local symbol bindings like TS
        ESM/CJS imports)."""
        self._finalized = True

    @classmethod
    def build(
        cls,
        root: Path | str,
        *,
        files: list[Path] | None = None,
    ) -> "GoRepositoryIndex":
        """Build an index by walking a repository root.

        Only ``.go`` files are indexed. ``_test.go`` files are skipped
        (mirrors the engine's go-file collection). ``files`` may be
        passed to restrict to a specific file list (the engine's
        already-filtered go file list).
        """
        root_path = Path(root)
        idx = cls(root=root_path)

        if files is None:
            file_paths = sorted(
                p for p in root_path.rglob("*.go")
                if p.is_file() and not p.name.endswith("_test.go")
            )
        else:
            file_paths = [Path(f) for f in files if not Path(f).name.endswith("_test.go")]

        for fp in file_paths:
            try:
                rel = str(fp.relative_to(root_path)) if root_path.is_dir() else fp.name
                rel = rel.replace("\\", "/")
                source = fp.read_text(encoding="utf-8-sig")
                idx.add_file(rel, source)
            except (UnicodeDecodeError, OSError):
                continue
        idx.finalize()
        return idx

    # ── symbol indexing ──────────────────────────────────────────────

    def _index_symbols(
        self,
        root_node,
        file_rel: str,
        package_qname: str,
        info: _GoPackageInfo,
        source_bytes: bytes,
    ) -> None:
        for node in _walk(root_node):
            if node.type == "function_declaration":
                name = _first_child_text(node, "name", source_bytes)
                if not name:
                    continue
                qname = f"{package_qname}.{name}" if package_qname else name
                sym = GoSymbol(
                    name=name,
                    kind=GoSymbolKind.FUNCTION,
                    qualified_name=qname,
                    location=_loc(file_rel, node),
                    receiver_type="",
                    file=file_rel,
                )
                self._register_symbol(sym, info)
            elif node.type == "method_declaration":
                name = _first_child_text(node, "name", source_bytes)
                if not name:
                    continue
                # Receiver is the first child of the "receiver" field.
                receiver_type = _receiver_type_name(node, source_bytes)
                if receiver_type:
                    if package_qname:
                        qname = f"{package_qname}.{receiver_type}.{name}"
                    else:
                        # Root-level Go file (no directory path). Use
                        # "ReceiverType.method" without a leading dot.
                        qname = f"{receiver_type}.{name}"
                else:
                    qname = f"{package_qname}.{name}" if package_qname else name
                sym = GoSymbol(
                    name=name,
                    kind=GoSymbolKind.METHOD,
                    qualified_name=qname,
                    location=_loc(file_rel, node),
                    receiver_type=receiver_type,
                    file=file_rel,
                )
                self._register_symbol(sym, info)

    def _register_symbol(self, sym: GoSymbol, info: _GoPackageInfo) -> None:
        # Canonical index by qualified_name. If a duplicate qname is
        # encountered (rare in Go — would require two methods with the
        # same name on the same receiver type in the same package),
        # the first registration wins and subsequent ones are silently
        # dropped (mirrors TS index behaviour).
        if sym.qualified_name in self._symbols_by_qname:
            return
        self._symbols_by_qname[sym.qualified_name] = sym
        info.symbols_by_qname[sym.qualified_name] = sym

        # Index by local name for bare-name resolution (same-package).
        info.local_symbols.setdefault(sym.name, []).append(sym)

        # Repository-wide index by name (for cross-package dotted-call
        # resolution — used by resolve_call_target for the HEURISTIC
        # case where the receiver variable's type can't be proven).
        if sym.kind == GoSymbolKind.FUNCTION:
            self._functions_by_name.setdefault(sym.name, []).append(sym)
        else:  # METHOD
            self._methods_by_name.setdefault(sym.name, []).append(sym)

    # ── call-site indexing ───────────────────────────────────────────

    def _index_call_sites(
        self,
        root_node,
        file_rel: str,
        package_qname: str,
        info: _GoPackageInfo,
        source_bytes: bytes,
    ) -> None:
        for node in _walk(root_node):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None:
                continue
            callee_text = _node_text(func, source_bytes)
            caller = self._enclosing_function_qualified_name(
                node, package_qname, source_bytes
            )
            if caller is None:
                # Module-level call (Go: package-level init or var init).
                caller = package_qname or "<package>"
            arg_texts = _arg_texts(node, source_bytes)
            self._call_sites.append(
                GoCallSite(
                    location=_loc(file_rel, node),
                    callee_text=callee_text,
                    caller_qualified_name=caller,
                    arg_texts=arg_texts,
                )
            )

    def _enclosing_function_qualified_name(
        self,
        node,
        package_qname: str,
        source_bytes: bytes,
    ) -> str | None:
        parent = node.parent
        while parent is not None:
            if parent.type == "function_declaration":
                name = _first_child_text(parent, "name", source_bytes)
                if not name:
                    return None
                return f"{package_qname}.{name}" if package_qname else name
            if parent.type == "method_declaration":
                name = _first_child_text(parent, "name", source_bytes)
                if not name:
                    return None
                recv = _receiver_type_name(parent, source_bytes)
                if recv:
                    if package_qname:
                        return f"{package_qname}.{recv}.{name}"
                    return f"{recv}.{name}"
                return f"{package_qname}.{name}" if package_qname else name
            parent = parent.parent
        return None

    # ── resolution API ────────────────────────────────────────────────

    def resolve_call_target(
        self,
        callee_text: str,
        in_module: str,
    ) -> tuple[GoSymbol | None, ResolutionCertainty, str]:
        """Resolve a callee (textual form) to a Go symbol.

        Returns ``(symbol, certainty, qualified_name_attempt)``:

        - Bare name (``foo``): look up among same-package functions
          named ``foo``. Exactly one match → RESOLVED. Multiple or
          zero → UNRESOLVED (conservative; never silently pick one).
        - Dotted callee (``recv.Method``): strip the receiver variable
          name and look up methods named ``Method`` across the whole
          index. Exactly one match → HEURISTIC (we can't prove the
          receiver variable's type matches the method's receiver type
          without type information, but for the common single-Manager
          case this is correct). Multiple matches → UNRESOLVED.
        - Computed form (subscript, slice, etc.): UNRESOLVED.
        """
        if not self._finalized:
            self.finalize()

        if not callee_text:
            return (None, ResolutionCertainty.UNRESOLVED, "")

        # Dynamic / computed-key forms contain "[".
        if "[" in callee_text:
            return (None, ResolutionCertainty.UNRESOLVED, "")

        # Bare-name call: ``foo()``
        if "." not in callee_text:
            name = callee_text
            info = self._module_info(in_module)
            if info is not None:
                candidates = info.local_symbols.get(name, [])
                if len(candidates) == 1:
                    return (candidates[0], ResolutionCertainty.RESOLVED,
                            candidates[0].qualified_name)
                if len(candidates) > 1:
                    return (None, ResolutionCertainty.UNRESOLVED, "")
            # Heuristic: exactly one repository-wide function has this name.
            repo_candidates = self._functions_by_name.get(name, [])
            if len(repo_candidates) == 1:
                return (repo_candidates[0], ResolutionCertainty.HEURISTIC,
                        repo_candidates[0].qualified_name)
            return (None, ResolutionCertainty.UNRESOLVED, "")

        # Dotted callee: ``recv.Method`` (or ``pkg.Func``).
        parts = callee_text.split(".")
        attr = parts[-1]

        # Try as a method name first (HEURISTIC — receiver type
        # inference is not done in this slice).
        method_candidates = self._methods_by_name.get(attr, [])
        if len(method_candidates) == 1:
            return (method_candidates[0], ResolutionCertainty.HEURISTIC,
                    method_candidates[0].qualified_name)
        # Try as a package-qualified function name (e.g. "fmt.Println"
        # — won't be in our index, but check anyway).
        func_candidates = self._functions_by_name.get(attr, [])
        if len(func_candidates) == 1:
            return (func_candidates[0], ResolutionCertainty.HEURISTIC,
                    func_candidates[0].qualified_name)
        if len(method_candidates) > 1 or len(func_candidates) > 1:
            return (None, ResolutionCertainty.UNRESOLVED, "")
        return (None, ResolutionCertainty.UNRESOLVED, "")

    def lookup_symbol(self, qualified_name: str) -> GoSymbol | None:
        return self._symbols_by_qname.get(qualified_name)

    def call_sites_in(self, caller_qualified_name: str) -> list[GoCallSite]:
        return [s for s in self._call_sites if s.caller_qualified_name == caller_qualified_name]

    # ── helpers ──────────────────────────────────────────────────────

    def _module_info(self, in_module: str) -> _GoPackageInfo | None:
        for info in self._packages.values():
            if info.qualified_name == in_module:
                return info
        return self._packages.get(in_module)

    def _package_qualified_name(self, file_rel: str) -> str:
        """Compute the package qualified name for a Go file.

        Go has one package per directory (conventionally). We use the
        directory path (relative to root) as the package qualified name,
        so all .go files in the same directory share a package qname.

        ``pkg/github/issues.go`` → ``pkg.github``
        ``internal/mcp/server.go`` → ``internal.mcp``
        ``main.go`` → ``""`` (root-level)

        Note: this is a heuristic — Go's actual package name is declared
        with ``package X`` at the top of the file, not derived from the
        directory. We use the directory path for qualified_name
        determinism (mirrors the TS index's module-qualified-name
        convention).
        """
        f = file_rel.replace("\\", "/")
        if "/" in f:
            dir_path = f.rsplit("/", 1)[0]
            return dir_path.replace("/", ".")
        return ""

    def get_ast(self, file_rel: str) -> tuple[str, object] | None:
        """Re-parse and return the AST for a file (best-effort).

        Returns ``(source_text, tree_node)`` or ``None`` on parse error
        or unknown file. Used by downstream consumers that need to walk
        a specific function's body.
        """
        info = self._packages.get(file_rel)
        if info is None:
            return None
        try:
            from pathlib import Path as P
            p = P(self.root) / file_rel if self.root else P(file_rel)
            source = p.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            return None
        try:
            lang = _ensure_language()
            from tree_sitter import Parser
            parser = Parser(lang)
            tree = parser.parse(source.encode("utf-8"))
        except Exception:
            return None
        return (source, tree.root_node)


# ---------------------------------------------------------------------------
# tree-sitter helpers
# ---------------------------------------------------------------------------


def _walk(node) -> Iterator:
    yield node
    for child in node.children:
        yield from _walk(child)


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _first_child_text(node, field_name: str, source_bytes: bytes) -> str:
    child = node.child_by_field_name(field_name)
    if child is None:
        return ""
    return _node_text(child, source_bytes)


def _receiver_type_name(method_node, source_bytes: bytes) -> str:
    """Extract the receiver type name from a method_declaration.

    Go method_declaration has a ``receiver`` field that is a
    parameter_list like ``(m *Manager)`` or ``(s Server)``. We extract
    the type name, handling both pointer and value receivers.

    Returns ``""`` if no receiver type can be extracted.
    """
    receiver = method_node.child_by_field_name("receiver")
    if receiver is None:
        return ""
    # The receiver is a parameter_list. Walk its children for
    # parameter_declaration nodes; the type is in the "type" field.
    for child in receiver.children:
        if child.type == "parameter_declaration":
            type_node = child.child_by_field_name("type")
            if type_node is None:
                continue
            type_text = _node_text(type_node, source_bytes)
            # Strip leading "*" (pointer receiver).
            type_text = type_text.lstrip("*")
            return type_text
    return ""


def _arg_texts(call_node, source_bytes: bytes) -> tuple[str, ...]:
    """Return the textual form of each argument to a call_expression."""
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return ()
    texts: list[str] = []
    for child in args.children:
        if child is None:
            continue
        if child.type == "argument_list":
            # The arguments field is itself an argument_list; iterate
            # its children for the actual arguments.
            for arg in child.children:
                if arg is None:
                    continue
                # Skip punctuation.
                if arg.type in (",", "(", ")"):
                    continue
                texts.append(_node_text(arg, source_bytes))
            break
        if child.type in (",", "(", ")"):
            continue
        texts.append(_node_text(child, source_bytes))
    return tuple(texts)


def _loc(file_rel: str, node) -> SourceLocation:
    return SourceLocation(
        file=file_rel,
        line=node.start_point[0] + 1,  # 1-indexed
        col=node.start_point[1],
    )
