"""Unit tests for the TypeScript/JavaScript repository symbol index.

These tests exercise every resolution case the TS index claims to support,
including the explicit UNRESOLVED state for dynamic forms. They mirror the
shape of ``tests/repository/test_symbol_index_and_call_graph.py`` (the Python
index's tests) so the two indexes can be evolved in lockstep.

If the ``[typescript]`` extra is not installed (i.e. tree-sitter-typescript
is absent), every test is skipped — the analyser documents the extra as
optional for base installs.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from actenon_scan.detectors.typescript import is_typescript_extra_available
from actenon_scan.repository.symbol_index import ResolutionCertainty
from actenon_scan.repository.ts_symbol_index import (
    TSImport,
    TSSymbol,
    TSSymbolKind,
    TSRepositoryIndex,
)


_TS_AVAILABLE = is_typescript_extra_available()
_skip_if_no_ts = unittest.skipUnless(
    _TS_AVAILABLE,
    "tree-sitter-typescript not installed (pip install actenon-scan[typescript])",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _index_sources(files: dict[str, str]) -> TSRepositoryIndex:
    """Build an index from a {relpath: source} map, with a temp root.

    Mirrors the helper in ``tests/repository/test_symbol_index_and_call_graph.py``.
    """
    tmp = tempfile.mkdtemp()
    root = Path(tmp)
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    return TSRepositoryIndex.build(root)


def _module_qname_for(files: dict[str, str], file_rel: str) -> str:
    """Compute the module qname the index would assign to ``file_rel``.

    For ``app.ts`` → ``"app"``; for ``sub/mod.ts`` → ``"sub.mod"``.
    Tests use this so they don't hard-code qnames that depend on the
    temp dir layout.
    """
    f = file_rel.replace("\\", "/")
    if f.startswith("./"):
        f = f[2:]
    for ext in (".tsx", ".ts", ".mts", ".cts", ".jsx", ".js", ".mjs", ".cjs"):
        if f.endswith(ext):
            f = f[: -len(ext)]
            break
    return f.replace("/", ".")


# ---------------------------------------------------------------------------
# Symbol extraction tests
# ---------------------------------------------------------------------------


@_skip_if_no_ts
class TSSymbolExtractionTests(unittest.TestCase):
    def test_function_declaration_extracted(self) -> None:
        files = {"app.ts": "function f() {}\n"}
        idx = _index_sources(files)
        funcs = [s for s in idx.symbols if s.kind == TSSymbolKind.FUNCTION]
        self.assertEqual(len(funcs), 1)
        sym = funcs[0]
        self.assertEqual(sym.name, "f")
        self.assertEqual(sym.kind, TSSymbolKind.FUNCTION)
        self.assertEqual(sym.qualified_name, "app.f")
        self.assertEqual(sym.enclosing_class, "")

    def test_arrow_function_assignment_extracted(self) -> None:
        files = {"app.ts": "const arrow = () => 1;\n"}
        idx = _index_sources(files)
        arrows = [s for s in idx.symbols if s.kind == TSSymbolKind.ARROW_FUNCTION]
        self.assertEqual(len(arrows), 1)
        sym = arrows[0]
        self.assertEqual(sym.name, "arrow")
        self.assertEqual(sym.kind, TSSymbolKind.ARROW_FUNCTION)
        self.assertEqual(sym.qualified_name, "app.arrow")
        self.assertEqual(sym.enclosing_class, "")

    def test_class_with_methods_extracted(self) -> None:
        files = {"app.ts": "class C {\n  m() {}\n}\n"}
        idx = _index_sources(files)
        classes = [s for s in idx.symbols if s.kind == TSSymbolKind.CLASS]
        methods = [s for s in idx.symbols if s.kind == TSSymbolKind.METHOD]
        self.assertEqual(len(classes), 1)
        self.assertEqual(classes[0].name, "C")
        self.assertEqual(classes[0].qualified_name, "app.C")
        self.assertEqual(len(methods), 1)
        m = methods[0]
        self.assertEqual(m.name, "m")
        self.assertEqual(m.kind, TSSymbolKind.METHOD)
        self.assertEqual(m.qualified_name, "app.C.m")
        # enclosing_class is the class's qualified name (mirrors Python index).
        self.assertTrue(m.enclosing_class.endswith(".C"))
        self.assertEqual(m.enclosing_class, classes[0].qualified_name)


# ---------------------------------------------------------------------------
# Import extraction tests
# ---------------------------------------------------------------------------


@_skip_if_no_ts
class TSImportExtractionTests(unittest.TestCase):
    def test_esm_default_import(self) -> None:
        files = {"app.ts": "import foo from 'mod';\n"}
        idx = _index_sources(files)
        defaults = [i for i in idx.imports if i.kind == "esm_default"]
        self.assertEqual(len(defaults), 1)
        imp = defaults[0]
        self.assertEqual(imp.kind, "esm_default")
        self.assertEqual(imp.bound_name, "foo")
        self.assertEqual(imp.module, "mod")
        self.assertEqual(imp.imported_name, "foo")

    def test_esm_named_import(self) -> None:
        files = {"app.ts": "import { foo } from 'mod';\n"}
        idx = _index_sources(files)
        named = [i for i in idx.imports if i.kind == "esm_named"]
        self.assertEqual(len(named), 1)
        imp = named[0]
        self.assertEqual(imp.kind, "esm_named")
        self.assertEqual(imp.bound_name, "foo")
        self.assertEqual(imp.imported_name, "foo")
        self.assertEqual(imp.module, "mod")

    def test_esm_aliased_import(self) -> None:
        files = {"app.ts": "import { foo as bar } from 'mod';\n"}
        idx = _index_sources(files)
        named = [i for i in idx.imports if i.kind == "esm_named"]
        self.assertEqual(len(named), 1)
        imp = named[0]
        self.assertEqual(imp.bound_name, "bar")
        self.assertEqual(imp.imported_name, "foo")
        self.assertEqual(imp.module, "mod")

    def test_esm_namespace_import(self) -> None:
        files = {"app.ts": "import * as ns from 'mod';\n"}
        idx = _index_sources(files)
        ns_imports = [i for i in idx.imports if i.kind == "esm_namespace"]
        self.assertEqual(len(ns_imports), 1)
        imp = ns_imports[0]
        self.assertEqual(imp.kind, "esm_namespace")
        self.assertEqual(imp.bound_name, "ns")
        self.assertEqual(imp.module, "mod")

    def test_cjs_require(self) -> None:
        files = {"app.ts": "const foo = require('mod');\n"}
        idx = _index_sources(files)
        cjs_imports = [i for i in idx.imports if i.kind == "cjs"]
        self.assertEqual(len(cjs_imports), 1)
        imp = cjs_imports[0]
        self.assertEqual(imp.kind, "cjs")
        self.assertEqual(imp.bound_name, "foo")
        self.assertEqual(imp.module, "mod")


# ---------------------------------------------------------------------------
# Call-site extraction + resolution tests
# ---------------------------------------------------------------------------


@_skip_if_no_ts
class TSCallSiteAndResolutionTests(unittest.TestCase):
    def test_call_site_extraction(self) -> None:
        files = {"app.ts": "function f() { g(); }\n"}
        idx = _index_sources(files)
        # Exactly one call site (the bare g() call).
        self.assertEqual(len(idx.call_sites), 1)
        site = idx.call_sites[0]
        self.assertEqual(site.callee_text, "g")
        self.assertTrue(
            site.caller_qualified_name.endswith(".f"),
            f"expected caller to end with '.f', got {site.caller_qualified_name!r}",
        )

    def test_resolve_local_function_call(self) -> None:
        files = {"app.ts": "function f() { g(); }\nfunction g() {}\n"}
        idx = _index_sources(files)
        sym, certainty, qname = idx.resolve_call_target("g", "app")
        self.assertIsNotNone(sym)
        self.assertEqual(sym.name, "g")
        self.assertEqual(certainty, ResolutionCertainty.RESOLVED)
        self.assertEqual(qname, "app.g")

    def test_resolve_imported_call(self) -> None:
        files = {
            "main.ts": "import { g } from './mod';\nfunction f() { g(); }\n",
            "mod.ts": "export function g() {}\n",
        }
        idx = _index_sources(files)
        sym, certainty, qname = idx.resolve_call_target("g", "main")
        self.assertIsNotNone(sym)
        self.assertEqual(sym.name, "g")
        self.assertEqual(certainty, ResolutionCertainty.RESOLVED)
        # The resolved symbol is mod.g (cross-file).
        self.assertEqual(qname, "mod.g")
        self.assertEqual(sym.qualified_name, "mod.g")

    def test_dynamic_import_unresolved(self) -> None:
        files = {"app.ts": "const fn = await import('mod');\nfn();\n"}
        idx = _index_sources(files)
        sym, certainty, qname = idx.resolve_call_target("fn", "app")
        self.assertIsNone(sym)
        self.assertEqual(certainty, ResolutionCertainty.UNRESOLVED)
        # Also: the dynamic import is recorded as a TSImport with kind="dynamic".
        dynamics = [i for i in idx.imports if i.kind == "dynamic"]
        self.assertEqual(len(dynamics), 1)
        self.assertEqual(dynamics[0].bound_name, "fn")


if __name__ == "__main__":
    unittest.main()
