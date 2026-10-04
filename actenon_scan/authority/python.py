"""Python authority extractor.

Walks every Python module of a project, finds calls that perform consequential effects (HTTP requests,
LLM provider calls, GitHub operations through PyGithub, file writes and deletes, process execution, mail)
and evaluates *where* each effect goes with a small abstract interpreter:

* string literals, f-strings, ``+`` concatenation, ``str.format``/``%`` with known parts;
* module-level constants (also imported from other project modules) and single local assignments;
* ``self.<attr>`` set in ``__init__`` or the class body;
* ``os.environ[...]`` / ``os.getenv`` / ``os.environ.get`` from the project configuration supplied by the
  caller (``.env`` files and the environment at scan time), recorded as provenance; values of secret-looking
  variables are never inlined;
* parameters of local helper functions, resolved at each local call site (up to three levels). Parameters of
  functions registered as agent tools, or of functions referenced as values, stay dynamic.

Anything else is *unknown* and stays unknown: the resulting evidence is TEMPLATE (only whole path segments
unknown) or UNRESOLVED. Nothing is widened.
"""

from __future__ import annotations

import ast
import os
import warnings
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

from . import sdk
from .model import AuthorityEvidence, AuthorityReport, ResourceState, ValueSource
from .routes import HOLE, TEMPLATE_SEGMENT, classify_http

MAX_DEPTH = 3
_BUILD_FILES = {"setup.py", "noxfile.py", "fabfile.py", "tasks.py", "conf.py"}  # packaging/build tooling, not agent code
_EXCLUDED_DIRS = {"docs", ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox", ".nox",
                  "build", "dist", "site-packages", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".airlock"}

# ---------------------------------------------------------------------------------------------------------
# Value domain
# ---------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Unknown:
    reason: str
    name: str = ""
    param_of: str = ""  # function key when this is an unbound parameter
    source: ValueSource | None = None


@dataclass(frozen=True)
class Str:
    parts: tuple[str | Unknown, ...]
    sources: tuple[ValueSource, ...] = ()

    @staticmethod
    def lit(s: str, src: ValueSource | None = None) -> Str:
        return Str((s,), (src,) if src else ())

    def known(self) -> str | None:
        if all(isinstance(p, str) for p in self.parts):
            return "".join(self.parts)  # type: ignore[arg-type]
        return None

    def template(self) -> str:
        return "".join(HOLE if isinstance(p, Unknown) else p for p in self.parts)

    def unknowns(self) -> list[Unknown]:
        return [p for p in self.parts if isinstance(p, Unknown)]

    def __add__(self, other: Str) -> Str:
        parts = _merge_parts(self.parts + other.parts)
        if len(parts) > 64:
            return Str((Unknown("string built from too many parts"),))
        return Str(parts, (self.sources + other.sources)[:16])


def _merge_parts(parts: tuple) -> tuple:
    out: list = []
    for p in parts:
        if isinstance(p, str) and out and isinstance(out[-1], str):
            out[-1] = out[-1] + p
        elif p != "":
            out.append(p)
    return tuple(out)


@dataclass(frozen=True)
class Obj:
    kind: str  # e.g. requests.Session, httpx.Client, llm:openai, gh:Repository, Path, smtp
    attrs: tuple[tuple[str, Value], ...] = ()

    def get(self, name: str) -> Value | None:
        for k, v in self.attrs:
            if k == name:
                return v
        return None


Value = Union[Str, Obj, Unknown]


def _as_str(v: Value) -> Str:
    if isinstance(v, Str):
        return v
    if isinstance(v, Unknown):
        return Str((v,))
    return Str((Unknown(f"object {v.kind}"),))


# ---------------------------------------------------------------------------------------------------------
# Project index
# ---------------------------------------------------------------------------------------------------------


@dataclass
class FunctionInfo:
    key: str  # "<module>:<qualname>"
    module: ModuleInfo
    node: ast.FunctionDef | ast.AsyncFunctionDef
    qualname: str
    class_name: str | None
    parent: FunctionInfo | None
    params: list[str]
    assigns: dict[str, list[ast.expr]] = field(default_factory=dict)
    is_tool: bool = False
    referenced_as_value: bool = False
    call_sites: list[tuple[FunctionInfo | None, ModuleInfo, ast.Call]] = field(default_factory=list)


@dataclass
class ClassInfo:
    name: str
    module: ModuleInfo
    attrs: dict[str, list[tuple[ast.expr, FunctionInfo | None]]] = field(default_factory=dict)  # attr -> [(expr, defining fn)]
    bases: list[str] = field(default_factory=list)


@dataclass
class ModuleInfo:
    name: str
    path: Path
    rel: str
    tree: ast.Module
    imports: dict[str, str] = field(default_factory=dict)  # local name -> canonical dotted name
    constants: dict[str, list[ast.expr]] = field(default_factory=dict)
    functions: dict[str, FunctionInfo] = field(default_factory=dict)  # qualname -> info
    classes: dict[str, ClassInfo] = field(default_factory=dict)


def _module_name(root: Path, path: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or "__root__"


def _iter_py_files(root: Path, include_tests: bool) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _EXCLUDED_DIRS and not d.startswith("."))
        if not include_tests:
            dirnames[:] = [d for d in dirnames if d not in ("tests", "test", "testing")]
        for f in sorted(filenames):
            if f in _BUILD_FILES:
                continue
            if f.endswith(".py") and (include_tests or not (f.startswith("test_") or f.endswith("_test.py") or f == "conftest.py")):
                yield Path(dirpath) / f


def _decorator_names(node: ast.AST) -> list[str]:
    out = []
    for d in getattr(node, "decorator_list", []):
        target = d.func if isinstance(d, ast.Call) else d
        parts = []
        while isinstance(target, ast.Attribute):
            parts.append(target.attr)
            target = target.value
        if isinstance(target, ast.Name):
            parts.append(target.id)
        out.append(".".join(reversed(parts)))
    return out


class _Indexer(ast.NodeVisitor):
    def __init__(self, mod: ModuleInfo):
        self.mod = mod
        self.fn_stack: list[FunctionInfo] = []
        self.cls_stack: list[ClassInfo] = []

    # imports -----------------------------------------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            if a.asname:
                self.mod.imports[a.asname] = a.name
            else:
                top = a.name.split(".")[0]
                self.mod.imports[top] = top
                self.mod.imports.setdefault(a.name, a.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = node.module or ""
        if node.level:
            pkg = self.mod.name.split(".")
            if not self.mod.rel.endswith("__init__.py"):
                pkg = pkg[:-1]
            pkg = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
            base = ".".join([p for p in pkg if p] + ([base] if base else []))
        for a in node.names:
            self.mod.imports[a.asname or a.name] = f"{base}.{a.name}" if base else a.name

    # definitions -------------------------------------------------------------------------------------
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if self.fn_stack:
            self.generic_visit(node)
            return
        info = ClassInfo(node.name, self.mod, bases=[ast.unparse(b) for b in node.bases])
        self.mod.classes[node.name] = info
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name):
                        info.attrs.setdefault(t.id, []).append((stmt.value, None))
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                info.attrs.setdefault(stmt.target.id, []).append((stmt.value, None))
        self.cls_stack.append(info)
        for stmt in node.body:
            self.visit(stmt)
        self.cls_stack.pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        parent = self.fn_stack[-1] if self.fn_stack else None
        cls = self.cls_stack[-1] if (self.cls_stack and parent is None) else None
        if parent is not None:
            qual = f"{parent.qualname}.{node.name}"
        elif cls is not None:
            qual = f"{cls.name}.{node.name}"
        else:
            qual = node.name
        a = node.args
        params = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
        if a.vararg:
            params.append(a.vararg.arg)
        if a.kwarg:
            params.append(a.kwarg.arg)
        decos = _decorator_names(node)
        is_tool = any(any(h == d.split(".")[-1] or d.split(".")[-1].endswith("_" + h) for h in sdk.TOOL_DECORATOR_HINTS) for d in decos)
        info = FunctionInfo(f"{self.mod.name}:{qual}", self.mod, node, qual, cls.name if cls else None, parent, params, is_tool=is_tool)
        self.mod.functions[qual] = info
        self.fn_stack.append(info)
        for stmt in node.body:
            self.visit(stmt)
        self.fn_stack.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def _record_assign(self, target: ast.expr, value: ast.expr) -> None:
        if isinstance(target, ast.Name):
            if self.fn_stack:
                self.fn_stack[-1].assigns.setdefault(target.id, []).append(value)
            elif not self.cls_stack:
                self.mod.constants.setdefault(target.id, []).append(value)
        elif (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self"
              and self.fn_stack and self.fn_stack[-1].class_name):
            cls = self.mod.classes.get(self.fn_stack[-1].class_name)
            if cls is not None:
                cls.attrs.setdefault(target.attr, []).append((value, self.fn_stack[-1]))
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._record_assign(elt, ast.Constant(value=None))  # unpacking: value unknown

    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            self._record_assign(t, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._record_assign(node.target, node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name):
            # x += ... makes x a multi-definition variable
            self._record_assign(node.target, ast.Constant(value=None))
            self._record_assign(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._record_assign(node.target, ast.Constant(value=None))
        self._record_assign(node.target, ast.Constant(value=None))
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._record_assign(item.optional_vars, item.context_expr)
        self.generic_visit(node)

    visit_AsyncWith = visit_With  # type: ignore[assignment]

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._record_assign(node.target, node.value)
        self.generic_visit(node)


# ---------------------------------------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Effect:
    kind: str  # http | github | fs | exec | email
    action: str
    target: Value  # URL (http), repository full name / owner (github), path (fs), program (exec), host (email)
    method: str = ""
    via: str = ""
    owner_only: bool = False  # github target is an owner/org, not a repository
    account: bool = False  # github target is the authenticated account


class Extractor:
    def __init__(self, root: Path, *, env: dict[str, str] | None = None, include_tests: bool = False):
        self.root = root
        self.env = dict(env or {})
        self.include_tests = include_tests
        self.modules: dict[str, ModuleInfo] = {}
        self.functions: dict[str, FunctionInfo] = {}
        self.report = AuthorityReport(root=str(root))
        self._ctx_cache: dict[str, list[tuple[dict[str, Value], tuple[str, ...]]]] = {}
        self._in_progress: set[str] = set()
        self._memo: dict[tuple, Value] = {}  # (scope, bindings, name) -> value
        self._active: set[tuple] = set()  # evaluations in progress (cycle guard)

    # indexing ----------------------------------------------------------------------------------------
    def index(self) -> None:
        for path in _iter_py_files(self.root, self.include_tests):
            rel = str(path.relative_to(self.root))
            try:
                src = path.read_text(encoding="utf-8")
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")  # the agent's own SyntaxWarnings are not ours to print
                    tree = ast.parse(src, filename=rel)
            except (SyntaxError, UnicodeDecodeError, ValueError) as exc:
                self.report.parse_errors.append({"file": rel, "error": f"{type(exc).__name__}: {exc}"})
                continue
            mod = ModuleInfo(_module_name(self.root, path), path, rel, tree)
            _Indexer(mod).visit(tree)
            self.modules[mod.name] = mod
            for fn in mod.functions.values():
                self.functions[fn.key] = fn
        self.report.files_analysed = len(self.modules)
        self._index_call_sites()

    def _index_call_sites(self) -> None:
        for mod in self.modules.values():
            for owner, node in self._walk_with_owner(mod):
                if isinstance(node, ast.Call):
                    target = self._local_callee(node.func, mod, owner)
                    if target is not None:
                        target.call_sites.append((owner, mod, node))
                    for arg in list(node.args) + [k.value for k in node.keywords]:
                        ref = self._local_callee(arg, mod, owner) if isinstance(arg, (ast.Name, ast.Attribute)) else None
                        if ref is not None:
                            ref.referenced_as_value = True
                elif isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                    elts = node.values if isinstance(node, ast.Dict) else node.elts
                    for e in elts:
                        if isinstance(e, (ast.Name, ast.Attribute)):
                            ref = self._local_callee(e, mod, owner)
                            if ref is not None:
                                ref.referenced_as_value = True

    def _walk_with_owner(self, mod: ModuleInfo) -> Iterator[tuple[FunctionInfo | None, ast.AST]]:
        fn_by_node = {id(f.node): f for f in mod.functions.values()}

        def walk(node: ast.AST, owner: FunctionInfo | None) -> Iterator[tuple[FunctionInfo | None, ast.AST]]:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    f = fn_by_node.get(id(child))
                    for d in child.decorator_list:
                        yield from walk_expr(d, owner)
                    yield from walk(child, f if f is not None else owner)
                else:
                    yield owner, child
                    yield from walk(child, owner)

        def walk_expr(node: ast.AST, owner: FunctionInfo | None) -> Iterator[tuple[FunctionInfo | None, ast.AST]]:
            yield owner, node
            yield from walk(node, owner)

        yield from walk(mod.tree, None)

    def _local_callee(self, func: ast.expr, mod: ModuleInfo, owner: FunctionInfo | None) -> FunctionInfo | None:
        if isinstance(func, ast.Name):
            # nested function in an enclosing function
            f = owner
            while f is not None:
                cand = mod.functions.get(f"{f.qualname}.{func.id}")
                if cand is not None:
                    return cand
                f = f.parent
            if func.id in mod.functions:
                return mod.functions[func.id]
            if func.id in mod.classes:
                return mod.functions.get(f"{func.id}.__init__")
            canon = mod.imports.get(func.id)
            if canon:
                return self._project_function(canon)
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id in ("self", "cls") and owner is not None:
                cls_name = owner.class_name or (owner.parent.class_name if owner.parent else None)
                if cls_name:
                    return mod.functions.get(f"{cls_name}.{func.attr}")
            canon = mod.imports.get(func.value.id)
            if canon:
                return self._project_function(f"{canon}.{func.attr}")
        return None

    def _project_function(self, dotted: str) -> FunctionInfo | None:
        mod_name, _, name = dotted.rpartition(".")
        mod = self.modules.get(mod_name)
        if mod is not None:
            if name in mod.functions:
                return mod.functions[name]
            if name in mod.classes:
                return mod.functions.get(f"{name}.__init__")
        return None

    # contexts ----------------------------------------------------------------------------------------
    def contexts(self, fn: FunctionInfo | None, depth: int = 0) -> list[tuple[dict[str, Value], tuple[str, ...]]]:
        """Possible parameter bindings of ``fn``, one per local call path (or one unbound context)."""
        if fn is None:
            return [({}, ())]
        cache_key = f"{fn.key}@{depth}"
        if cache_key in self._ctx_cache:
            return self._ctx_cache[cache_key]
        unbound = ({}, (fn.qualname,))
        if (fn.is_tool or fn.referenced_as_value or not fn.call_sites or depth >= MAX_DEPTH
                or fn.key in self._in_progress):
            result = [unbound]
        else:
            self._in_progress.add(fn.key)
            result = []
            for caller, cmod, call in fn.call_sites:
                for cbind, cchain in self.contexts(caller, depth + 1):
                    ctx = _Ctx(self, cmod, caller, cbind)
                    bind = self._bind_args(fn, call, ctx)
                    chain = (cchain or ("<module>",)) + (fn.qualname,)
                    result.append((bind, chain))
                    if len(result) > 32:
                        break
            self._in_progress.discard(fn.key)
            if not result:
                result = [unbound]
        self._ctx_cache[cache_key] = result
        return result

    def _bind_args(self, fn: FunctionInfo, call: ast.Call, ctx: _Ctx) -> dict[str, Value]:
        params = list(fn.params)
        if fn.class_name and params and params[0] in ("self", "cls"):
            params = params[1:]
        bind: dict[str, Value] = {}
        for i, a in enumerate(call.args):
            if isinstance(a, ast.Starred):
                break
            if i < len(params):
                bind[params[i]] = ctx.eval(a)
        for kw in call.keywords:
            if kw.arg and kw.arg in fn.params:
                bind[kw.arg] = ctx.eval(kw.value)
        # defaults for parameters the call did not pass
        a = fn.node.args
        positional = a.posonlyargs + a.args
        for p, d in zip(positional[len(positional) - len(a.defaults):], a.defaults):
            bind.setdefault(p.arg, _Ctx(self, fn.module, fn.parent, {}).eval(d))
        for p, d in zip(a.kwonlyargs, a.kw_defaults):
            if d is not None:
                bind.setdefault(p.arg, _Ctx(self, fn.module, fn.parent, {}).eval(d))
        return bind

    # extraction --------------------------------------------------------------------------------------
    def run(self) -> AuthorityReport:
        self.index()
        seen: set[tuple] = set()
        for mod in self.modules.values():
            for owner, node in self._walk_with_owner(mod):
                if not isinstance(node, ast.Call):
                    continue
                base_ctx = _Ctx(self, mod, owner, {})
                effects = base_ctx.effects_of(node)
                if not effects:
                    continue
                if any(self._depends_on_params(eff, owner) for eff in effects):
                    contexts = self.contexts(owner)
                else:
                    contexts = [({}, (owner.qualname,) if owner else ("<module>",))]
                for bind, chain in contexts:
                    for eff in (_Ctx(self, mod, owner, bind).effects_of(node) if bind else effects):
                        ev = self._evidence(eff, node, mod, owner, chain)
                        k = (ev.action, ev.resource, ev.file, ev.line, ev.col, ev.call_path)
                        if k not in seen:
                            seen.add(k)
                            self.report.evidence.append(ev)
        return self.report

    @staticmethod
    def _depends_on_params(effect: _Effect, owner: FunctionInfo | None) -> bool:
        if owner is None:
            return False
        vals: list[Value] = [effect.target]
        for v in vals:
            s = _as_str(v) if not isinstance(v, Obj) else None
            if s is not None and any(u.param_of for u in s.unknowns()):
                return True
        return False

    def _evidence(self, eff: _Effect, node: ast.Call, mod: ModuleInfo, owner: FunctionInfo | None,
                  chain: tuple[str, ...]) -> AuthorityEvidence:
        target = _as_str(eff.target)
        unknowns = target.unknowns()
        sources = list(target.sources)
        for u in unknowns:
            if u.source is not None:
                sources.append(u.source)
        hole_names = tuple(u.name or "value" for u in unknowns)
        common = dict(
            file=mod.rel, line=node.lineno, col=node.col_offset + 1, end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
            function=owner.qualname if owner else "<module>", call=ast.unparse(node), via=eff.via,
            tool_entry=bool(owner and owner.is_tool), call_path=chain,
        )
        reasons_unknown = "; ".join(sorted({u.reason for u in unknowns}))
        if eff.kind == "http":
            tmpl = target.template()
            auth = classify_http(eff.method or HOLE, tmpl, hole_names=hole_names)
            reason = f"{eff.via} sends an HTTP {eff.method.upper() or '(unknown method)'} request"
            if unknowns:
                reason += f"; unknown: {reasons_unknown}"
            return AuthorityEvidence(
                action=auth.action, resource=auth.resource, resource_state=auth.state, confidence="high" if not unknowns else "medium",
                reason=reason, unresolved_parts=auth.unresolved_parts, template_params=auth.template_params,
                sources=tuple(sources), method=eff.method, url=tmpl.replace(HOLE, TEMPLATE_SEGMENT), **common,
            )
        if eff.kind == "github":
            reason = f"{eff.via} performs {eff.action}"
            if eff.account:
                return AuthorityEvidence(action=eff.action, resource="github.com", resource_state=ResourceState.RESOLVED,
                                         confidence="high", reason=reason + " on the authenticated account", sources=tuple(sources), **common)
            known = target.known()
            if known is not None and known.strip("/") and (eff.owner_only or known.count("/") == 1):
                return AuthorityEvidence(action=eff.action, resource=f"github.com/{known.strip('/')}", resource_state=ResourceState.RESOLVED,
                                         confidence="high", reason=reason, sources=tuple(sources), **common)
            parts = ("owner",) if eff.owner_only else ("repository",)
            if known is not None:
                reasons_unknown = f"'{known}' is not an owner/repository name"
            return AuthorityEvidence(action=eff.action, resource=None, resource_state=ResourceState.UNRESOLVED, confidence="medium",
                                     reason=f"{reason}; repository unknown: {reasons_unknown}", unresolved_parts=parts,
                                     sources=tuple(sources), url=target.template().replace(HOLE, TEMPLATE_SEGMENT), **common)
        if eff.kind == "fs":
            return self._path_evidence(eff, target, unknowns, reasons_unknown, sources, common)
        if eff.kind == "llm":
            model = target.known()
            if model is not None:
                for prefixes, chat_url, embed_url in sdk.LITELLM_PROVIDERS:
                    if model.lower().startswith(prefixes):
                        url = embed_url if eff.action == "embed" else chat_url
                        if url:
                            auth = classify_http("post", url.replace("{}", HOLE), hole_names=("model",))
                            return AuthorityEvidence(
                                action=auth.action, resource=auth.resource, resource_state=auth.state, confidence="high",
                                reason=f"{eff.via} sends model '{model}' to its provider", template_params=auth.template_params,
                                sources=tuple(sources), method="post", url=url, **common)
            return AuthorityEvidence(
                action="http.post", resource=None, resource_state=ResourceState.UNRESOLVED, confidence="medium",
                reason=f"{eff.via} calls the model provider chosen by the model configuration"
                       + (f" ('{model}' is not a known provider prefix)" if model else f": {reasons_unknown or 'model not statically known'}"),
                unresolved_parts=("provider",), sources=tuple(sources), method="post", **common)
        if eff.kind == "exec":
            known = target.known()
            if known:
                prog = os.path.basename(known.strip().split()[0]) if known.strip() else ""
                if prog:
                    return AuthorityEvidence(action="process.exec", resource=prog, resource_state=ResourceState.RESOLVED, confidence="high",
                                             reason=f"{eff.via} runs the program '{prog}'", sources=tuple(sources), **common)
            # first token known?
            first = target.parts[0] if target.parts else None
            if isinstance(first, str) and first.strip() and (" " in first.strip() or len(target.parts) == 1):
                prog = os.path.basename(first.strip().split()[0])
                return AuthorityEvidence(action="process.exec", resource=prog, resource_state=ResourceState.RESOLVED, confidence="medium",
                                         reason=f"{eff.via} runs the program '{prog}' with arguments not statically known",
                                         sources=tuple(sources), **common)
            return AuthorityEvidence(action="process.exec", resource=None, resource_state=ResourceState.UNRESOLVED, confidence="medium",
                                     reason=f"{eff.via} runs a program that is not statically known: {reasons_unknown or 'dynamic command'}",
                                     unresolved_parts=("program",), sources=tuple(sources), **common)
        # email
        known = target.known()
        if known:
            return AuthorityEvidence(action="email.send", resource=known, resource_state=ResourceState.RESOLVED, confidence="high",
                                     reason=f"{eff.via} sends mail through {known}", sources=tuple(sources), **common)
        return AuthorityEvidence(action="email.send", resource=None, resource_state=ResourceState.UNRESOLVED, confidence="medium",
                                 reason=f"{eff.via} sends mail through an unknown server", unresolved_parts=("host",),
                                 sources=tuple(sources), **common)

    def _path_evidence(self, eff: _Effect, target: Str, unknowns: list[Unknown], reasons_unknown: str,
                       sources: list[ValueSource], common: dict) -> AuthorityEvidence:
        tmpl = target.template()
        if not tmpl or tmpl.startswith(HOLE):
            return AuthorityEvidence(action=eff.action, resource=None, resource_state=ResourceState.UNRESOLVED, confidence="medium",
                                     reason=f"{eff.via} writes to a path that is not statically known: {reasons_unknown or 'dynamic path'}",
                                     unresolved_parts=("path",), sources=tuple(sources), **common)
        norm = _normalise_path(tmpl)
        if norm is None:
            return AuthorityEvidence(action=eff.action, resource=None, resource_state=ResourceState.UNRESOLVED, confidence="medium",
                                     reason=f"{eff.via} uses a path whose directory is not statically known", unresolved_parts=("path",),
                                     sources=tuple(sources), **common)
        state = ResourceState.TEMPLATE if HOLE in norm else ResourceState.RESOLVED
        verb = "deletes" if eff.action == "filesystem.delete" else "writes"
        return AuthorityEvidence(action=eff.action, resource=norm.replace(HOLE, TEMPLATE_SEGMENT), resource_state=state,
                                 confidence="high" if state is ResourceState.RESOLVED else "medium",
                                 reason=f"{eff.via} {verb} {norm.replace(HOLE, TEMPLATE_SEGMENT)}",
                                 template_params=tuple(u.name or "value" for u in unknowns), sources=tuple(sources), **common)


def normalise_path(path: str) -> str | None:
    """The filesystem resource Scan names for ``path``; runtime enforcement uses the same spelling."""
    return _normalise_path(path)


def _normalise_path(tmpl: str) -> str | None:
    """Project-relative paths become ``./x/y``; absolute (``/``) and home (``~/``) paths keep their root.
    An unknown part may be a whole directory segment or any part of the final segment, never part of a
    directory name; ``..`` is refused (UNRESOLVED)."""
    p = tmpl.replace("\\", "/")
    prefix = ""
    if p.startswith("/"):
        prefix = "/"
    elif p == "~" or p.startswith("~/"):
        prefix, p = "~/", p[1:]
    segs = [s for s in p.split("/") if s not in ("", ".")]
    if ".." in segs:
        return None
    for s in segs[:-1]:
        if HOLE in s:  # only the file name may be unknown; an unknown directory is unresolved
            return None
    body = "/".join(segs)
    return prefix + body if prefix else "./" + body


# ---------------------------------------------------------------------------------------------------------
# Evaluation context
# ---------------------------------------------------------------------------------------------------------


class _Ctx:
    def __init__(self, ex: Extractor, mod: ModuleInfo, fn: FunctionInfo | None, bind: dict[str, Value], depth: int = 0):
        self.ex, self.mod, self.fn, self.bind, self.depth = ex, mod, fn, bind, depth

    def _src(self, kind: str, name: str, node: ast.AST | None, detail: str = "") -> ValueSource:
        return ValueSource(kind, name, self.mod.rel, getattr(node, "lineno", 0) if node is not None else 0, detail)

    # names -------------------------------------------------------------------------------------------
    def canonical(self, expr: ast.expr) -> str | None:
        """Dotted canonical name of an imported module/function expression, e.g. requests.post."""
        if isinstance(expr, ast.Name):
            if self._is_local(expr.id):
                return None
            if expr.id in self.mod.imports:
                return self.mod.imports[expr.id]
            if expr.id in ("open", "print"):
                return f"builtins.{expr.id}"
            return None
        if isinstance(expr, ast.Attribute):
            base = self.canonical(expr.value)
            return f"{base}.{expr.attr}" if base else None
        return None

    def _is_local(self, name: str) -> bool:
        f = self.fn
        while f is not None:
            if name in f.params or name in f.assigns:
                return True
            f = f.parent
        return False

    def _bkey(self) -> tuple:
        try:
            k = tuple(sorted(self.bind.items()))
            hash(k)
            return k
        except TypeError:
            return (("<unhashable>", id(self.bind)),)

    def _memoised(self, key: tuple, compute, cyclic: str) -> Value:
        memo = self.ex._memo
        if key in memo:
            return memo[key]
        if key in self.ex._active:
            return Unknown(cyclic)
        self.ex._active.add(key)
        try:
            value = compute()
        finally:
            self.ex._active.discard(key)
        memo[key] = value
        return value

    def lookup(self, name: str, node: ast.AST) -> Value:
        key = ("name", self.mod.name, self.fn.key if self.fn else None, self._bkey(), name)
        return self._memoised(key, lambda: self._lookup(name, node), f"'{name}' is defined in terms of itself")

    def _lookup(self, name: str, node: ast.AST) -> Value:
        f = self.fn
        bind = self.bind
        while f is not None:
            if name in bind:
                return bind[name]
            if name in f.assigns:
                return self._eval_defs(f.assigns[name], name, _Ctx(self.ex, self.mod, f, bind, self.depth + 1))
            if name in f.params:
                kind = "parameter of tool function" if f.is_tool else "parameter"
                return Unknown(f"{kind} '{name}' of {f.qualname}", name, f.key, self._src("parameter", name, f.node, f.qualname))
            f, bind = f.parent, {}
        if name in self.mod.constants:
            return self._eval_defs(self.mod.constants[name], name, _Ctx(self.ex, self.mod, None, {}, self.depth + 1))
        if name in self.mod.imports:
            canon = self.mod.imports[name]
            mod_name, _, attr = canon.rpartition(".")
            other = self.ex.modules.get(mod_name)
            if other is not None and attr in other.constants:
                return _Ctx(self.ex, other, None, {}, self.depth + 1)._eval_defs(other.constants[attr], attr, _Ctx(self.ex, other, None, {}, self.depth + 1))
        return Unknown(f"name '{name}' is not statically known", name)

    def _eval_defs(self, defs: list[ast.expr], name: str, ctx: _Ctx) -> Value:
        if ctx.depth > 12:
            return Unknown(f"'{name}' is defined through too many indirections", name)
        vals = [ctx.eval(d) for d in defs]
        if len(vals) == 1:
            return _with_source(vals[0], ValueSource("constant", name, ctx.mod.rel, getattr(defs[0], "lineno", 0)))
        return _join(vals, f"'{name}'")

    # evaluation --------------------------------------------------------------------------------------
    def eval(self, e: ast.expr | None) -> Value:
        if e is None:
            return Unknown("missing value")
        if self.depth > 16:
            return Unknown("evaluation too deep")
        if isinstance(e, ast.Constant):
            if isinstance(e.value, str):
                return Str.lit(e.value, ValueSource("literal", "", self.mod.rel, e.lineno))
            if isinstance(e.value, (int, float)) and not isinstance(e.value, bool):
                return Str.lit(str(e.value))
            if e.value is None:
                return Unknown("None", "")
            return Unknown(f"non-string constant {e.value!r}")
        if isinstance(e, ast.JoinedStr):
            out = Str(())
            for v in e.values:
                if isinstance(v, ast.Constant):
                    out = out + Str.lit(str(v.value))
                elif isinstance(v, ast.FormattedValue):
                    out = out + _as_str(self.eval(v.value)) if v.format_spec is None else out + Str((Unknown("formatted value"),))
            return out
        if isinstance(e, ast.BinOp):
            if isinstance(e.op, ast.Add):
                left, right = self.eval(e.left), self.eval(e.right)
                if isinstance(left, Obj) or isinstance(right, Obj):
                    return Unknown("object arithmetic")
                return _as_str(left) + _as_str(right)
            if isinstance(e.op, ast.Div):
                left = self.eval(e.left)
                if isinstance(left, Obj) and left.kind == "Path":
                    base = _as_str(left.get("path") or Unknown("path"))
                    return Obj("Path", (("path", base + Str.lit("/") + _as_str(self.eval(e.right))),))
            if isinstance(e.op, ast.Mod):
                fmt = self.eval(e.left)
                if isinstance(fmt, Str) and fmt.known() is not None:
                    args = e.right.elts if isinstance(e.right, ast.Tuple) else [e.right]
                    return _percent_format(fmt.known() or "", [_as_str(self.eval(a)) for a in args])
            return Unknown("arithmetic on non-strings")
        if isinstance(e, ast.Name):
            return self.lookup(e.id, e)
        if isinstance(e, ast.Attribute):
            return self._eval_attribute(e)
        if isinstance(e, ast.Subscript):
            return self._eval_subscript(e)
        if isinstance(e, ast.Call):
            return self._eval_call(e)
        if isinstance(e, ast.IfExp):
            a, b = self.eval(e.body), self.eval(e.orelse)
            return a if a == b else Unknown("conditional value")
        if isinstance(e, ast.BoolOp) and isinstance(e.op, ast.Or):
            # `os.getenv("X") or "default"`: the first known string wins only if earlier operands are unknown env refs
            vals = [self.eval(v) for v in e.values]
            for v in vals:
                if isinstance(v, Str) and v.known() is not None:
                    return v
            return Unknown("alternative values")
        if isinstance(e, ast.Await):
            return self.eval(e.value)
        return Unknown(f"{type(e).__name__} expression")

    def _eval_attribute(self, e: ast.Attribute) -> Value:
        if isinstance(e.value, ast.Name) and e.value.id == "self" and self.fn is not None:
            cls_name = self.fn.class_name or (self.fn.parent.class_name if self.fn.parent else None)
            cls = self.mod.classes.get(cls_name or "")
            if cls is not None and e.attr in cls.attrs:
                return self._memoised(("self", self.mod.name, cls.name, e.attr), lambda: self._self_attr(cls, e),
                                      f"self.{e.attr} is defined in terms of itself")
            return Unknown(f"self.{e.attr} is not statically known", e.attr)
        return self._eval_attribute_rest(e)

    def _self_attr(self, cls: ClassInfo, e: ast.Attribute) -> Value:
        vals: list[Value] = []
        for expr, definer in cls.attrs[e.attr]:
            if definer is None:
                vals.append(_Ctx(self.ex, self.mod, None, {}, self.depth + 1).eval(expr))
            else:
                for bind, _chain in self.ex.contexts(definer):
                    vals.append(_Ctx(self.ex, self.mod, definer, bind, self.depth + 1).eval(expr))
        return _join(vals, f"self.{e.attr}")

    def _eval_attribute_rest(self, e: ast.Attribute) -> Value:
        canon = self.canonical(e)
        if canon == "os.environ":
            return Obj("os.environ")
        base = self.eval(e.value)
        if isinstance(base, Obj) and base.kind in ("gh:PullRequest", "gh:Issue", "gh:Repository") and e.attr in sdk.PYGITHUB_URL_ATTRS:
            # PyGithub objects' API URLs, as used with the raw requester: derived from the tracked repository.
            repo = _as_str(base.get("repo") or Unknown("repository"))
            suffix = sdk.PYGITHUB_URL_ATTRS[e.attr].get(base.kind[3:])
            if suffix is not None:
                number = Str((Unknown("number", "number"),))
                return Str.lit("https://api.github.com/repos/") + repo + (Str.lit(suffix) + number if suffix else Str(()))
        if isinstance(base, Obj) and base.kind == "alt":
            alts = []
            for k, alt in base.attrs:
                if isinstance(alt, Obj):
                    kept = tuple((ak, av) for ak, av in alt.attrs if ak != "_attr_path")
                    alts.append((k, alt.get(e.attr) or Obj(alt.kind, kept + (("_attr_path", Str.lit(_attr_path(alt) + "." + e.attr)),))))
            return Obj("alt", tuple(alts))
        if isinstance(base, Obj):
            v = base.get(e.attr)
            if v is not None:
                return v
            kept = tuple((k, v) for k, v in base.attrs if k != "_attr_path")
            return Obj(base.kind, kept + (("_attr_path", Str.lit(_attr_path(base) + "." + e.attr)),))
        if isinstance(base, Unknown) and canon is None:
            return Unknown(f"attribute {e.attr} of an unknown value", e.attr)
        return Unknown(f"attribute {canon or e.attr}", e.attr)

    def _eval_subscript(self, e: ast.Subscript) -> Value:
        canon = self.canonical(e.value)
        if canon == "os.environ":
            key = self.eval(e.slice)
            if isinstance(key, Str) and key.known():
                return self._env(key.known() or "", None, e)
            return Unknown("environment variable with unknown name")
        base = self.eval(e.value)
        if isinstance(e.value, ast.Dict) or (isinstance(base, Obj) and base.kind == "dict"):
            pass
        return Unknown("subscript")

    def _env(self, name: str, default: Value | None, node: ast.AST) -> Value:
        secret = any(h in name.upper() for h in sdk.SECRET_NAME_HINTS)
        if name in self.ex.env:
            if secret:
                return Unknown(f"value of secret configuration variable {name} (never written to authority)", name,
                               source=self._src("env", name, node, "secret: not inlined"))
            return Str.lit(self.ex.env[name], self._src("env", name, node, "project configuration at scan time"))
        if default is not None:
            if isinstance(default, Str) and default.known() is not None:
                return Str(default.parts, default.sources + (self._src("env-default", name, node, f"{name} is not set; code default used"),))
            return default
        return Unknown(f"configuration variable {name} is not set", name, source=self._src("env", name, node, "not set at scan time"))

    def _eval_call(self, e: ast.Call) -> Value:
        canon = self.canonical(e.func)
        args = e.args
        kw = {k.arg: k.value for k in e.keywords if k.arg}
        if canon in ("os.getenv", "os.environ.get") or (isinstance(e.func, ast.Attribute) and e.func.attr == "get"
                                                       and self.canonical(e.func.value) == "os.environ"):
            if args:
                key = self.eval(args[0])
                default = self.eval(args[1]) if len(args) > 1 else (self.eval(kw["default"]) if "default" in kw else None)
                if isinstance(key, Str) and key.known():
                    return self._env(key.known() or "", default, e)
            return Unknown("environment variable with unknown name")
        if canon in ("str",) and args:
            return self.eval(args[0])
        if canon in ("urllib.parse.urljoin",) and len(args) >= 2:
            return _as_str(self.eval(args[0])) + _as_str(self.eval(args[1]))
        if canon in ("pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "os.path.join"):
            parts = [_as_str(self.eval(a)) for a in args]
            joined = Str(())
            for i, p in enumerate(parts):
                joined = joined + (Str.lit("/") if i else Str(())) + p
            return Obj("Path", (("path", joined),)) if canon != "os.path.join" else joined
        # constructors producing tracked objects
        if canon in sdk.HTTP_CLIENT_CONSTRUCTORS:
            kwname = sdk.HTTP_CLIENT_CONSTRUCTORS[canon]
            attrs: tuple = ()
            if kwname and kwname in kw:
                attrs = (("base_url", _as_str(self.eval(kw[kwname]))),)
            return Obj(canon if canon != "requests.session" else "requests.Session", attrs)
        if canon in sdk.LLM_CLIENTS:
            default, envvar, kwname = sdk.LLM_CLIENTS[canon]
            if kwname in kw:
                base = _as_str(self.eval(kw[kwname]))
            elif "openai_api_base" in kw:
                base = _as_str(self.eval(kw["openai_api_base"]))
            else:
                base = self._env(envvar, Str.lit(default, ValueSource("sdk-default", envvar, "", 0, f"{canon} default endpoint")), e)  # type: ignore[assignment]
                base = _as_str(base)
            provider = canon if canon.startswith("langchain") else canon.split(".")[0]
            return Obj(f"llm:{provider}", (("base_url", base), ("_via", Str.lit(canon))))
        if canon in sdk.PYGITHUB_CONSTRUCTORS:
            return Obj("gh:Github")
        if canon in sdk.SMTP_CONSTRUCTORS:
            host = self.eval(args[0]) if args else (self.eval(kw["host"]) if "host" in kw else Unknown("SMTP host"))
            return Obj("smtp", (("host", _as_str(host)),))
        if canon == "urllib.request.Request":
            url = self.eval(args[0]) if args else self.eval(kw.get("url"))
            method = kw.get("method")
            has_data = len(args) > 1 or "data" in kw
            m = self.eval(method) if method is not None else Str.lit("POST" if has_data else "GET")
            return Obj("urllib.Request", (("url", _as_str(url)), ("method", _as_str(m))))
        # accessors on tracked objects (PyGithub)
        if isinstance(e.func, ast.Attribute):
            recv = self.eval(e.func.value)
            if isinstance(recv, Obj) and recv.kind.startswith("gh:"):
                kind = recv.kind[3:]
                nxt = sdk.PYGITHUB_ACCESSORS.get((kind, e.func.attr))
                if nxt is not None:
                    attrs = recv.attrs
                    if kind == "Github" and e.func.attr == "get_repo":
                        attrs = (("repo", _as_str(self.eval(args[0]) if args else self.eval(kw.get("full_name_or_id")))),)
                    elif kind == "Github" and e.func.attr == "get_organization":
                        attrs = (("owner", _as_str(self.eval(args[0]) if args else self.eval(kw.get("login")))),)
                    elif kind in ("Organization", "AuthenticatedUser") and e.func.attr == "get_repo" and args:
                        owner = recv.get("owner")
                        name = _as_str(self.eval(args[0]))
                        attrs = (("repo", (_as_str(owner) + Str.lit("/") + name) if owner is not None else Str((Unknown("authenticated user's login"),)) + Str.lit("/") + name),)
                    return Obj(f"gh:{nxt}", attrs)
        # local function returning a constant
        target = self.ex._local_callee(e.func, self.mod, self.fn)
        if target is not None and self.depth < 6:
            rets = [n.value for n in _own_returns(target.node)]
            if 1 <= len(rets) <= 12:
                ctx = _Ctx(self.ex, target.module, target, self.ex._bind_args(target, e, self), self.depth + 1)
                return self._memoised(("return", target.key, ctx._bkey()),
                                      lambda: _join([ctx.eval(r) for r in rets], f"result of {target.qualname}()"),
                                      f"recursive call to {target.qualname}")
        if isinstance(e.func, ast.Attribute) and e.func.attr in ("format",):
            fmt = self.eval(e.func.value)
            if isinstance(fmt, Str) and fmt.known() is not None:
                return _str_format(fmt.known() or "", [_as_str(self.eval(a)) for a in args],
                                   {k: _as_str(self.eval(v)) for k, v in kw.items()})
        if isinstance(e.func, ast.Attribute) and e.func.attr in ("strip", "rstrip", "lstrip", "lower", "upper") and not args:
            v = self.eval(e.func.value)
            if isinstance(v, Str) and v.known() is not None:
                return Str.lit(getattr(v.known() or "", e.func.attr)(), *(v.sources[:1] or [None]))
            return v if isinstance(v, Str) else Unknown("string method on unknown value")
        return Unknown(f"result of {canon or ast.unparse(e.func)}()")

    # effects -----------------------------------------------------------------------------------------
    def effects_of(self, call: ast.Call) -> list[_Effect]:
        """The effects of one call. A receiver that may be one of several client objects (a factory returning
        ChatOpenAI or ChatAnthropic) has the effects of each alternative."""
        if isinstance(call.func, ast.Attribute):
            recv = self.eval(call.func.value)
            if isinstance(recv, Obj) and recv.kind == "alt":
                out = []
                for _k, alt in recv.attrs:
                    e = self.effect_of(call, recv_override=alt)
                    if e is not None:
                        out.append(e)
                return out
        e = self.effect_of(call)
        return [e] if e is not None else []

    def effect_of(self, call: ast.Call, recv_override: Value | None = None) -> _Effect | None:
        canon = self.canonical(call.func)
        args = call.args
        kw = {k.arg: k.value for k in call.keywords if k.arg}

        def arg(i: int | None, name: str) -> ast.expr | None:
            if name in kw:
                return kw[name]
            if i is not None and i < len(args) and not isinstance(args[i], ast.Starred):
                return args[i]
            return None

        # module-level HTTP functions
        if canon in sdk.HTTP_CALLS:
            verb, url_i, meth_i = sdk.HTTP_CALLS[canon]
            return self._http_effect(canon, verb, arg(url_i, "url"), arg(meth_i, "method"))
        if canon in ("urllib.request.urlopen",):
            target = arg(0, "url")
            v = self.eval(target)
            if isinstance(v, Obj) and v.kind == "urllib.Request":
                m = _as_str(v.get("method") or Unknown("method"))
                return _Effect("http", "", v.get("url") or Unknown("url"), (m.known() or "").lower(), canon)
            data = arg(1, "data")
            return _Effect("http", "", v, "post" if data is not None else "get", canon)
        if canon and canon.startswith("openai.") and canon.count(".") >= 2 and not canon.startswith("openai.OpenAI"):
            # module-level client: openai.chat.completions.create(...)
            path = canon[len("openai."):]
            m = sdk.LLM_METHODS["openai"].get(path)
            if m:
                base = _as_str(self._env("OPENAI_BASE_URL", Str.lit("https://api.openai.com/v1"), call))
                return _Effect("http", "", base + Str.lit(m[1]), m[0], canon)
        if canon in sdk.LITELLM_FUNCS or canon in sdk.LITELLM_EMBED_FUNCS:
            model = self.eval(arg(0, "model")) if arg(0, "model") is not None else Unknown("model passed through **kwargs")
            base = arg(None, "api_base") or arg(None, "base_url")
            if base is not None:
                path = "/embeddings" if canon in sdk.LITELLM_EMBED_FUNCS else "/chat/completions"
                return _Effect("http", "", _join_url(_as_str(self.eval(base)), path), "post", canon)
            return _Effect("llm", "embed" if canon in sdk.LITELLM_EMBED_FUNCS else "chat", model, "post", canon)
        if canon in sdk.TIKTOKEN_GET_ENCODING or canon in sdk.TIKTOKEN_FOR_MODEL:
            v = self.eval(arg(0, "encoding_name" if canon in sdk.TIKTOKEN_GET_ENCODING else "model_name"))
            name = v.known() if isinstance(v, Str) else None
            if name is not None and canon in sdk.TIKTOKEN_FOR_MODEL:
                name = next((enc for prefix, enc in sdk.TIKTOKEN_MODEL_PREFIXES if name.startswith(prefix)), None)
            url = sdk.TIKTOKEN_ENCODINGS.get(name or "")
            return _Effect("http", "", Str.lit(url) if url else Str((Unknown("tiktoken encoding"),)), "get", canon)
        if canon in ("builtins.open", "io.open", "codecs.open"):
            mode = self.eval(arg(1, "mode"))
            mode_s = mode.known() if isinstance(mode, Str) else None
            if mode_s is None and arg(1, "mode") is None:
                return None  # read
            if mode_s is not None and not any(c in mode_s for c in "wax+"):
                return None
            return _Effect("fs", "filesystem.write", self._path_value(arg(0, "file")), via=canon)
        if canon in sdk.FILE_WRITE_FUNCS:
            return _Effect("fs", "filesystem.write", self._path_value(arg(sdk.FILE_WRITE_FUNCS[canon], "dst")), via=canon)
        if canon in sdk.FILE_DELETE_FUNCS:
            return _Effect("fs", "filesystem.delete", self._path_value(arg(sdk.FILE_DELETE_FUNCS[canon], "path")), via=canon)
        if canon in sdk.PROCESS_FUNCS:
            return _Effect("exec", "process.exec", self._program_value(arg(0, "args")), via=canon)

        if isinstance(call.func, ast.Attribute) and call.func.attr in sdk.PYGITHUB_REQUESTER_METHODS \
                and isinstance(call.func.value, ast.Attribute) and call.func.value.attr in sdk.PYGITHUB_REQUESTER_ATTRS:
            # PyGithub's raw requester: requestJsonAndCheck(verb, url, ...); relative URLs are API paths.
            mv = self.eval(arg(0, "verb"))
            method = (mv.known() or "").lower() if isinstance(mv, Str) else ""
            url = _as_str(self.eval(arg(1, "url")))
            first = url.parts[0] if url.parts else ""
            if isinstance(first, str) and first.startswith("/"):
                url = Str.lit("https://api.github.com") + url
            return _Effect("http", "", url, method, f"PyGithub requester.{call.func.attr}")
        if isinstance(call.func, ast.Attribute):
            attr = call.func.attr
            recv = recv_override if recv_override is not None else self.eval(call.func.value)
            if isinstance(recv, Obj):
                kind = recv.kind
                if kind in ("requests.Session", "requests.sessions.Session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession"):
                    key = f"{kind}.{attr}"
                    if key in sdk.HTTP_CALLS:
                        verb, url_i, meth_i = sdk.HTTP_CALLS[key]
                        if verb is None:
                            url_i = 1
                        else:
                            url_i = 0
                        return self._http_effect(key, verb, arg(url_i, "url"), arg(meth_i, "method"), base=recv.get("base_url"))
                if kind.startswith("llm:"):
                    provider = kind[4:]
                    table = sdk.LLM_METHODS.get(provider) or sdk.LLM_METHODS.get(provider.split(".")[0], {})
                    path = (_attr_path(recv) + "." + attr).lstrip(".")
                    m = table.get(path)
                    if m:
                        base = _as_str(recv.get("base_url") or Unknown("base URL"))
                        via = (_as_str(recv.get("_via")).known() or provider) + "." + path
                        return _Effect("http", "", _join_url(base, m[1]), m[0], via)
                if kind.startswith("gh:"):
                    gk = kind[3:]
                    action = sdk.PYGITHUB_EFFECTS.get((gk, attr))
                    if action is None and gk == "Github" and attr == "get_repo":
                        repo = self.eval(arg(0, "full_name_or_id"))
                        return _Effect("github", "github.repo.read", _as_str(repo), via="PyGithub Github.get_repo")
                    if action is None and gk in ("Repository", "PullRequest", "Issue") and attr.startswith(("get_", "compare")):
                        # authenticated reads release the token too: they need github.repo.read on the repository
                        return _Effect("github", "github.repo.read", recv.get("repo") or Unknown("repository"), via=f"PyGithub {gk}.{attr}")
                    if action:
                        via = f"PyGithub {gk}.{attr}"
                        if gk == "AuthenticatedUser":
                            return _Effect("github", action, Str(()), via=via, account=True)
                        if gk == "Organization":
                            return _Effect("github", action, recv.get("owner") or Unknown("organization"), via=via, owner_only=True)
                        return _Effect("github", action, recv.get("repo") or Unknown("repository"), via=via)
                if kind == "Path":
                    if attr in sdk.PATH_WRITE_METHODS or (attr == "open" and self._open_mode_writes(call)):
                        return _Effect("fs", "filesystem.write", recv.get("path") or Unknown("path"), via=f"pathlib.Path.{attr}")
                    if attr in sdk.PATH_DELETE_METHODS:
                        return _Effect("fs", "filesystem.delete", recv.get("path") or Unknown("path"), via=f"pathlib.Path.{attr}")
                if kind == "smtp" and attr in sdk.SMTP_SEND_METHODS:
                    return _Effect("email", "email.send", recv.get("host") or Unknown("host"), via=f"smtplib.SMTP.{attr}")
        return None

    def _open_mode_writes(self, call: ast.Call) -> bool:
        mode = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "mode"), None)
        v = self.eval(mode) if mode is not None else None
        s = v.known() if isinstance(v, Str) else None
        return bool(s and any(c in s for c in "wax+"))

    def _http_effect(self, via: str, verb: str | None, url_expr: ast.expr | None, method_expr: ast.expr | None,
                     base: Value | None = None) -> _Effect:
        url = _as_str(self.eval(url_expr))
        if base is not None:
            b = _as_str(base)
            known_url = url.parts[0] if url.parts and isinstance(url.parts[0], str) else ""
            if "://" not in known_url:
                url = _join_url(b, url)
        if verb is not None:
            method = verb
        else:
            mv = self.eval(method_expr)
            method = (mv.known() or "").lower() if isinstance(mv, Str) else ""
        return _Effect("http", "", url, method, via)

    def _path_value(self, e: ast.expr | None) -> Value:
        v = self.eval(e)
        if isinstance(v, Obj) and v.kind == "Path":
            return v.get("path") or Unknown("path")
        return v

    def _program_value(self, e: ast.expr | None) -> Value:
        if isinstance(e, (ast.List, ast.Tuple)) and e.elts:
            return self.eval(e.elts[0])
        v = self.eval(e)
        return v


def _attr_path(obj: Obj) -> str:
    v = obj.get("_attr_path")
    return v.known() or "" if isinstance(v, Str) else ""


def _join_url(base: Str, path: Str | str) -> Str:
    p = Str.lit(path) if isinstance(path, str) else path
    bk = base.parts[-1] if base.parts else ""
    pk = p.parts[0] if p.parts else ""
    if isinstance(bk, str) and isinstance(pk, str):
        if bk.endswith("/") and pk.startswith("/"):
            p = Str((pk[1:],) + p.parts[1:], p.sources)
        elif not bk.endswith("/") and not pk.startswith("/") and pk:
            p = Str.lit("/") + p
    return base + p


def _is_none(v: Value) -> bool:
    return isinstance(v, Unknown) and v.reason == "None"


def _join(vals: list[Value], what: str) -> Value:
    """One value from several definitions. Equal values join to that value; objects of one kind join to that
    kind (attributes kept only where every definition agrees); ``None`` is ignored for objects. Different
    strings never join: the result is unknown, never an alternative widened into authority."""
    vals = [v for v in vals if not _is_none(v)] or vals
    if not vals:
        return Unknown(f"{what} has no definition")
    first = vals[0]
    if all(v == first for v in vals):
        return first
    if all(isinstance(v, Obj) for v in vals) and len({v.kind for v in vals}) > 1:  # type: ignore[union-attr]
        flat: list[Obj] = []
        for v in vals:
            for alt in ([a for _k, a in v.attrs] if v.kind == "alt" else [v]):  # type: ignore[union-attr]
                if isinstance(alt, Obj) and alt not in flat:
                    flat.append(alt)
        if len(flat) <= 8:
            return Obj("alt", tuple((f"alt{i}", a) for i, a in enumerate(flat)))
    if all(isinstance(v, Obj) for v in vals) and len({v.kind for v in vals}) == 1:  # type: ignore[union-attr]
        keys = [k for k, _ in first.attrs]  # type: ignore[union-attr]
        attrs = []
        for k in keys:
            got = [v.get(k) for v in vals]  # type: ignore[union-attr]
            attrs.append((k, got[0] if all(g == got[0] for g in got) else Unknown(f"{what}.{k} differs between definitions", k)))
        return Obj(first.kind, tuple(attrs))  # type: ignore[union-attr]
    return Unknown(f"{what} is assigned more than once with different values", what.strip("'"))


def _own_returns(fn: ast.AST) -> list[ast.Return]:
    """Return statements of ``fn`` itself (not of nested functions or classes)."""
    out: list[ast.Return] = []
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(n, ast.Return) and n.value is not None:
            out.append(n)
        stack.extend(ast.iter_child_nodes(n))
    return out


def _with_source(v: Value, src: ValueSource) -> Value:
    if isinstance(v, Str) and src not in v.sources:
        return Str(v.parts, (src,) + v.sources)
    return v


def _percent_format(fmt: str, args: list[Str]) -> Value:
    out = Str(())
    pieces = fmt.split("%s")
    if len(pieces) - 1 != len(args):
        return Unknown("%-format")
    for i, piece in enumerate(pieces):
        out = out + Str.lit(piece)
        if i < len(args):
            out = out + args[i]
    return out


def _str_format(fmt: str, args: list[Str], kwargs: dict[str, Str]) -> Value:
    import string

    out = Str(())
    auto = 0
    try:
        for literal, field_name, spec, conv in string.Formatter().parse(fmt):
            out = out + Str.lit(literal)
            if field_name is None:
                continue
            if field_name == "":
                val = args[auto] if auto < len(args) else Str((Unknown("format argument"),))
                auto += 1
            elif field_name.isdigit():
                idx = int(field_name)
                val = args[idx] if idx < len(args) else Str((Unknown("format argument"),))
            else:
                val = kwargs.get(field_name, Str((Unknown(f"format field {field_name}", field_name),)))
            out = out + val
    except ValueError:
        return Unknown("format string")
    return out


# ---------------------------------------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------------------------------------


def load_env_files(root: Path, names: Iterable[str] = (".env", ".env.local")) -> tuple[dict[str, str], list[str]]:
    env: dict[str, str] = {}
    used: list[str] = []
    for n in names:
        p = root / n
        if not p.is_file():
            continue
        used.append(n)
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            line = line.removeprefix("export ")
            k, _, v = line.partition("=")
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            env[k.strip()] = v
    return env, used


def extract_authority(root: str | os.PathLike[str], *, env: dict[str, str] | None = None,
                      include_tests: bool = False, read_env_files: bool = True) -> AuthorityReport:
    """Structured authority evidence for every consequential effect in the Python code under ``root``.

    ``env`` is the project configuration to resolve ``os.environ`` lookups with (for example the environment
    the agent will run with). ``.env``/``.env.local`` in ``root`` are read too unless ``read_env_files`` is
    false; explicit ``env`` values win.
    """
    root_p = Path(root).resolve()
    merged: dict[str, str] = {}
    used: list[str] = []
    if read_env_files:
        merged, used = load_env_files(root_p)
    merged.update(env or {})
    ex = Extractor(root_p, env=merged, include_tests=include_tests)
    report = ex.run()
    report.env_files = used
    report.evidence.sort(key=lambda ev: (ev.file, ev.line, ev.col, ev.action, ev.resource or ""))
    return report
