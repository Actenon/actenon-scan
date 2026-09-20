#!/usr/bin/env python3
"""Build per-case evidence packs for manual reachability classification.

For each sampled sink this assembles the material a human needs to decide
whether an agent/tool/model-controlled execution boundary can reach it:

  * the enclosing function/method, its decorators and its class
  * the module's imports and any agent-boundary markers in the file
  * a REVERSE call graph: who calls the enclosing function, who calls them,
    to depth 4, annotated with each caller's decorators

The call graph is name-based and therefore APPROXIMATE. It exists to surface
candidate paths for inspection, never to assign a label. Every classification
in labels.json was made by reading the cited source.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "research/reachability-ground-truth"
sys.path.insert(0, str(ROOT))
from actenon_scan.engine import _collect_files
from actenon_scan.rules.loader import load_rules

RULES = load_rules(None)
RCFG = RULES.reachability
TOOL_DECOS = set(RCFG.get("tool_decorators", []))
RES_DECOS = set(RCFG.get("resource_boundary_decorators", []))
TOOL_BASES = set(RCFG.get("tool_base_classes", []))
TOOL_METHODS = set(RCFG.get("tool_methods", []))
TOOL_LIST_PARAMS = set(RCFG.get("tool_list_params", []))
SKIP = {".git", "__pycache__", ".venv", "node_modules", "build", "dist"}


def deco_name(n):
    if isinstance(n, ast.Name): return n.id
    if isinstance(n, ast.Attribute):
        parts = []
        cur = n
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr); cur = cur.value
        if isinstance(cur, ast.Name): parts.append(cur.id)
        return ".".join(reversed(parts))
    if isinstance(n, ast.Call): return deco_name(n.func)
    return ""


def callee_name(n):
    f = n.func
    if isinstance(f, ast.Name): return f.id
    if isinstance(f, ast.Attribute): return f.attr
    return None


class RepoIndex:
    """Name-keyed definition and call index for one repository."""

    def __init__(self, base: Path):
        self.base = base
        self.defs = defaultdict(list)       # func name -> [defrec]
        self.calls_to = defaultdict(list)   # callee name -> [defrec of caller]
        self.tool_list_names = set()        # names appearing in tools=[...]
        self._build()

    def _build(self):
        # Mirror the engine's file selection. Test files are excluded by
        # _collect_files, so a caller that lives in a test file is not part
        # of any path the scanner considers -- and a test harness is not an
        # agent boundary regardless. Including them produced spurious
        # `resource_boundary:patch` ancestors from unittest.mock's @patch.
        for fp in _collect_files(self.base, None, None):
            if SKIP & set(fp.parts): continue
            try:
                src = fp.read_text(encoding="utf-8")
                tree = ast.parse(src)
            except Exception:
                continue
            rel = str(fp.relative_to(self.base))
            lines = src.splitlines()
            cls_of, deco_of = {}, {}
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    for ch in ast.walk(node):
                        if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            cls_of.setdefault(id(ch), node)
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg in TOOL_LIST_PARAMS and isinstance(kw.value, (ast.List, ast.Tuple)):
                            for e in kw.value.elts:
                                if isinstance(e, ast.Name): self.tool_list_names.add(e.id)
                                elif isinstance(e, ast.Attribute): self.tool_list_names.add(e.attr)
                                elif isinstance(e, ast.Call):
                                    for a in e.args:
                                        if isinstance(a, ast.Name): self.tool_list_names.add(a.id)

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                cls = cls_of.get(id(node))
                rec = {
                    "name": node.name, "file": rel, "line": node.lineno,
                    "end": getattr(node, "end_lineno", node.lineno),
                    "decorators": [deco_name(d) for d in node.decorator_list],
                    "class": cls.name if cls else None,
                    "class_bases": [deco_name(b) for b in cls.bases] if cls else [],
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                }
                self.defs[node.name].append(rec)
                for ch in ast.walk(node):
                    if isinstance(ch, ast.Call):
                        cn = callee_name(ch)
                        if cn: self.calls_to[cn].append(rec)

    def boundary_kind(self, rec) -> str | None:
        """Is this definition itself an agent/resource entry point?"""
        for d in rec["decorators"]:
            if d in TOOL_DECOS or d.split(".")[-1] in {t.split(".")[-1] for t in TOOL_DECOS}:
                return f"tool_decorator:{d}"
            # HTTP-verb boundaries only count in attribute form (app.get,
            # org_router.post). A BARE @get/@patch/@delete is matched by the
            # real detector via last-segment suffix, which also matches
            # unittest.mock's @patch; that collision is recorded in
            # FINDINGS.md and is not treated as a boundary here.
            if "." in d and (d in RES_DECOS or d.split(".")[-1] in {t.split(".")[-1] for t in RES_DECOS}):
                return f"resource_boundary:{d}"
        if rec["class"] and rec["name"] in TOOL_METHODS:
            for b in rec["class_bases"]:
                if b in TOOL_BASES or b.split(".")[-1] in TOOL_BASES:
                    return f"tool_base_class:{b}.{rec['name']}"
        if rec["name"] in self.tool_list_names:
            return "tool_list_param"
        return None

    def callers_of(self, name, depth=4):
        """Reverse BFS. Returns [(depth, defrec, boundary_kind_or_None)]."""
        seen, out, frontier = set(), [], [name]
        for d in range(1, depth + 1):
            nxt = []
            for nm in frontier:
                for rec in self.calls_to.get(nm, []):
                    key = (rec["file"], rec["line"])
                    if key in seen: continue
                    seen.add(key)
                    out.append((d, rec, self.boundary_kind(rec)))
                    nxt.append(rec["name"])
            frontier = nxt
            if not frontier: break
        return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=HERE / "evidence.json")
    args = ap.parse_args()

    sample = json.loads((HERE / "sample.json").read_text())["rows"]
    by_repo = defaultdict(list)
    for r in sample: by_repo[r["repo_name"]].append(r)

    packs = []
    for repo_name, rws in sorted(by_repo.items()):
        base = args.corpus_dir / repo_name
        idx = RepoIndex(base)
        print(f"  {repo_name:22s} {len(idx.defs)} def-names, {len(rws)} cases", flush=True)
        for r in rws:
            fp = base / r["file"]
            try:
                lines = fp.read_text(encoding="utf-8").splitlines()
            except Exception:
                lines = []
            fn = r["enclosing_function"]
            # locate the enclosing def record for this exact site
            rec = None
            for cand in idx.defs.get(fn or "", []):
                if cand["file"] == r["file"] and cand["line"] <= r["line"] <= cand["end"]:
                    rec = cand; break
            callers = idx.callers_of(fn, depth=4) if fn else []
            boundary_hits = [(d, c, k) for d, c, k in callers if k]
            imports = [ln.strip() for ln in lines[:60]
                       if ln.startswith(("import ", "from "))][:18]
            body = []
            if rec:
                s, e = rec["line"] - 1, min(rec["end"], rec["line"] + 45)
                body = lines[s:e]
            packs.append({
                "id": r["id"], "repo_name": repo_name, "repo": r["repo"], "sha": r["sha"],
                "file": r["file"], "line": r["line"], "rule_id": r["rule_id"],
                "category": r["category"], "tier": r["tier"],
                "enclosing_function": fn, "enclosing_class": r["enclosing_class"],
                "enclosing_kind": r["enclosing_kind"],
                "source_line": r["source_line"],
                "self_boundary": idx.boundary_kind(rec) if rec else None,
                "decorators": rec["decorators"] if rec else [],
                "class_bases": rec["class_bases"] if rec else [],
                "imports": imports,
                "body": body[:46],
                "n_callers": len(callers),
                "boundary_ancestors": [
                    {"depth": d, "name": c["name"], "file": c["file"], "line": c["line"],
                     "class": c["class"], "decorators": c["decorators"], "boundary": k}
                    for d, c, k in boundary_hits[:8]
                ],
                "caller_sample": [
                    {"depth": d, "name": c["name"], "file": c["file"], "line": c["line"],
                     "class": c["class"], "decorators": c["decorators"]}
                    for d, c, k in callers[:10]
                ],
            })

    args.out.write_text(json.dumps(packs, indent=1))
    withb = sum(1 for p in packs if p["boundary_ancestors"])
    print(f"\n{len(packs)} packs -> {args.out}")
    print(f"  with >=1 candidate boundary ancestor: {withb}")
    print(f"  with no caller found at all:          {sum(1 for p in packs if p['n_callers']==0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
