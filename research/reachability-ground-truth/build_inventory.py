#!/usr/bin/env python3
"""Enumerate consequential sinks the scanner currently does NOT consider agent-reachable.

Mirrors actenon_scan.engine.scan_path exactly up to the reachability gate:
same file collection, same sink matcher, same reachability detector, same
self-package suppression. A sink lands in the inventory when detect_reachability
returns confidence "none" -- the precise population "Actenon currently considers
unreachable".

Reproducible: corpus is pinned by SHA in tests/benchmark/pinned_repos.json.

Usage:
    python research/reachability-ground-truth/build_inventory.py --corpus-dir DIR
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from actenon_scan.detectors.reachability import detect_reachability
from actenon_scan.detectors.sinks import detect_sinks
from actenon_scan.engine import (
    _assign_tier,
    _build_parent_map_for_engine,
    _collect_files,
    _detect_self_package,
    _reachability_markers,
)
from actenon_scan.rules.loader import load_rules

PINNED = ROOT / "tests/benchmark/pinned_repos.json"


def enclosing_def(tree: ast.Module, line: int):
    """Innermost enclosing function/method, plus its class if any."""
    best = best_cls = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            e = getattr(node, "end_lineno", None)
            if e and node.lineno <= line <= e:
                if best_cls is None or node.lineno > best_cls.lineno:
                    best_cls = node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            e = getattr(node, "end_lineno", None)
            if e and node.lineno <= line <= e:
                if best is None or node.lineno > best.lineno:
                    best = node
    return best, best_cls


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", required=True, type=Path)
    ap.add_argument("--out", type=Path,
                    default=ROOT / "research/reachability-ground-truth/unreachable_inventory.json")
    args = ap.parse_args()

    rules = load_rules(None)
    markers = _reachability_markers(rules.reachability)
    pinned = json.loads(PINNED.read_text())

    rows: list[dict] = []
    stats = {"files_scanned": 0, "files_skipped_shortcircuit": 0, "parse_errors": 0,
             "sinks_total": 0, "sinks_unreachable": 0, "sinks_reachable": 0}
    per_repo = defaultdict(lambda: Counter())

    for entry in pinned["repos"]:
        name, sha, repo = entry["name"], entry["sha"], entry["repo"]
        base = args.corpus_dir / name
        if not base.exists():
            print(f"MISSING {name}", file=sys.stderr)
            continue
        self_pkg = _detect_self_package(base)
        files = _collect_files(base, None, None)
        for fp in files:
            rel = str(fp.relative_to(base))
            try:
                source = fp.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                stats["parse_errors"] += 1
                continue
            stats["files_scanned"] += 1
            try:
                tree = ast.parse(source, filename=str(fp))
            except SyntaxError:
                stats["parse_errors"] += 1
                continue

            # Engine short-circuit: no reachability marker anywhere in the
            # file means no sink in it can be reachable. Such files are not
            # part of the "considered and rejected" population, but we count
            # them so the denominator is auditable.
            if not any(m in source for m in markers):
                stats["files_skipped_shortcircuit"] += 1

            try:
                pm = _build_parent_map_for_engine(tree)
                sinks = detect_sinks(tree, str(fp), rules.sinks, parent_map=pm)
            except Exception as exc:  # detector crash -- record, never swallow
                stats["parse_errors"] += 1
                print(f"DETECTOR-ERROR {name}/{rel}: {exc}", file=sys.stderr)
                continue
            if not sinks:
                continue

            lines = source.splitlines()
            for sf in sinks:
                stats["sinks_total"] += 1
                try:
                    reach = detect_reachability(tree, sf.line, rules.reachability,
                                                self_package=self_pkg)
                except Exception as exc:
                    print(f"REACH-ERROR {name}/{rel}:{sf.line}: {exc}", file=sys.stderr)
                    continue
                if reach.confidence != "none":
                    stats["sinks_reachable"] += 1
                    per_repo[name]["reachable"] += 1
                    continue

                stats["sinks_unreachable"] += 1
                per_repo[name]["unreachable"] += 1
                fn, cls = enclosing_def(tree, sf.line)
                snippet = lines[sf.line - 1].strip() if 0 < sf.line <= len(lines) else ""
                rows.append({
                    "id": f"{name}:{rel}:{sf.line}:{sf.rule_id}",
                    "repo": repo, "repo_name": name, "sha": sha,
                    "file": rel, "line": sf.line,
                    "rule_id": sf.rule_id, "category": sf.category,
                    "severity": sf.severity,
                    "call_text": (sf.call_text or snippet)[:300],
                    "source_line": snippet[:300],
                    "enclosing_function": fn.name if fn else None,
                    "enclosing_is_async": isinstance(fn, ast.AsyncFunctionDef) if fn else None,
                    "enclosing_class": cls.name if cls else None,
                    "enclosing_kind": ("method" if (fn and cls) else "function" if fn else "module"),
                    "reachability": reach.confidence,
                    "reachability_signals": list(reach.signals),
                    "tier": _assign_tier(rel),
                    "repo_category": entry["category"],
                })
        print(f"  {name:22s} unreachable={per_repo[name]['unreachable']:6d} "
              f"reachable={per_repo[name]['reachable']:5d}", flush=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "_meta": {
            "description": "Consequential sinks that detect_reachability scores 'none'.",
            "scanner_version": (ROOT / "pyproject.toml").read_text().split('version = "')[1].split('"')[0],
            "corpus": "tests/benchmark/pinned_repos.json (25 repos, pinned SHAs)",
            "stats": stats,
            "per_repo": {k: dict(v) for k, v in per_repo.items()},
        },
        "rows": rows,
    }, indent=1))
    print(f"\n{json.dumps(stats, indent=1)}")
    print(f"\ninventory -> {args.out}  ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
