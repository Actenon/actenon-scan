#!/usr/bin/env python3
"""Emit explicit boundary->sink call chains for each sampled case.

Edges are real AST call edges (a Call node inside the caller's body). Callee
resolution is by NAME, so a chain is a CANDIDATE to verify by reading source,
never a label. Chains are printed with file:line for every hop so each edge
can be checked.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "research/reachability-ground-truth"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))
from evidence import RepoIndex


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", required=True, type=Path)
    args = ap.parse_args()
    sample = json.loads((HERE / "sample.json").read_text())["rows"]
    by_repo = defaultdict(list)
    for r in sample: by_repo[r["repo_name"]].append(r)

    out = []
    for repo_name, rws in sorted(by_repo.items()):
        idx = RepoIndex(args.corpus_dir / repo_name)
        for r in rws:
            fn = r["enclosing_function"]
            chains = []
            if fn:
                # BFS backwards keeping the path
                start = [(fn, [])]
                seen = set()
                for depth in range(4):
                    nxt = []
                    for nm, path in start:
                        for rec in idx.calls_to.get(nm, []):
                            key = (rec["file"], rec["line"], nm)
                            if key in seen: continue
                            seen.add(key)
                            hop = {"callee": nm, "caller": rec["name"],
                                   "caller_class": rec["class"],
                                   "file": rec["file"], "line": rec["line"],
                                   "decorators": rec["decorators"]}
                            newpath = path + [hop]
                            b = idx.boundary_kind(rec)
                            if b:
                                chains.append({"boundary": b, "hops": newpath})
                            else:
                                nxt.append((rec["name"], newpath))
                    start = nxt
                    if not start: break
            out.append({"id": r["id"], "repo_name": repo_name, "file": r["file"],
                        "line": r["line"], "rule_id": r["rule_id"],
                        "enclosing_function": fn, "enclosing_class": r["enclosing_class"],
                        "tier": r["tier"], "chains": chains[:6], "n_chains": len(chains)})
        print(f"  {repo_name:22s} done", flush=True)
    (HERE / "chains.json").write_text(json.dumps(out, indent=1))
    print(f"\n{len(out)} cases, {sum(1 for c in out if c['chains'])} with >=1 candidate chain")
    return 0


if __name__ == "__main__":
    sys.exit(main())
