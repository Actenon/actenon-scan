#!/usr/bin/env python3
"""Re-check every AGENT_REACHABLE case against the FULL scanner.

build_inventory.py measures the per-file reachability layer. The real
scan_path ALSO runs the repository layer (transitive call graph, on by
default for directory targets). This script closes that gap: it runs the
full directory scan and asks, for each hand-labelled AGENT_REACHABLE case,
whether the scanner actually reports it.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "research/reachability-ground-truth"
sys.path.insert(0, str(ROOT))
from actenon_scan.engine import scan_path

corpus = Path(sys.argv[1])
labels = json.loads((HERE / "labels.json").read_text())
reach = [x for x in labels if x["label"] == "AGENT_REACHABLE"]
by_repo = defaultdict(list)
for x in reach: by_repo[x["repo_name"]].append(x)

out, followed_tot, unfollowed_tot = [], 0, 0
for repo_name, cases in sorted(by_repo.items()):
    base = corpus / repo_name
    res = scan_path(base)
    act = [f for f in res.findings if not f.suppressed]
    fol = getattr(res, "transitive_followed_count", 0)
    unf = getattr(res, "transitive_unfollowed_count", 0)
    followed_tot += fol; unfollowed_tot += unf
    hits = {(f.file.replace("\\", "/"), f.line) for f in act}
    for x in cases:
        key = (x["file"].replace("\\", "/"), x["line"])
        caught = key in hits
        x2 = dict(x); x2["caught_by_full_scan"] = caught
        out.append(x2)
        print(f"  {'CAUGHT ' if caught else 'MISSED '} [{x['idx']:3d}] {repo_name:16s} "
              f"{x['file'][-46:]}:{x['line']}  {x['mechanism']}", flush=True)
    print(f"     -- {repo_name}: {len(act)} findings, transitive followed={fol} unfollowed={unf}", flush=True)

(HERE / "full_scan_check.json").write_text(json.dumps({
    "transitive_followed_total": followed_tot,
    "transitive_unfollowed_total": unfollowed_tot,
    "cases": out}, indent=1))
c = sum(1 for x in out if x["caught_by_full_scan"])
print(f"\nAGENT_REACHABLE cases caught by the FULL scanner: {c}/{len(out)}")
print(f"transitive followed total={followed_tot}  unfollowed total={unfollowed_tot}")
