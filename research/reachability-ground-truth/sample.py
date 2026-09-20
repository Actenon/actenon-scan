#!/usr/bin/env python3
"""Draw a deterministic stratified sample from the unreachable-sink inventory.

Strata are (repository x consequence category) cells. Cells are visited
round-robin so that neither an enormous repository (openhands 590, llamaindex
584, agno 447 -- 52% of the inventory between them) nor a single generic rule
(DATA-DELETE-SQL, 25%) can dominate the sample.

Round-robin allocation deliberately OVER-samples small strata relative to their
population share. Each row therefore carries `weight` = N_h / n_h, the inverse
inclusion probability within its stratum, so a population estimate can be
recovered by weighting. The unweighted sample statistic is a statement about
the SAMPLE, not about the inventory; both are reported separately.

Seed: 20260920. Re-running reproduces the identical sample.
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "research/reachability-ground-truth"
SEED = 20260920
TARGET = 160


def main() -> int:
    inv = json.loads((HERE / "unreachable_inventory.json").read_text())
    rows = inv["rows"]

    cells: dict[tuple[str, str], list] = defaultdict(list)
    for r in rows:
        cells[(r["repo_name"], r["category"])].append(r)

    rng = random.Random(SEED)
    # Deterministic cell order, and a deterministic shuffle inside each cell.
    order = sorted(cells.keys())
    for k in order:
        cells[k].sort(key=lambda r: r["id"])
        rng.shuffle(cells[k])

    # Round-robin draw.
    picked, cursor = [], {k: 0 for k in order}
    while len(picked) < TARGET:
        progressed = False
        for k in order:
            if len(picked) >= TARGET:
                break
            i = cursor[k]
            if i < len(cells[k]):
                picked.append((k, cells[k][i]))
                cursor[k] = i + 1
                progressed = True
        if not progressed:
            break  # inventory exhausted

    n_h = defaultdict(int)
    for k, _ in picked:
        n_h[k] += 1

    out = []
    for k, r in picked:
        row = dict(r)
        row["stratum"] = f"{k[0]}|{k[1]}"
        row["stratum_N"] = len(cells[k])
        row["stratum_n"] = n_h[k]
        row["weight"] = len(cells[k]) / n_h[k]
        out.append(row)
    out.sort(key=lambda r: r["id"])

    (HERE / "sample.json").write_text(json.dumps({
        "_meta": {
            "seed": SEED, "target": TARGET, "drawn": len(out),
            "method": "round-robin over (repo x category) strata; "
                      "within-stratum order = sort by id then Random(seed).shuffle",
            "inventory_rows": len(rows), "strata": len(order),
            "weighting": "weight = stratum_N / stratum_n (inverse inclusion probability)",
        },
        "rows": out,
    }, indent=1))

    from collections import Counter
    print(f"drawn {len(out)} from {len(rows)} across {len(order)} strata")
    for key in ("repo_name", "category", "rule_id", "tier", "enclosing_kind", "repo_category"):
        c = Counter(r[key] for r in out)
        top = c.most_common(1)[0]
        print(f"  {key:15s} {len(c):2d} distinct   max={top[1]:3d} ({top[1]/len(out):4.1%}) {top[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
