#!/usr/bin/env python3
"""Compute ground-truth statistics, the P01 measurement and mechanism ranking."""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
labels = json.loads((HERE / "labels.json").read_text())
inv = json.loads((HERE / "unreachable_inventory.json").read_text())
stats = inv["_meta"]["stats"]

R, N, A = "AGENT_REACHABLE", "NOT_AGENT_REACHABLE", "AMBIGUOUS"
c = Counter(x["label"] for x in labels)
n = len(labels)
reach = [x for x in labels if x["label"] == R]
amb = [x for x in labels if x["label"] == A]
web = [x for x in labels if x["web_route"]]

def wilson(k, m, z=1.96):
    if m == 0: return (0.0, 0.0)
    p = k / m
    d = 1 + z*z/m
    c0 = (p + z*z/(2*m)) / d
    h = z*math.sqrt(p*(1-p)/m + z*z/(4*m*m)) / d
    return (max(0.0, c0-h), min(1.0, c0+h))

out = {}
print("="*78); print("GROUND TRUTH"); print("="*78)
print(f"  Sample size:            {n}")
print(f"  AGENT_REACHABLE:        {c[R]}   ({c[R]/n:.1%})")
print(f"  NOT_AGENT_REACHABLE:    {c[N]}   ({c[N]/n:.1%})   of which web-route-only: {len(web)}")
print(f"  AMBIGUOUS:              {c[A]}   ({c[A]/n:.1%})")
print("  Actenon detected among AGENT_REACHABLE:  0  (BY CONSTRUCTION -- every")
print("      sampled row scored reachability 'none', so the sample contains no")
print("      detectable case. See the recall note below.)")
print(f"  Actenon missed among AGENT_REACHABLE:    {c[R]}")

lo, hi = wilson(c[R], n)
print("\n  Share of the UNREACHABLE inventory that is agent-reachable:")
print(f"    unweighted sample: {c[R]}/{n} = {c[R]/n:.1%}   (95% Wilson: {lo:.1%}-{hi:.1%})")

# Weighted (population) estimate over the 3,109-row inventory
W = sum(x["weight"] for x in labels)
Wr = sum(x["weight"] for x in reach)
Wa = sum(x["weight"] for x in amb)
est_missed = Wr
est_amb = Wa
print(f"    weighted estimate:  {Wr/W:.1%} of {stats['sinks_unreachable']} "
      f"-> ~{est_missed:.0f} agent-reachable sinks missed")
print(f"    weighted AMBIGUOUS: {Wa/W:.1%} -> ~{est_amb:.0f} further sinks unresolved")

detected = stats["sinks_reachable"]
r_lo = detected / (detected + est_missed + est_amb)
r_hi = detected / (detected + est_missed)
print("\n  REAL-WORLD RECALL (sink level, estimated):")
print(f"    currently reachable (detected) sinks: {detected}")
print(f"    estimated missed (AGENT_REACHABLE):   ~{est_missed:.0f}")
print(f"    recall if AMBIGUOUS all NOT reachable: {r_hi:.1%}")
print(f"    recall if AMBIGUOUS all ARE reachable: {r_lo:.1%}")
print(f"    => bracket: {r_lo:.0%} - {r_hi:.0%}")
out["recall_bracket"] = [r_lo, r_hi]

print("\n" + "="*78); print("FALSE-NEGATIVE MECHANISMS (observed counts, AGENT_REACHABLE only)"); print("="*78)
mech = Counter(x["mechanism"] for x in reach)
mrepo = defaultdict(set)
for x in reach: mrepo[x["mechanism"]].add(x["repo_name"])
mw = defaultdict(float)
for x in reach: mw[x["mechanism"]] += x["weight"]
print(f"  {'mechanism':26s} {'n':>3s} {'est.pop':>8s}  repos")
for m, k in mech.most_common():
    print(f"  {m:26s} {k:3d} {mw[m]:8.0f}  {len(mrepo[m])} ({', '.join(sorted(mrepo[m]))[:52]})")
out["mechanisms"] = dict(mech)

print("\n" + "="*78); print("P01 -- transitive local/interprocedural reachability"); print("="*78)
# P01 = a RECOGNISED agent boundary transitively calls a statically resolvable
# local function/method that reaches the sink. Case 11 (agno Workspace) is
# excluded: its boundary is not recognised at all (registration by getattr),
# so it is a boundary-recognition miss, not a transitive-call miss.
P01_IDX = {18, 31, 32, 53, 66, 89, 91, 102, 105, 106, 111, 154, 158, 159}
p01 = [x for x in reach if x["idx"] in P01_IDX]
print(f"  P01 instances: {len(p01)}/{c[R]} of AGENT_REACHABLE ({len(p01)/c[R]:.0%})")
print(f"  repositories affected: {len(set(x['repo_name'] for x in p01))} "
      f"({', '.join(sorted(set(x['repo_name'] for x in p01)))})")
print(f"  estimated population: ~{sum(x['weight'] for x in p01):.0f} sinks")
print("\n  per-case shape:")
DEPTH = {102:2,105:2,106:3,111:1,53:2,66:1,89:1,91:1,154:1,158:1,159:1,31:2,32:2,18:1}
XFILE = {102:True,105:False,106:False,111:False,53:False,66:False,89:False,91:False,
         154:True,158:False,159:False,31:True,32:True,18:True}
ASYNC = {102:False,105:True,106:True,111:True,53:True,66:True,89:False,91:False,
         154:False,158:False,159:False,31:True,32:True,18:False}
KIND  = {102:"method",105:"fn->method",106:"fn->fn",111:"function",53:"method",66:"method",
         89:"method",91:"method",154:"method",158:"method",159:"method",31:"method",
         32:"method",18:"method"}
print(f"  {'idx':>4s} {'repo':16s} {'depth':>5s} {'cross-file':>10s} {'async':>6s} {'kind':10s} mechanism")
for x in sorted(p01, key=lambda y: y["idx"]):
    i = x["idx"]
    print(f"  {i:4d} {x['repo_name']:16s} {DEPTH.get(i,'?'):>5} {XFILE.get(i,'?')!s:>10s} "
          f"{ASYNC.get(i,'?')!s:>6s} {KIND.get(i,'?'):10s} {x['mechanism']}")
d = Counter(DEPTH[x["idx"]] for x in p01 if x["idx"] in DEPTH)
print("\n  call depth distribution: " + ", ".join(f"depth {k}: {v}" for k, v in sorted(d.items())))
print(f"  cross-file: {sum(1 for x in p01 if XFILE.get(x['idx']))}/{len(p01)}   "
      f"same-file: {sum(1 for x in p01 if XFILE.get(x['idx']) is False)}/{len(p01)}")
print(f"  async:      {sum(1 for x in p01 if ASYNC.get(x['idx']))}/{len(p01)}   "
      f"sync: {sum(1 for x in p01 if ASYNC.get(x['idx']) is False)}/{len(p01)}")
print(f"  method:     {sum(1 for x in p01 if 'method' in KIND.get(x['idx'],''))}/{len(p01)}")

print("\n" + "="*78); print("BREAKDOWNS"); print("="*78)
for k in ("repo_name","category","rule_id","tier"):
    cc = Counter(x[k] for x in reach)
    print(f"  AGENT_REACHABLE by {k}: " + ", ".join(f"{a}={b}" for a, b in cc.most_common(8)))
print("\n  NOT_AGENT_REACHABLE reasons:")
for a, b in Counter(x["reason"] for x in labels if x["label"] == N).most_common():
    print(f"    {b:4d}  {a}")
print("\n  AMBIGUOUS reasons:")
for a, b in Counter(x["reason"] for x in labels if x["label"] == A).most_common():
    print(f"    {b:4d}  {a}")

(HERE / "analysis.json").write_text(json.dumps({
    "sample_size": n, "counts": dict(c), "web_route_only": len(web),
    "wilson_95_share_reachable": [lo, hi],
    "weighted_share_reachable": Wr / W,
    "inventory_unreachable": stats["sinks_unreachable"],
    "inventory_reachable": stats["sinks_reachable"],
    "estimated_missed_population": est_missed,
    "estimated_ambiguous_population": est_amb,
    "recall_bracket_low": r_lo, "recall_bracket_high": r_hi,
    "mechanisms": dict(mech),
    "p01_count": len(p01), "p01_share_of_reachable": len(p01) / c[R],
    "p01_estimated_population": sum(x["weight"] for x in p01),
}, indent=1))
print(f"\nanalysis -> {HERE/'analysis.json'}")
