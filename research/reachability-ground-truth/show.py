#!/usr/bin/env python3
"""Render evidence packs for manual inspection."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
packs = json.loads((HERE / "evidence.json").read_text())
sel = sys.argv[1] if len(sys.argv) > 1 else "all"
lo, hi = (0, 10**9)
if ":" in sel: lo, hi = (int(x) if x else d for x, d in zip(sel.split(":"), ("0", "999999")))
elif sel.isdigit(): lo, hi = int(sel), int(sel) + 1
elif sel != "all":
    packs = [p for p in packs if sel in p["id"]]; lo, hi = 0, 10**9
mode = sys.argv[2] if len(sys.argv) > 2 else "full"
for i, p in enumerate(packs):
    if not (lo <= i < hi): continue
    print("=" * 100)
    print(f"[{i}] {p['id']}")
    print(f"    {p['repo']}@{p['sha'][:10]}  {p['file']}:{p['line']}  {p['rule_id']} / {p['category']} / tier={p['tier']}")
    print(f"    enclosing: {p['enclosing_kind']} {p['enclosing_class'] or ''}.{p['enclosing_function']}  decorators={p['decorators']} bases={p['class_bases']}")
    print(f"    self_boundary={p['self_boundary']}  n_callers={p['n_callers']}  boundary_ancestors={len(p['boundary_ancestors'])}")
    if p["boundary_ancestors"]:
        print("    --- CANDIDATE BOUNDARY ANCESTORS ---")
        for b in p["boundary_ancestors"]:
            print(f"      d{b['depth']} {b['boundary']:38s} {b['class'] or ''}.{b['name']}  {b['file']}:{b['line']}")
    if mode == "full":
        if p["caller_sample"]:
            print("    --- callers (name-based, approximate) ---")
            for c in p["caller_sample"][:6]:
                print(f"      d{c['depth']} {c['class'] or ''}.{c['name']:28s} {c['file']}:{c['line']} {c['decorators'] or ''}")
        print(f"    --- imports --- {'; '.join(p['imports'][:8])}")
        print("    --- body ---")
        for ln in p["body"][:30]:
            print("      " + ln[:150])
    print()
