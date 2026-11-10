"""Compare TS findings across ablation variants. Prints per-target counts and every finding not in the frozen baseline."""
import glob, json, os, sys
D = sys.argv[1]
def load(path):
    d = json.load(open(path))
    root = None
    out = set()
    for f in d["findings"]:
        fp = f["file"]
        for marker in ("/corpus/", "/snap/"):
            if marker in fp:
                fp = fp.split(marker, 1)[1].split("/", 1)[1]
        out.add((fp, f["line"], f["rule_id"]))
    return out, d.get("files_scanned"), d.get("analysis_errors") or []
targets = sorted({os.path.basename(p).split("__", 1)[1][:-5] for p in glob.glob(f"{D}/frozen__*.json")})
print(f"{'target':34} {'files':>5} {'frozen':>6} {'base':>5} {'g1':>4} {'g2':>4} {'both':>5}  errors(frozen/both)")
new = {}
for t in targets:
    row = {}
    for m in ("frozen", "base", "g1", "g2", "both"):
        p = f"{D}/{m}__{t}.json"
        row[m] = load(p) if os.path.exists(p) else (set(), 0, [])
    print(f"{t:34} {row['frozen'][1] or 0:5} {len(row['frozen'][0]):6} {len(row['base'][0]):5} {len(row['g1'][0]):4} {len(row['g2'][0]):4} {len(row['both'][0]):5}  {len(row['frozen'][2])}/{len(row['both'][2])}"
          + ("  BASE!=FROZEN" if row['base'][0] != row['frozen'][0] else ""))
    for m in ("g1", "g2", "both"):
        for x in sorted(row[m][0] - row["frozen"][0]):
            new.setdefault((t,) + x, set()).add(m)
    for x in sorted(row["frozen"][0] - row["both"][0]):
        print("   LOST in candidate:", x)
print("\nNEW findings vs frozen baseline (variant(s) producing it):")
for k in sorted(new): print("  ", k, sorted(new[k]))
