"""Run the installed actenon-scan with one of its TS mechanisms disabled, for ablation.
usage: variant_scan.py {base|g1|g2|both} OUT.json PATH
  g1   = fs import-binding resolution only (schema dispatch disabled)
  g2   = schema dispatch only (fs binding resolution disabled)
  both = candidate as committed
  base = candidate with both disabled (must equal the frozen baseline; used as a sanity check)
Runs with --jobs 1 so the monkeypatch applies in-process."""
import sys
import actenon_scan.detectors.typescript as t
mode, out, path = sys.argv[1:4]
if mode in ("g2", "base"):
    t._resolve_fs_bindings = lambda root: {}
if mode in ("g1", "base"):
    t._ts_declared_tool_names = lambda root: set()
from actenon_scan.cli import main
sys.exit(main(["scan", path, "--format", "json", "--output", out, "--fail-on", "none", "--no-cache", "--jobs", "1",
               "--include", "*.ts", "--include", "*.tsx", "--include", "*.mts", "--include", "*.cts",
               "--include", "*.js", "--include", "*.jsx", "--include", "*.mjs", "--include", "*.cjs"]))
