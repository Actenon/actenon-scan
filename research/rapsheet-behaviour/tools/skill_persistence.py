"""Cross-session persistence check for an MCP skill store (BREAKTHROUGH.md, "The effect is real").

Reads Claude Code session logs locally with Rapsheet's parser and prints COUNTS
and content HASHES only - never names' content, paths or values.

usage: python -I skill_persistence.py <path/to/rapsheet.py> <logs-dir> [server-name]
       (logs-dir is usually ~/.claude/projects; server-name defaults to "surface")
"""
import glob, hashlib, importlib.util, os, sys

rapsheet_py, logs = sys.argv[1], sys.argv[2]
server = sys.argv[3] if len(sys.argv) > 3 else "surface"
spec = importlib.util.spec_from_file_location("rapsheet", rapsheet_py)
rs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rs)

prefix = f"mcp__{server}__"
saves, reads = [], []
for path in sorted(glob.glob(os.path.join(logs, "**", "*.jsonl"), recursive=True)):
    session = hashlib.sha256(path.encode()).hexdigest()[:8]
    pending = {}
    for ev in rs.parse_claude(path):
        if ev.kind == "call" and ev.data["tool"] in (prefix + "save_skill", prefix + "read_skill"):
            pending[ev.data["id"]] = (ev.data["tool"][len(prefix):], ev.data["input"], ev.ts)
        elif ev.kind == "result" and ev.data.get("id") in pending:
            tool, inp, ts = pending.pop(ev.data["id"])
            out = ev.data.get("output") or ""
            if tool == "save_skill":
                h = hashlib.sha256(str(inp.get("content", "")).encode()).hexdigest()
                saves.append((ts, session, inp.get("name"), h, out == "saved"))
            else:
                reads.append((ts, session, inp.get("name"), hashlib.sha256(out.encode()).hexdigest()))

def earlier_other_session(read):
    ts, session, name, h = read
    return any(s[2] == name and s[0] < ts and s[1] != session and s[3] == h for s in saves)

print("save_skill calls:", len(saves), "| returned 'saved':", sum(s[4] for s in saves),
      "| distinct sessions:", len({s[1] for s in saves}))
print("read_skill calls:", len(reads), "| byte-identical to content saved by an earlier, different session:",
      sum(1 for r in reads if earlier_other_session(r)))
