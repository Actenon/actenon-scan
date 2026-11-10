# SCAN-GAPS — demonstrated misses, uncertainties, ranked opportunities

Baseline: Actenon Scan `ef8487a`. Every source snapshot below was scanned with
it: `actenon-scan scan <dir> --format json --fail-on none --no-cache`.

| Snapshot | Why it qualifies | Baseline result |
|---|---|---|
| Repo A @ `202bcaf`, `5033ec5`, `0e5c96b`, `b8b460b` | The commits live while rows 25–27 and 30 ran (calls 02:29–18:42 UTC on 17 Oct; `surface.ts` committed at 10:04 UTC, unchanged until `b8b460b` the next day) | 0 findings in any agent-tool file |
| Repo A @ HEAD `49e8e70` | Current state | 1 finding (a demo `execSync`) |
| Repo B @ `b0f6951` | Committed 57 s before rows 28–29 | 0 findings |
| Repo B @ HEAD, Repos C, D, E @ HEAD | Holdout: not examined before the change was written | Repo C: 6 TS/JS findings, none in its two hand-written MCP dispatch files; B, D, E: 0 |
| 10 TS-bearing pinned corpus repos | Third-party code | 11 findings, 5,636 files |

Classification uses the repository's own adjudication rules
(`research/reachability-ground-truth/ADJUDICATION_RULES.md`): a sink is
AGENT_REACHABLE only through a concrete, repository-local path from a boundary
that exposes the function to a model, and an MCP `tools/call` handler is such a
boundary. A CLI `main()`, a harness, or internal plumbing is not.

## Demonstrated cases

| ID | Class | Case | Root cause (verified, not inferred) | Status |
|---|---|---|---|---|
| G1 | **VERIFIED MISS** | Hand-written MCP server, `surface.ts`: `tools` schema literal + `call(name, a)` with `if (name === "save_skill" && <store>) { writeFileSync(<store path>, args.content) }` and `if (name === "http_get") { … fetch(u) }`. 31 + 13 recorded calls (rows 25, 27). | TS reachability recognises only SDK text signals (`setRequestHandler`, `registerTool`, `server.tool`, `tool(`, `execute:`, …). Raw tool-schema dispatch (r07) exists only in the Python detector. A line-for-line Python transliteration **is** flagged by the same baseline (FILE-OPEN-WRITE + NET-EGRESS), so the architecture is in declared scope and the gap is language parity. Every sink in the file evaluates `reachable=False`; the file is analysed (1 file, 0 errors, not excluded, TS extra present). | **Fixed** (`5020b44`) |
| G2 | **VERIFIED MISS** | `import { writeFileSync } from "node:fs"; writeFileSync(p, c)`, including inside a recognised `setRequestHandler(CallToolRequestSchema, …)` handler, the COVERED r02 architecture. `rmSync`, `fs/promises` named imports, `import * as nodefs`, `require` destructuring: all unmatched. | FILE-WRITE / DATA-DELETE-FILE patterns are `fs.*`-qualified; the matcher is exact-or-suffix on the call text, with no import resolution (unlike `child_process`, which has it). Required for G1's `save_skill` write. | **Fixed** (`ad07a60`) |
| G3 | **FALSE POSITIVE** (baseline, partly latent) | Repo C demo: `execSync("<constant command>")`, a constant command in a demo function, is a HIGH EXEC-SHELL finding. Repo A: two benchmark-harness evidence writes and three trace-log writes become findings as soon as G2 is fixed. | `_is_tool_handler` treats any `tool(` substring in a function body as a registration: `client.tool("name", args)` (an MCP **client** call) and `registry.tool(id)` (a lookup) qualify. `_is_inline_handler` treats any `execute:` within 3 lines as a Vercel handler: `authority: { execute: programs }` qualifies. | **Fixed** (`de06061`) |
| G4 | **VERIFIED MISS, not fixed** | Repo B `src/mcp.js`: `switch (name) { case "<edit tool>": return edit(…); case "<run tool>": return run(…) }`; the sinks are in `src/workspace.js` and `src/sandbox.js` (`rmSync`, atomic write, `spawn`). Rows 28–29 are real executions. Repo A `run_program` → `sandbox.run(...)` (row 26) is the same shape one level harder. | The r07 signal (now in both languages) is per-function: the sink must be inside the selected branch. The cross-file layer (`cross_language_reach.py`) only starts from SDK-registered handlers, so a dispatch branch that calls into another module is never an entrypoint. The candidate still reports 0 for Repo B; this is intended, and pinned by `test_sink_in_a_helper_outside_the_dispatcher_is_not_lifted_here`. | Open: **ranked #1** |
| G5 | **VERIFIED MISS** (third-party; found while searching for holdouts, not via Rapsheet) | `modelcontextprotocol/servers@d31124c` filesystem server: `registerTool("write_file", …, async (args) => { … await writeFileContent(validPath, args.content) })`, where `writeFileContent` in `lib.ts` calls `fs.writeFile`. No finding, no capability. | `import … from "./lib.js"` is the NodeNext convention for a `lib.ts` source; the TS index does not map `.js` specifiers to `.ts` files. All 33 local calls in that server are `unresolved_local_call`. This is disclosed in `local_calls_unfollowed`, so it is not silent. | Open: **ranked #2** |
| G6 | DOCUMENTED LIMITATION | Repo A runtime: its run tool, given a capability id, resolves a capability from a learned graph and dispatches to a reflector (row 30). The same runtime published to GitHub by learning GitHub's OpenAPI description and driving the operations through its generic network reflector (U1). | Registry / data-driven dispatch. The HTTP method and URL are data at runtime, so URL-gated rules (GITHUB-REST-MUTATION) cannot fire. `docs/COVERAGE.md` "Dynamic dispatch". | Out of reach for this design |
| G7 | DOCUMENTED LIMITATION | `const sandbox = await <factory>(); … sandbox.run(program, args)` (row 26) | Method call on a value returned by a factory in another module: the receiver's type is not inferred. | Out of reach without type inference |
| G8 | Guard recognition (precision-relevant) | Source-level authority checks reported as "no guard": `if (u.origin !== ORIGIN) return "refused"` (G1's `http_get`), a path-containment helper (Repo C), operator-grant lookups (Repo B), a per-tool refusal check (Repo A host). | Guards are recognised by name. These are allowlist / containment checks with an early `return`/`throw`, a structural shape, not a vocabulary word. They narrow the action; none binds it to an authorisation, and none is cryptographic. Users can register them with `--guard`. | Open: ranked #4 |
| G9 | UNRESOLVED | Module-level JSON-RPC loops: `for await (const line of stdin) { … if (msg.method === "tools/call") … }` with the effect at module scope (`direct-surface.ts@202bcaf`'s `run_program`; Repo A hosts' per-call trace logs). | Module-level sinks need `setRequestHandler`/`registerTool` text. `method === "tools/call"` is the MCP protocol's own boundary, but recognising it needs care: clients, proxies and test doubles contain the same string. | Needs an experiment (below) |
| G10 | UNRESOLVED | `runtime.<callback> = entry => appendFileSync(log, …)`: a callback the runtime invokes on every tool call. | Callback-by-assignment registration is not modelled. Plausibly AGENT_REACHABLE; not adjudicated here. | — |
| G11 | Observation (Python) | Python r07 accepts a sink in the `else` branch of `if name == "<declared>"` (`_stmts_contain_line(node.orelse, …)`), although its own comment says the sink must sit in the branch the name selects. | The TS port is stricter on purpose. Python was not changed: no measured false positive, and changing it changes Python output. | Recorded |
| G12 | Observation | `if (name === ToolName.ECHO)`: declared names reached through an enum or constant. | Only string literals are compared. | Recorded |
| G13 | Reporting | "N transitively-reachable sinks caught" prints a count of followed call edges. The baseline prints "1 … caught" beside 0 findings. | Label/field mismatch in the summary line. | Recorded (BASELINE.md) |

### The investigation areas, answered

1. **Dynamic dispatch and custom agent loops.** The recorded executions that
   ran through repository code all went through hand-written MCP dispatchers
   (G1, G4, G9) or a capability registry (G6). r05 ("LLM output reaches a
   sink") did not occur: no recorded operation passed raw model text to a sink
   outside a tool boundary.
2. **Subprocess commands more specific than generic shell execution.**
   Negative result. Every recorded `git push`, `gh pr merge`, `launchctl
   bootstrap` and `psql DROP` ran through the coding agent's own shell (rows
   4–19). No repository code in this history shelled out to them, so there is
   no evidence here for a more specific subprocess classification.
3. **Cross-module, multi-hop paths.** G4 (dispatch → other module) and G5
   (`.js` → `.ts` resolution) are both demonstrated. Neither is fixed.
4. **Action/observation dispatchers.** Not present in this history.
5. **Model-controlled input reaching a sink.** G1: the model's `content`
   string is written verbatim to a file that later sessions read back (49/49
   reads), a cross-session persistence channel. G4: model-chosen file edits
   and program runs.
6. **Guard recognition and source-level authority checks.** G8. Every
   recorded agent-tool server constrained its effects in source (origin
   allowlist, path containment, operator grants, digests, sandboxes), and Scan
   recognises none of these as guards. Two defects were also proven in the
   reachability heuristics that decide whether a guard question is asked at
   all (G3).

## Ranked engineering opportunities

Ranked by demonstrated real-world evidence, then by how credible the
implementation path is, then by precision risk.

| Rank | Opportunity | Evidence | Path | Risk |
|---|---|---|---|---|
| **0 (done)** | TS raw tool-schema dispatch (G1), import-resolved `fs` sinks (G2), hardened `tool(`/`execute:` signals (G3) | Rows 25 and 27: real, recorded, verified; parity with Python; 3 holdout TPs | Implemented, see BREAKTHROUGH.md | Measured: 0 new FPs on 5,636 corpus files and the holdouts |
| 1 | Make r07 dispatch branches entrypoints for the cross-file layer (G4) | Rows 28–29 (verified executions), row 26 | `cross_language_reach._analyze_ts` already does BFS from handler nodes; add the selected `if`/`case` body as a synthetic handler and follow only **resolved** edges | Medium. Every helper a dispatcher calls becomes reachable, so the existing UNRESOLVED/HEURISTIC discipline must hold. Repo B's own grants (G8) would then surface as unguarded, so this needs G8's triage first |
| 2 | Resolve `./x.js` specifiers to `x.ts` / `x.tsx` (G5) | Reference MCP filesystem server, 33 unresolved edges | `_resolve_module_path` in `ts_symbol_index.py`: try the TS extension swap when the `.js` file is absent | Low on resolution itself, but it exposes cross-file guard protection (`validatePath` in the caller, the sink in `lib.ts`), which COVERAGE.md lists as NOT detected. Triage before shipping |
| 3 | Recognise MCP JSON-RPC `method === "tools/call"` branches as a boundary (G9) | `direct-surface.ts`, Repo A hosts | Structural: a branch on `.method === "tools/call"` in a file that also answers `tools/list` with a schema literal | Unmeasured. Clients and proxies contain the same strings |
| 4 | Structural recognition of allowlist/containment checks (G8) | Four recorded servers | Recognise `if (!<pred>(arg)) return/throw` that dominates the sink as a **containment** check, reported as its own state, never as "guarded" and never as bound | High if done as suppression. Must preserve explicit UNKNOWN and never present a containment check as authorisation |

## Experiment needed for G9 (not run)

Count, over the corpus plus a sample of public MCP server repositories,
files that contain `"tools/call"`, split by role (server, client, proxy, test
double). Wire nothing in until the server share and a hand-triaged
false-positive rate below the 5% threshold used for r05 are known.
