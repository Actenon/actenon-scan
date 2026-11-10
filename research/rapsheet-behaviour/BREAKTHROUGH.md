# BREAKTHROUGH — a recorded agent write path Scan could not see, now detected

## The result in one paragraph

Coding agents on this machine called a hand-written MCP server's `save_skill`
tool 31 times. Each call wrote model-authored text to a persistent skill store,
and all 49 later `read_skill` calls, made from other sessions, returned exactly
those bytes. The server is TypeScript, inside Scan's declared scope: an
agent-tool boundary (MCP `tools/call`) dispatched on a tool name the file
declares in a schema literal, which is benchmark case r07. Scan detects that
same architecture in Python, and the frozen baseline flags a line-for-line
Python transliteration of the server. On the TypeScript original it reported
nothing. Three small commits make it report exactly the two tool effects
(`FILE-WRITE` at the write, `NET-EGRESS` at the server's `http_get`) and
nothing else in that file. Across 5,636 third-party corpus files no finding
changes, and on unseen local code it finds three more real model-controlled
writes and removes one baseline false positive.

## The evidence chain

| Link | Evidence | How it was established |
|---|---|---|
| The agent requested it | The harness prompt told the agent to save what it learned as a skill for later sessions to reuse (paraphrased) | Transcript, first user record of each benchmark session |
| The call happened | 31 `mcp__surface__save_skill {name, content}` calls, 17 Oct 10:10–14:40 UTC, every result `"saved"` | Rapsheet parser, call/result pairing by tool-use id |
| Authority | `permissionDecision {decision: accept, source: config, reasonType: rule}`: a standing allow rule for the tool, not a per-call approval | Permission record on each result |
| The effect is real | 49/49 `read_skill` results are byte-identical (SHA-256) to content saved by an **earlier, different** session | Cross-session hash join over the logs |
| The source | Repo A `experiments/north-star/surface.ts`, blob `d341d79`, introduced in `5033ec5` (10:04 UTC, six minutes before the first `save_skill`); identical at `0e5c96b` and every later commit until `b8b460b` (02:30 UTC the next day, after the last call). `b8b460b` changes only the sandbox wiring, not `save_skill` or `http_get`. | `git log` / `git diff` / `git hash-object` on the historical commits |
| The call came from that file | The tool set `{run_program, list_skills, read_skill, save_skill, http_get}`, the argument keys, the `"saved"` return string and `serverInfo.name = "surface"` match this file and no other; the other server named `surface` (`direct-surface.ts`) has only `run_program` | Source comparison |
| In scope | The same baseline flags a Python transliteration via `tool_schema_dispatch` (r07); TypeScript is a supported language | `actenon-scan scan` on both |
| Missed for the stated reasons | The file is analysed (1 file, 0 errors, not excluded, TS extra installed); every sink evaluates `reachable=False`; `writeFileSync` matches no rule at all | `_is_call_reachable` and `_extract_calls` evaluated directly on the historical blob |

The write matters beyond a single file: a skill store that later sessions read
as instructions is a cross-session persistence channel for whatever the model
writes. This report makes no claim about what was written (it was benign
benchmark notes); the claim is that the path exists, executed, and was invisible.

## Mechanism

All in `actenon_scan/detectors/typescript.py`. Zero new dependencies, no new
rule IDs, no changes to Python or Go, no benchmark fixtures touched.

1. **`de06061`: hardened text signals.** In the function-body check, `tool(`
   must be the bare `tool(...)` factory, not `client.tool("name", args)` or
   `registry.tool(id)`. In the function-body and inline-handler checks,
   `execute:` must introduce a function (`execute: async (…) =>`,
   `execute: function`, or a value on the next line), not
   `execute: programs`. The inline-handler `tool(` check is untouched, so
   `mcp.tool(name, schema, handler)` registrations still resolve. This commit
   comes first so that commit 2 never exposes the latent false positives
   (see "What was rejected").
2. **`ad07a60`: import-anchored `fs` resolution.** Identifiers bound to `fs`,
   `node:fs`, `fs/promises` or `node:fs/promises` (named, aliased, default,
   namespace, `require` and `require(...).promises` forms) are rewritten to
   their dotted name before matching: `writeFileSync` → `fs.writeFileSync`,
   `fsp.rm` → `fs.promises.rm`. Used in both the per-file detector and the
   cross-file sink discovery. The binding decides, never the name: `memfs`, a
   local module, or a local function called `writeFileSync` stay unmatched.
3. **`5020b44`: raw tool-schema dispatch for TS/JS (r07).** The port of the
   Python signal:
   - *Declared names*: object literals with `name: "<string>"` plus
     `inputSchema`, `input_schema`, `parameters` or `args_schema` (whose value
     is not an array), and the nested `{type, function: {name}}` form.
   - *Selection*: the sink lies inside the consequence of an `if` whose
     condition is `x === "<declared>"` or `"<declared>" == x`, possibly joined
     by `&&`/`||`, or inside a `case "<declared>":` body, including fallthrough
     from an empty case.
   - *Stricter than Python*, deliberately: the `else` branch never counts, a
     negated or indirect condition never counts, `parameters: [...]` is a
     parameter list rather than a schema, and containment is checked on the
     sink's exact position, so a one-line `if (…) a(); else sink();` does not
     match.
   - Module-level sinks keep the strict file-level rule. Guard dominance,
     binding and result-use analysis apply unchanged to the new boundary
     (`test_guard_analysis_still_applies_to_the_new_boundary`).

## Reproduce

Reproducer in the repository: a server with the same architecture, written
independently of the private source (self-authored, so it is a regression
test, not validation):

```bash
python -m pytest tests/test_ts_tool_schema_dispatch.py tests/test_ts_fs_named_imports.py tests/test_ts_reachability_text_signals.py -q
```

Discrimination, measured by running the same files against `ef8487a`:

| Test file | Candidate | Baseline |
|---|---|---|
| `test_ts_tool_schema_dispatch.py` | 21/21 pass | 8 fail (every positive case), 13 pass (every near-miss) |
| `test_ts_fs_named_imports.py` | 23/23 pass | 16 fail (every positive case), 7 pass (every negative) |
| `test_ts_reachability_text_signals.py` | 11/11 pass | 4 fail (every baseline false positive), 7 pass (every real registration) |

The original file (with access to Repo A):

```bash
git -C <repo-a> show 5033ec5:experiments/north-star/surface.ts > /tmp/surface.ts   # blob d341d79
actenon-scan scan /tmp/surface.ts --format list --fail-on none --no-cache
# ef8487a: 0 findings
# 5020b44: 62:… FILE-WRITE (save_skill), 74:… NET-EGRESS (http_get)
```

## Validation, kept separate

| Set | What it is | Independent of the change? | Result |
|---|---|---|---|
| Development | `surface.ts` in Repo A at 4 commits + HEAD; the in-repo reproducer | **No**: the change was written against it | 2 TP per snapshot (the write and the egress), nothing else in the file |
| Holdout (unseen local code) | Repos C, D, E at HEAD: 283 TS/JS files, not opened before the change was written | Unseen by me, but **same developer and agent ecosystem**: not third-party | +3 TP in Repo C (`terminal.ts:55`, `:61`: an MCP `write` tool and shell-output write-back; `protocol/mcp.ts:126`: a `use` tool writing to a model-chosen path) plus the same three in a frozen evidence copy (example tier). −1 baseline FP (G3), plus its copy. D, E unchanged |
| Recorded but not a holdout | Repo B at `b0f6951` and HEAD, 26 files each. Its dispatch structure was read before the change | No | Unchanged (0). Its recorded writes sit behind a cross-module call (G4) and are correctly not claimed |
| Third-party corpus | 10 pinned repos with TS, 5,636 files (Python + TS) | Yes | **Identical** findings and capabilities to the baseline |

No self-authored fixture is presented as real-world validation. The only
real-world claims are rows 25 and 27 of BEHAVIOUR-EVIDENCE.md and the Repo C
holdout results.

## What was rejected along the way

Commit 2 (`fs` resolution) was first written without commit 1. Measured on its
own it made five findings appear in Repo A's benchmark harness. Two are
evidence writes in a harness `main()` that drives the server as a **client**
(NOT_AGENT_REACHABLE under the adjudication rules). Three are trace-log
appends that may be reachable through a runtime callback or a module-level
JSON-RPC loop, but were flagged for an unrelated reason: an `execute:` config
key two lines up. A recall gain that brings unjustified accusations was not
accepted. The heuristics were hardened (commit 1, now first in history), and
the five disappeared without losing any real registration shape. Each commit
passes the full suite on its own.

## Limitations

- **Per-file only.** A dispatch branch that calls a helper in another module
  is not lifted (G4). That is why Repo B's recorded edits and runs (rows 28–29)
  are still missed.
- **Literal names only.** `name === ToolName.ECHO` (enum or constant) is not
  read (G12). Module-level `tools/call` loops are not boundaries (G9).
- **The guard question is unchanged.** `http_get`'s origin allowlist, Repo C's
  path-containment helper and Repo B's grants are real source-level constraints that Scan
  does not recognise (G8). The new findings therefore say "no guard found",
  which is accurate about Scan's vocabulary but silent about those constraints.
- **No runtime observation is treated as proof of authority.** That a call was
  permitted by a standing allow rule, or that `save_skill` returned `"saved"`,
  says nothing about whether a guard is bound to the action. Nothing in this
  change reads logs or treats an observed outcome as a guard.
- **Corpus-demonstrated recall is unchanged (3/16), and r07 stays PARTIAL.**
  The coverage contract requires a hand-triaged TP on a pinned commit of a
  public repository in `corpus-evidence.json`. The evidence here is a private
  repository; no contract row was changed. Publishing a pinned example of this
  architecture, or finding one in public MCP servers, is what would move r07.
- **Shadowing is not tracked.** An `fs` import shadowed by a local of the same
  name in a nested scope is still treated as fs (same as the existing
  `child_process` resolution).
