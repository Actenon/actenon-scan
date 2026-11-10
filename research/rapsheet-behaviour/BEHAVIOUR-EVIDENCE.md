# BEHAVIOUR-EVIDENCE — 30 recorded consequential operations

**Source.** Claude Code session logs on one developer machine, read locally
and read-only with Rapsheet `0993ea9`'s parser and redactor. Nothing was
uploaded. Session files are identified as `S-xxxxxxxx` (first 8 hex of the
SHA-256 of the log path). Private projects are pseudonymised (Repo A–E,
P-SALES, P-EVAL, P-QUAL); the mapping is kept outside the repository. Command
text is paraphrased, never quoted where it carries paths, names or values.

**The question for each operation** is not "was this risky" but: *is there a
source-level path, inside Actenon Scan's declared scope, that a model drove to
this effect?* A `git push` run by the coding agent's own Bash tool is executed
by a closed binary that is not under analysis, so it cannot be a Scan false
negative, however consequential it was. Those rows are `UNSUPPORTED` (outside
Scan's scope), not misses.

## The history

Counts below were taken before this study's own session was logged. Rapsheet
gained two commits from another session while the study ran (`1225575`,
`d98ec25`). Re-run pinned to each version: the cross-session persistence
result behind row 25 is identical (31/31 saves, 49/49 byte-identical
read-backs); Rapsheet's finding total is 100 at `0993ea9` and 145 at
`d98ec25`, which counts each operation inside a compound command separately.
The 30 rows were extracted from the raw log records, not from Rapsheet's
totals.

| | |
|---|---|
| Session files | 716 (188 of them subagent transcripts) |
| Tool calls | 20,982 (3,585 from subagents); 13,261 shell commands |
| Calls to locally built MCP servers | 1,216 (`surface` 411, a runtime in Repo A 729, a skills engine in Repo B 76) |
| Permission records (accept) | classifier 14,810 · standing rule 2,714 · permission mode 1,772 · config with no reason type 584 · `other` 309 · `user_temporary` 19 · hook 8 |
| Permission records (reject) | classifier 17 · built-in safety check 15 · hook 5 · user 1; and 727 results with no record at all |
| Headless sessions | 46 files with entrypoint `sdk-cli`; the ~160 benchmark-arm sessions behind rows 25–27 and 30 have a harness-written first prompt |

## Rapsheet: checked before trusting

Each suspected defect was probed against the real logs, not assumed.

| Suspected defect | Probe | Result |
|---|---|---|
| Call and result split across files (resumed sessions) lose outcome and attribution | Count results whose `tool_use` is not in the same file | **0** on this machine. Not a live defect here. |
| Tool-use ids reused with different content hidden by de-duplication | Count ids seen twice with different `(tool, input)` | **0**. |
| Permission attribution | Distribution of `permissionDecision` shapes | Mapping holds for the shapes present. Records with `circuitBreaker` / `reasonCode` keys (15 each) are reduced to source and reason type; the circuit-breaker reason is dropped. |
| Action ownership: headless / harness sessions | Entry points, first-prompt authors | **Defect.** Harness-written prompts are treated as "something you typed", and benchmark arms are mixed with interactive work. Rows 25–27 and 30 were requested by a benchmark harness, not a person. |
| Ownership: "Deleted the whole project folder" | Row 1 | **Overstated.** The target was a subfolder the agent had just scaffolded (its own description says so), which was also the session's working directory. Rapsheet correctly marks it "may have created this itself", but the title says "whole project". |
| Secret handling: `secret-dump` | Rows 22–23: inspect the shape of the printed output without printing values | **One false alarm.** Row 23 piped `.env` through `sed 's/=.+/=<set>/'`; all 8 values reached the log masked. Row 22 did print an env file; its only credential-named key was empty. |
| Compound-command outcome | Row 11 | **Overstated.** "Completed" because the pipeline exited 0, but the output shows the `gh repo create` call returned a GraphQL error. README already discloses this class. |
| Coverage of MCP tool effects | Rapsheet findings over the 1,216 local-MCP calls | **Blind spot.** Rapsheet analyses Bash and file-edit tools; MCP calls only feed a "messages sent" counter. Every row below that this study could tie to source (25–30) is invisible to Rapsheet. |

## The 30 operations

Authority column: the permission record (`classifier` = auto mode's
classifier, `rule` = a standing allow rule) plus the most recent human or
harness message. Verification uses only local, read-only checks (local
remote-tracking refs, files on disk, later transcript records).

| # | Category | What was requested | What the transcript proves | Authority evidence | Effect, and how verified | Source / commit | Scan classification |
|---|---|---|---|---|---|---|---|
| 1 | Destructive shell | User pivoted the task; the agent removed a scaffold it had just started | `rm -rf` of a scratch subfolder, exit 0, listing afterwards | classifier accept | Folder absent today (stat) | Agent's Bash tool | UNSUPPORTED |
| 2 | Destructive shell | Tabulate an evaluation | `rm -f evidence/tmp-*` in P-EVAL, then a Python tally, exit 0 | classifier accept | Not verifiable now (glob) | Agent's Bash tool | UNSUPPORTED |
| 3 | Destructive shell | Subagent lane task from a harness file | `rm -rf lib/*` with a variable root | **Rejected** by the built-in removal safety check (`dangerousRemoval`); never ran | None | Agent's Bash tool | UNSUPPORTED |
| 4 | Git push + merge | Asked to use the runtime on a real example | `merge -s ours` of the GitHub-side history, push `main` and 8 tags; output shows `612981e..c3a902e main -> main` | classifier accept; the push was not explicitly requested | `c3a902e` is on `origin/main` in local refs | Agent's Bash tool | UNSUPPORTED. The commit message says the remote history was "published by [the runtime] itself": see UNRESOLVED U1 in SCAN-GAPS |
| 5 | Git push | (system reminder only) | Fast-forward check, push `main` and 5 tags | classifier accept | `c27289e` on `origin/main` | Agent's Bash tool | UNSUPPORTED |
| 6 | Git push | Asked to continue after a usage-limit pause | `rm -rf` of smoke results, inline Python edits, commit, push `main` | classifier accept | `26d932f` on `origin/main` (Repo C) | Agent's Bash tool | UNSUPPORTED |
| 7 | Git push | Asked for the engine as an MCP server and a CLI | Tests 25/25, commit, push `main` | classifier accept | `6175d77` on `origin/main` (Repo B) | Agent's Bash tool | UNSUPPORTED |
| 8 | PR merge | Asked to retry | `gh pr merge 1 --match-head-commit …`; output state MERGED with merge commit | classifier accept | Output is the GitHub API's own response (P-SALES) | Agent's Bash tool | UNSUPPORTED |
| 9 | PR merge | User: complete the review and configure required checks **before** merging | Transcript records CI verified on the pinned head, branch protection requiring six checks applied and tested in both directions, review posted, then `gh pr merge 55` without admin bypass | classifier accept; the user's precondition is met in the transcript before the merge | `9abbb51` on `origin/main` (Repo A) | Agent's Bash tool | UNSUPPORTED |
| 10 | Repo create + push all branches | Approved setting up a private backup | `gh repo create --private` + push 4 branches | **Rejected** by the classifier as data exfiltration, despite the user's yes in chat | None | Agent's Bash tool | UNSUPPORTED |
| 11 | Repo create | Asked for a new repository | Commit succeeded; `gh repo create` output is a GraphQL error | classifier accept | That call's creation is not established; the repo exists later (row 7 pushes to it) | Agent's Bash tool | UNSUPPORTED |
| 12 | Workflow dispatch | Asked to run the control arm only | `gh workflow run` → queued run id and URL | classifier accept | Output only; a remote run, not checked | Agent's Bash tool | UNSUPPORTED |
| 13 | DB destruction | Asked to retry | `psql DROP DATABASE IF EXISTS` + create + migrate + drop | classifier accept | **No effect:** exit 2, connection refused | Agent's Bash tool | UNSUPPORTED |
| 14 | DB write + persistent workers | Asked to finish the product for the team to use | SQLite backup, `create_all` of two tables, `launchctl kickstart` of four workers, then an INSERT that failed ("database is locked") | classifier accept | Partial: tables created, workers restarted, insert failed | Inline Python in the transcript (not a repository file) + Bash | UNSUPPORTED |
| 15 | LaunchAgent creation | User approved starting it at login | Write tool created `~/Library/LaunchAgents/<app>.plist` | classifier accept; explicit chat approval | Plist exists today (stat) | Agent's Write tool | UNSUPPORTED |
| 16 | Persistent execution | Same approval | `plutil -lint`, bootout, bootstrap; `state = running`, servers report ready | classifier accept | Agent is running today (`launchctl print`) | Agent's Bash tool | UNSUPPORTED |
| 17 | Persistent execution | A background-task notification (no human turn) | Bootstrap 5 worker agents + the app agent; `launchctl list` shows 6 | classifier accept; the triggering turn was automated | 6 matching plists exist today | Agent's Bash tool | UNSUPPORTED |
| 18 | Persistent execution | Conditional go for a benchmark | `launchctl bootstrap` of a container apiserver plist | classifier accept | **No effect:** bootstrap failed, exit 5 | Agent's Bash tool | UNSUPPORTED |
| 19 | Persistent execution | Product mandate (pasted) | Copy + bootstrap 5 worker plists | **Rejected** by the classifier as unauthorised persistence | None | Agent's Bash tool | UNSUPPORTED |
| 20 | Downloaded code | A subagent-finished notification | `uv tool install` from a third-party GitHub release **`latest`** URL (unpinned), then ran `--help` | classifier accept; no human turn requested it | Binary exists today (stat) | Agent's Bash tool | UNSUPPORTED |
| 21 | Package install | User pasted their own failed `pip install` | Fresh venv, `pip install git+https://…@<branch>`, ran the demo | classifier accept | Scratch venv (temporary) | Agent's Bash tool | UNSUPPORTED |
| 22 | Credential access | Asked to finish the product for the team to use | A long heredoc script that also `cat`s a frontend env file | classifier accept | Printed 7 env-style lines; the only credential-named key is empty | Agent's Bash tool | UNSUPPORTED |
| 23 | Credential access | Approved a setup step | `cat .env \| sed 's/=.+/=<set>/'` | classifier accept | All 8 values masked by the pipeline; Rapsheet's "plain text" claim is wrong | Agent's Bash tool | UNSUPPORTED |
| 24 | Nested process | Asked for the engine as an MCP server and a CLI | `node -e` rewrites `package.json`, runs tests, commits, pushes | classifier accept | `600abcb` on `origin/main` (Repo B) | Agent's Bash tool (inline JS) | UNSUPPORTED |
| 25 | **MCP tool → persistent file write** | Harness prompt: save what was learned as a skill for later sessions | `save_skill {name, content}` → `"saved"`; 31 calls in 31 sessions, all `"saved"` | `rule` accept (standing allow rule for the MCP tool) | **Verified across sessions:** all 49 later `read_skill` results are byte-identical to content saved by an earlier, different session | Repo A `experiments/north-star/surface.ts` @ `5033ec5` (blob `d341d79`; unchanged until after the last call) → `writeFileSync` | **VERIFIED MISS** (in scope: TS MCP server, raw tool-schema dispatch, r07). Fixed by the candidate. |
| 26 | MCP tool → sandboxed program | Harness prompt: solve a task with one MCP tool, `run_program` | `run_program {args, files}` → `{exit:0, stdout…}`; 270 calls | `rule` accept | Exit status and output in the result | Same file → `sandbox.run(...)` on an object returned by a factory in another module | DOCUMENTED LIMITATION (method on a returned object, cross-module). Still missed. |
| 27 | **MCP tool → network egress** | Harness prompt: answer using `http_get`, restricted to one origin | `http_get {url}` → `{status:200, body…}`; 13 calls | `rule` accept | Status and body in the result | Same file → `fetch(u)` after an origin allowlist check | **VERIFIED MISS** (in scope, r07). Fixed by the candidate. The allowlist is a source-level authority check Scan does not recognise. |
| 28 | MCP tool → code edit | Harness prompt: work only through the engine's tools | The engine's edit tool → change id, before/after digests and diff | `rule` accept | Digest changed; a later run-tool call re-ran tests on the edit | Repo B `src/mcp.js` @ `b0f6951` (committed 57 s before the call): `switch` on the tool name → a helper in another module | **VERIFIED MISS, not fixed** (dispatch selects a call into another module) |
| 29 | MCP tool → program run | Same | The engine's run tool with `npm test` → exit 1, test output | `rule` accept | Output in the result | Same dispatch → `run` → `runConfined` → `spawn` (`src/sandbox.js`) | **VERIFIED MISS, not fixed** (same reason) |
| 30 | MCP tool → capability registry | Harness prompt: reuse a previously learned capability | The runtime's run tool with a capability id → `status: failed`, an unresolved dependency | `rule` accept | **No effect:** the run failed before executing | Repo A `src/interface/mcp-server.ts` → `tools.ts` dispatch → capability-graph lookup | DOCUMENTED LIMITATION (registry / dynamic dispatch) |

### Shortfall against the requested categories

All eight categories are represented. Two are thin:

- **Database writes** (rows 13–14) both ran through the agent's shell, not
  through source a model drives. No recorded operation reached a database
  through repository code.
- **Credential access** (rows 22–23) did not expose a credential. No recorded
  operation read a credential through repository code.

Only rows 25–30 have a source-level path at all. They all come from
benchmark harnesses and agent-tool servers the developer built locally, so
they are real executions of real code, but **not third-party code**.

## What the history establishes

1. **24 of 30 operations have no source-level path for a static analyser to
   find.** The coding agent's own tools executed them. Rapsheet sees them; Scan
   structurally cannot and should not claim to.
2. **Six operations went through repository code a model invoked**, and the
   frozen baseline reports **none** of them: not the persistent write (row 25),
   not the egress (27), not the code edits and program runs (28–29).
3. **Rapsheet does not see those six.** The two tools have complementary blind
   spots: Rapsheet audits the agent's built-in tools and ignores MCP effects;
   Scan audits repository code and cannot see the built-in tools.
