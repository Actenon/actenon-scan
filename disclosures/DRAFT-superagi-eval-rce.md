# DRAFT — Maintainer Security Report: Unintended `eval()` on LLM output in SuperAGI

**STATUS: DRAFT — NOT SENT. For human sign-off before any external communication.**

**DO NOT send this report without explicit human authorisation.**

---

## Recipient

**Project:** TransformerOptimus/SuperAGI

**Security contact route:** SuperAGI does not have a `SECURITY.md` file.
GitHub private vulnerability reporting is **disabled** for the repository.
GitHub issues are **enabled**.

Per Actenon Scan's
[Disclosure Policy](../DISCLOSURE_POLICY.md), the maintainer must have an
accessible response route (issue, email, or discussion). The available
route for this project is:

- **GitHub issue on TransformerOptimus/SuperAGI** (the maintainer's
  preferred public channel), OR
- **Direct contact** with the top contributors via their published
  GitHub profiles (mukundans89, NishantBorthakur, Fluder-Paradyne,
  luciferlinx101, namessleeps2).

**Recommended action:** Open a GitHub issue titled "Security finding:
unintended `eval()` on LLM output in `output_handler.py`" with the body
of this draft. Request private coordination before any public
discussion of the exploit path.

If the maintainers prefer a private channel, they can respond via the
issue with a contact method.

---

## Finding

### Summary

`ReplaceTaskOutputHandler.handle()` calls `eval()` directly on the LLM's
`assistant_reply` — the raw text output of the model. An attacker who
can influence the model's output (via prompt injection, tool output
poisoning, or direct model control) can execute arbitrary Python code
in the agent's process.

### Severity

**Critical.** This is a direct model-output-to-`eval()` path with no
sanitization, no allowlisting, and no sandboxing. The agent process
typically has access to the filesystem, network, and any API keys
configured for the agent's tools.

### Reproduction evidence

| Field | Value |
|-------|-------|
| **Repository** | `TransformerOptimus/SuperAGI` |
| **Pinned commit SHA** | `c3c1982e7bd6a11cfed53c5a193ea502f924b1b6` |
| **File** | `superagi/agent/output_handler.py` |
| **Line** | 180 |
| **Enclosing class** | `ReplaceTaskOutputHandler` |
| **Enclosing method** | `handle` |
| **Scanner rule** | `EXEC-CODE` |
| **Scanner version** | actenon-scan 1.4.0 (source build from `25ee4f9`) |
| **Scan command** | `actenon-scan scan <superagi checkout> --repository-analysis` |
| **Scanner detected?** | **No.** The scanner reported this case as clean because the sink is inside a method that is not directly `@tool`-decorated. The reachability path requires same-file same-class method resolution (`self.handle` → `eval`), which the scanner does not currently follow. This is a known scanner limitation documented in `docs/COVERAGE.md` under "Interprocedural flow". |

### The vulnerable code

```python
# superagi/agent/output_handler.py, lines 178-188
# At pinned commit c3c1982e7bd6a11cfed53c5a193ea502f924b1b6

def handle(self, session, assistant_reply):
    assistant_reply = JsonCleaner.extract_json_array_section(assistant_reply)
    tasks = eval(assistant_reply)          # ← line 180: RCE
    self.task_queue.clear_tasks()
    for task in reversed(tasks):
        self.task_queue.add_task(task)
    if len(tasks) > 0:
        logger.info("Tasks reprioritized in order: " + str(tasks))
    status = "COMPLETE" if len(self.task_queue.get_tasks()) == 0 else "PENDING"
    session.commit()
    return TaskExecutorResponse(status=status, retry=False)
```

### Call path from model output to `eval()`

1. The LLM produces an `assistant_reply` string — a JSON array of tasks
   (or text that the handler attempts to parse as one).
2. The agent's dispatch loop calls the output handler:
   `get_output_handler("replace_tasks", ...)` →
   `ReplaceTaskOutputHandler.handle(session, assistant_reply)`.
3. Line 179: `assistant_reply = JsonCleaner.extract_json_array_section(assistant_reply)`
   — extracts the JSON-array substring. This is a text-cleaning step;
   it does **not** sanitise against code injection. An attacker who
   controls the model's output can craft a string that passes
   `extract_json_array_section` and contains arbitrary Python.
4. Line 180: `tasks = eval(assistant_reply)` — the cleaned string is
   passed directly to `eval()`, executing it as Python code.

### Why it is reachable

`ReplaceTaskOutputHandler.handle` is the dispatch target for the
`"replace_tasks"` output type (see `get_output_handler` at line 191).
When the agent's output type is `"replace_tasks"`, this handler is
called on every LLM response. The LLM's output is the **sole input**
to `eval()` (after a text-cleaning step that does not prevent code
injection).

The `assistant_reply` parameter is model-controlled: it is the text
the LLM produces in response to the agent's prompt. An attacker who
can influence the LLM's output — via prompt injection through tool
results, user messages, or retrieved context — can cause the model to
emit a string that, when passed to `eval()`, executes arbitrary code.

### Suggested remediation

Replace `eval()` with a safe parser. The handler expects a JSON array
of tasks; use `json.loads` (which parses JSON without executing code):

```python
import json

def handle(self, session, assistant_reply):
    assistant_reply = JsonCleaner.extract_json_array_section(assistant_reply)
    try:
        tasks = json.loads(assistant_reply)
    except json.JSONDecodeError:
        # Handle malformed input gracefully — do NOT fall back to eval()
        logger.error(f"Failed to parse assistant_reply as JSON: {assistant_reply!r}")
        return TaskExecutorResponse(status="ERROR", retry=True)
    if not isinstance(tasks, list):
        logger.error(f"Expected a JSON array, got {type(tasks).__name__}")
        return TaskExecutorResponse(status="ERROR", retry=True)
    # ... rest of the method
```

If the input is not strict JSON (the `JsonCleaner` suggests some
preprocessing is expected), use `ast.literal_eval` as a second-best
option — it evaluates Python literals (strings, numbers, tuples,
lists, dicts, booleans, None) without executing arbitrary code:

```python
import ast

tasks = ast.literal_eval(assistant_reply)
```

**Do not** fall back to `eval()` under any condition. If parsing fails,
return an error response and let the agent retry.

### Disclosure timeline

Per Actenon Scan's
[Disclosure Policy](../DISCLOSURE_POLICY.md):

1. **Private-first.** This draft is delivered privately first. The
   maintainer receives the full report before any publication
   decision.
2. **Reproduction evidence included.** The exact commit SHA, file,
   line, scanner version, and command are stated above.
3. **Right of reply.** The maintainer may identify configuration,
   guards, or architecture outside the analysed scope that the
   scanner could not see. For example: if the `assistant_reply` is
   pre-validated by a step not visible in this file, or if
   `ReplaceTaskOutputHandler` is never used in production
   configurations, the maintainer should state this.
4. **Corrections.** The report will be corrected where evidence
   supports correction.
5. **No automatic publication.** The report will not be published
   without explicit consent from the maintainer. The maintainer may
   choose: private (report delivered, not published), anonymised
   (published without repo name), or named (published with full
   attribution).

**Actenon's commitment:** We will not publish this finding for at
least 90 days from the date of this draft, or until the maintainer
confirms a fix is deployed — whichever is later. If the maintainer
disputes the finding, the dispute will be recorded publicly with
evidence.

---

## Other confirmed cases in the 160-case set that may meet the same bar

The following AGENT_REACHABLE cases involve code execution or shell
execution sinks, but they are tools **designed** to execute code
(`browser_exec`, `docker exec`, `subprocess` in a shell tool). They
are NOT unintended `eval()`-on-LLM-output paths. They are listed
here for completeness, not as disclosure candidates:

| Repo | File:Line | Rule | Justification for NOT drafting |
|------|----------|------|-------------------------------|
| agno | `agno/tools/daytona.py:344` | EXEC-CODE | `create_file` in a file-management tool — the sink is the tool's intended function, not an unintended `eval()` |
| agno | `agno/tools/docker.py:192` | EXEC-CONTAINER | `start_container` in a Docker tool — container execution is the tool's purpose |
| agno | `agno/tools/workspace.py:813` | EXEC-SHELL | `run_command` in a workspace tool — shell execution is the tool's purpose |
| browser-use | `browser_use/mcp/cli_mcp.py:105` | EXEC-CODE | `_screenshot` in a browser tool — not an `eval()` path |
| browser-use | `browser_use/mcp/cli_mcp.py:128` | EXEC-CODE | `_execute(code)` in a `browser_exec` tool — code execution is the tool's purpose, the code is passed as an argument not as raw LLM output |
| langchain | `langchain/agents/middleware/file_search.py:314` | EXEC-SHELL | `_ripgrep_search` calls `subprocess` — shell execution for a search tool, not `eval()` on LLM output |

**Conclusion:** The superagi `output_handler.py:180` case is the only
confirmed case in the 160-case set that meets the bar of an unintended
`eval()`-on-raw-LLM-output RCE path. The others are tools whose code
execution capability is intentional and documented.

---

## Sign-off

**This draft has NOT been sent.**

Before any external communication:

1. A human reviewer must confirm the finding is accurate (the code
   at the pinned SHA does call `eval(assistant_reply)` at line 180).
2. A human reviewer must confirm the recipient route is appropriate
   (GitHub issue on TransformerOptimus/SuperAGI, or direct contact
   with top contributors).
3. A human reviewer must authorise the send.

**Do not send without explicit human sign-off.**
