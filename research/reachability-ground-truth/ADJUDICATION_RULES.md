# Adjudication Rules — Real-World Reachability Ground Truth

**Status:** PRE-REGISTERED. This document was written and committed
**before** any case in `labels.json` was re-examined under Phase 4 of the
correctness PR (`fix/correctness-and-integrity`, Task 7-P4). Commit order
is the proof of pre-registration: this file's first commit predates the
re-adjudication of the 16 Task-5 cases by a measurable number of commits
in the same PR.

**Purpose.** The bracket published in commit `129b926` (43%–52%) was
withdrawn on 2026-09-20 because (a) all 16 adjudications moved in one
direction (toward NOT_AGENT_REACHABLE — the direction that flatters the
tool), (b) 6 of 16 were scope changes presented as adjudications, and
(c) the highest-weight case misclassified the agent-facing
`LoadAndSearchToolSpec.load`. This document states the rules under which
the 16 cases are re-adjudicated so the result cannot be rationalised
after the fact.

---

## 1. Definition of AGENT_REACHABLE

A sink is **AGENT_REACHABLE** if and only if there exists a concrete call
path from an **agent/tool/model-controlled boundary** to the sink, where
the path is **traceable through repository-local code** (not through
external library internals — i.e. not through the bodies of PyPI
dependencies that are not pinned in the corpus).

An **agent/tool/model-controlled boundary** is one of:

- A `@tool` (or `@tool(...)`) decorator — LangChain-style.
- A tool base-class method override — e.g. a `BaseTool._run` /
  `BaseTool._execute` / `BaseTool._arun` body, a `Toolkit` method
  registered in a `tools=` list, a `BaseAction.run` /
  `Action._run`-style method, a `StructuredTool` body, a CrewAI
  `BaseTool` subclass method.
- A tool **registration in a `tools=` list** — e.g. `tools=[self.run_cmd]`,
  `agent = Agent(tools=[...])`, `AgentTool(name=..., func=...)`. This
  includes dynamic registration patterns such as
  `sync_tools = [getattr(self, name) for name in registered]` followed
  by `super().__init__(tools=sync_tools)` (the agno `Workspace` pattern).
- A callback registration that exposes a function to a model — e.g.
  `@server.call_tool()` (MCP), `@mcp.tool()`, `@kernel_function`
  (semantic-kernel), `@function_tool` (openai-agents), `@ast_tool_method`
  (autogen).

The following are **NOT** agent/tool/model-controlled boundaries for
the purposes of this dataset:

- A FastAPI / Flask / Starlette / Sanic / Django REST route handler
  (`@app.post`, `@router.delete`, etc.). A web-route handler is driven
  by an HTTP client, not by a model. Cases whose only boundary is a
  web route are NOT_AGENT_REACHABLE and carry `web_route: true`.
- An inbound webhook handler (Telegram, Slack, etc.). The model may
  *supply text* for the message but does not *choose to invoke the
  send* — the inbound HTTP request does. Webhook-only paths are
  NOT_AGENT_REACHABLE.
- A `__main__` / `if __name__ == "__main__":` block, a `main()`
  function, a CLI entrypoint, a build script, a migration runner.
- Internal message passing between agent components where no model
  decision drives the call (autogen `wsbridge`, semantic-kernel
  `SequentialAgentActor`, agno A2A transport). This was a specific
  trap from the prior work order and remains in force.

---

## 2. Scope rule for `examples/`, `samples/`, `demos/`, `cookbook/`, `notebooks/`

Directories matching any of these prefixes contain demonstration code.
The README's `tier` field already flags these cases with
`tier=example`. The scope rule has **two variants**, and Phase 4
reports the bracket under **both**:

### Variant (a) — examples IN scope

Demo-directory cases are adjudicated on reachability alone, exactly
like production cases. The demo code **is** the population. A sink in
`examples/mcpserver/memory.py` reached from `@mcp.tool()` is
AGENT_REACHABLE; a sink in `examples/apps/news-use/news_monitor.py`
reached only from `main()` is NOT_AGENT_REACHABLE.

### Variant (b) — examples OUT of scope

Every case whose file path begins with `examples/`, `samples/`,
`demos/`, `cookbook/`, or `notebooks/` is removed from the population
**on both sides** of the recall equation:

- removed from the weighted AGENT_REACHABLE sum,
- removed from the weighted AMBIGUOUS sum,
- removed from the weighted NOT_AGENT_REACHABLE sum,
- and the **sample total weight is recomputed** so the bracket's
  denominator is consistent.

This variant includes the two AGENT_REACHABLE cases in
`examples/mcpserver/memory.py` (idx 105, 106). Removing them is the
correction to the asymmetric scope rule applied in commit `129b926`,
which removed demo-directory AMBIGUOUS cases from the low end of the
bracket while leaving demo-directory AGENT_REACHABLE cases in the high
end.

Weights are `stratum_N / stratum_n` and were drawn from a stratified
sample. Removing demo cases does **not** change the stratum totals;
removing them is equivalent to dropping the demo rows from the
weighted sum.

---

## 3. Evidence standard required to move a case

**AMBIGUOUS → AGENT_REACHABLE** requires tracing a concrete call path
from an agent boundary (§1) to the sink, citing `file:line` for each
hop. The trace must stay inside repository-local code. A trace that
disappears into a generic dispatcher (e.g. `getattr(self, name)` with
an unresolved `name`) without re-emerging at the sink **does not** meet
the standard and the case stays AMBIGUOUS.

**AMBIGUOUS → NOT_AGENT_REACHABLE** requires showing one of:

- That no agent boundary in §1 reaches the sink — the sink's callers
  are framework-internal, infra-only, or a non-agent boundary in the
  §1 exclusion list.
- **Or**, under scope variant (b) only, that the sink is in a demo
  directory (§2) and is therefore out of the population. Under variant
  (a) this is not a valid reason on its own — the sink must also fail
  the reachability test.

**AGENT_REACHABLE → NOT_AGENT_REACHABLE** requires showing that the
original adjudication was wrong — specifically, that the "agent
boundary" it relied on is **not** actually agent-controlled under §1
(e.g. it was a web route misclassified as an agent boundary, or a
`__main__` block).

**NOT_AGENT_REACHABLE → AGENT_REACHABLE** requires showing that an
agent boundary in §1 was missed in the original adjudication —
specifically, by tracing a concrete call path from such a boundary to
the sink that the prior label did not record.

---

## 4. Symmetry requirement

If re-adjudication produces a result in which **every** move goes one
direction (e.g. all AMBIGUOUS → NOT_AGENT_REACHABLE, or all
AMBIGUOUS → AGENT_REACHABLE), that is reported explicitly in the
adjudication ledger and in `docs/RECALL.md`. A one-directional result
is **not** invalid on its face — it can be the truth — but it must be
flagged so the reader can look at the evidence and decide.

---

## 5. Cases in scope for Phase 4 re-adjudication

The 16 cases adjudicated in commit `129b926`, identified by `idx` in
`ambiguity_resolution.json`:

| idx | weight | stratum | file |
|----:|-------:|---|---|
| 2 | 75.5 | agno\|data_destruction | libs/agno/agno/db/postgres/utils.py:122 |
| 4 | 75.5 | agno\|data_destruction | libs/agno/agno/fs/db.py:416 |
| 5 | 20.0 | agno\|communication | libs/agno/agno/os/interfaces/telegram/helpers.py:141 |
| 12 | 30.0 | agno\|file_mutation | libs/agno/agno/utils/media.py:154 |
| 44 | 2.0 | autogen\|database_mutation | python/samples/gitty/src/gitty/_db.py:121 |
| 45 | 2.0 | autogen\|database_mutation | python/samples/gitty/src/gitty/_db.py:131 |
| 46 | 8.0 | autogen\|shell_execution | python/samples/gitty/src/gitty/_github.py:65 |
| 57 | 4.5 | browser-use\|communication | examples/apps/msg-use/scheduler.py:246 |
| 58 | 13.5 | browser-use\|file_mutation | examples/apps/news-use/news_monitor.py:208 |
| 59 | 2.0 | browser-use\|data_destruction | examples/custom-functions/file_upload.py:109 |
| 88 | 15.0 | langchain\|data_destruction | libs/langchain/langchain_classic/indexes/_sql_record_manager.py:523 |
| 101 | 297.0 | llamaindex\|data_destruction | llama-index-integrations/vector_stores/.../oracledb/base.py:388 |
| 113 | 15.0 | metagpt\|network_egress | metagpt/environment/minecraft/minecraft_ext_env.py:182 |
| 129 | 33.0 | openai-agents\|data_destruction | src/agents/sandbox/entries/mounts/patterns.py:393 |
| 130 | 117.0 | openai-agents\|code_execution | src/agents/sandbox/session/base_sandbox_session.py:1100 |
| 150 | 33.0 | semantic-kernel\|data_destruction | python/semantic_kernel/connectors/sql_server.py:505 |

Each is reset to its pre-`129b926` state (label `AMBIGUOUS`, with the
reason recorded in the parent commit) **before** re-adjudication, and
re-adjudicated under §3 of this document.

---

## 6. Forbidden metrics

The Phase 4 re-adjudication does **not** introduce or report:

- "authority coverage"
- "% protected" / "% safe"
- any figure dividing findings by an estimate of total consequential
  actions

The bracket's denominators are fully observed on the detected side
(149 reachable sinks) and weighted-by-design on the missed side; the
AMBIGUOUS bucket is a weighted sum of explicitly-labelled sample rows,
not an estimate of total actions.

---

## 7. Reproducibility

Each re-adjudication records, in
`adjudication_results.json`:

- `idx`, `old_label` (after reset, always `AMBIGUOUS`), `new_label`,
  `reason_code`, `evidence` (with `file:line` cites for every hop on
  any AGENT_REACHABLE move), `source_verified` (true if GitHub source
  was fetched at the pinned SHA), `stratum`, `weight`.

The brackets under §2 variants (a) and (b) are reported separately in
`docs/RECALL.md`. The synthetic adversarial recall (9/10), the
corpus-demonstrated architecture recall (3/10), and the precision
benchmark (16/16) are reported alongside the real-world labelled-sink
bracket, and **never collapsed** into one number.
