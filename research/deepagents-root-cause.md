# ROOT CAUSE ANALYSIS — DeepAgents precision failures

## ROOT_CAUSE_ENTRYPOINT

**Symptom:** Actenon treats FastAPI `@app.post` functions as model-callable
entrypoints and says "agent entry point" in the blast radius output.

**Root cause:** The `_reachability_for_func` function in
`actenon_scan/detectors/reachability.py` returns `confidence="high"` with
`signals=["resource_boundary"]` when a function has a `@app.post` decorator
and `--resource-boundary` is enabled. The pretty output in
`actenon_scan/report/pretty.py` line 109 calls `_decorator_or_function(f)`
which returns `"agent entry point"` for ALL high-confidence signals,
including `resource_boundary`. This conflates:
- **model-callable entrypoint** (decorated with `@tool`, `@mcp.tool()` — the
  LLM can invoke by name)
- **externally callable HTTP entrypoint** (decorated with `@app.post` — an
  HTTP client invokes it, the LLM may or may not be that client)

The `--resource-boundary` flag correctly makes this opt-in, but the output
wording does not distinguish the two.

**Evidence:** `reachability.py` line 99-102 returns `resource_boundary`
signal. `pretty.py` line 109 hardcodes `"agent entry point"` for the
`Reachable by:` field.

## ROOT_CAUSE_HTTP

**Symptom:** Actenon reports `client.post("https://api.tavily.com/search",
json={"query": query})` as having model-controlled input, but the URL is
constant. The model-controlled value `query` appears only in the JSON body.

**Root cause (two defects):**

1. **`_is_tainted` does not handle `ast.Dict`** (`actenon_scan/detectors/
   sinks.py` line 235). When `_check_escalate` checks the `json=` keyword
   argument, the value is a `ast.Dict` `{'api_key': 'secret-key', 'query':
   query, 'max_results': 5}`. `_is_tainted` returns `False` for any node
   type not explicitly handled (Name, JoinedStr, BinOp, Attribute, Call).
   `ast.Dict` is not handled → taint inside the dict is invisible.

2. **The `escalate_when` config for NET-EGRESS only checks `arg_positions:
   [0]` and `arg_keywords: ['url', 'endpoint', 'uri']`** (default_rules.json
   line 476-480). The `json` and `data` keyword arguments are NOT in the
   list. Even if `_is_tainted` handled Dict, the escalate check would not
   look at `json=` or `data=` arguments.

**Evidence:** `_is_tainted` source — no `isinstance(node, ast.Dict)` branch.
`_check_escalate` source — checks `kw.arg in arg_keywords` where
`arg_keywords = ['url', 'endpoint', 'uri']`. The `json` kwarg is not
checked.

## ROOT_CAUSE_SQL

**Symptom:** Actenon reports `conn.execute("UPDATE runs SET status = ?
WHERE run_id = ?", (run_id,))` as a database mutation with model-controlled
input, but the SQL is a constant string. The model-controlled value
`run_id` is in the bound parameter tuple.

**Root cause (two defects):**

1. **`_is_tainted` does not handle `ast.Tuple`** — same as the Dict defect.
   The bound parameter `(run_id,)` is an `ast.Tuple` containing `ast.Name`
   `run_id`. `_is_tainted` returns `False` for `ast.Tuple` → the taint in
   the bound parameter is invisible.

2. **The blast radius "Model-controlled inputs" field** in
   `actenon_scan/report/pretty.py` `_extract_params()` (line 385) extracts
   argument names from the call_text by splitting on commas. For
   `conn.execute("UPDATE runs SET status = ?", (run_id,))`, it extracts
   `"UPDATE runs SET status = ?"` as the first "parameter" — a string
   literal that is NOT model-controlled. The function does not check
   whether the extracted text is an actual function parameter.

**Evidence:** `_is_tainted` — no `isinstance(node, ast.Tuple)` branch.
`_extract_params` — splits on commas, takes first arg as "parameter"
without checking if it's a function parameter.
