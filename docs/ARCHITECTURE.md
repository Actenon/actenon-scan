# Architecture — repository-level consequence analysis

This document describes the architecture of the repository-level
analysis layer added in `actenon_scan/repository/`. It is the
authoritative reference for what the layer does, what it does not do,
and how it integrates with the existing per-file scan engine.

## Design philosophy

The repository layer obeys four non-negotiable principles (mirroring
the project's overall stance):

1. **FALSE ASSURANCE IS WORSE THAN A REVIEWABLE FALSE POSITIVE.**
   Every analysis state has a literal `UNKNOWN` value; nothing labelled
   `unknown` is ever silently promoted to `safe`.
2. **EVIDENCE OVER HEURISTICS.** Resolved-symbol edges dominate
   heuristic-name-match edges, which dominate unresolved-dynamic-call
   edges. The weakest edge in a path determines the path's certainty.
3. **BACKWARDS COMPATIBILITY.** The repository layer is opt-in via
   `--repository-analysis` (default off). Existing per-file findings
   are NEVER suppressed — the layer only adds new findings or augments
   existing ones with call-chain evidence.
4. **EVERY NEW ANALYSIS CLAIM REQUIRES A TEST.** See
   `tests/repository/` (unit tests for each primitive) and
   `tests/adversarial/` (end-to-end tests against dangerous programs).

## Module layout

```
actenon_scan/repository/
├── __init__.py            # public re-exports
├── symbol_index.py       # RepositoryIndex + Symbol/Import/CallSite
├── call_graph.py         # CallGraph + build_call_graph + transitive_reachable
├── effect_summary.py     # EffectType + EffectSummary + propagate_effects
├── taint.py              # TaintLattice + function_local_dataflow
├── certainty.py          # AnalysisCertainty + combine_certainty
└── engine_augment.py     # analyze_repository — the engine integration
```

## Repository layer

### RepositoryIndex (`symbol_index.py`)

A `RepositoryIndex` represents everything the analyser knows about a
repository's Python source files:

- **Files** (relative path) and their qualified module names
- **Symbols** — functions, methods, classes, modules. Each `Symbol`
  carries its qualified name (`pkg.mod.ClassName.method`), source
  location, decorators, and enclosing class (if any).
- **Imports** — every `import` / `from x import y` statement. Each is
  classified with explicit `ResolutionCertainty`:
  - `RESOLVED` — the import unambiguously resolves to a local target.
  - `HEURISTIC` — best-effort name match (no symbol evidence).
  - `UNRESOLVED` — dynamic form (`importlib.import_module`,
    `__import__`, `from x import *`).
- **Call sites** — every `ast.Call` in every function. Each carries
  the textual callee, the caller's qualified name, and arg/kwarg text.

Import resolution is **deferred** to a `finalize()` pass so that
cross-file imports (`main.py` importing from `srv.py`) resolve
correctly regardless of file-add order.

The `resolve_call_target(callee_node, in_module)` API resolves an AST
call node to a `Symbol` with explicit certainty. Bare names resolve
via the module's bindings; `self.foo()` resolves via the class's
method table; dynamic forms return `UNRESOLVED`.

### CallGraph (`call_graph.py`)

Adjacency-list call graph with provenance. Each `CallEdge` records:

- `caller` and `callee` qualified names
- `certainty` — inherited from symbol resolution
- `site` — the original `CallSite` (location, callee text, args)

UNRESOLVED edges are preserved (not silently dropped) so that
downstream analysis knows a call *exists* even when its target is
unknown.

`transitive_reachable(graph, entrypoints, max_depth=32)` is a
breadth-first search with:

- A visited set (cycle-safe — recursion and mutual recursion work)
- Depth bound; paths that exceed it are marked `truncated=True` but
  the reachability claim still holds
- The shortest path is returned per reachable node

`CallPath.certainty()` returns the weakest certainty across all edges
in the path (a single `UNRESOLVED` edge makes the whole path
`UNRESOLVED`).

### EffectSummary (`effect_summary.py`)

Each function's effect set is the set of consequential side-effect
categories its execution can produce. The `EffectType` catalogue has
20 entries (`SHELL_EXECUTION`, `MONEY_MUTATION`, `DATA_DELETION`,
`EMAIL_SEND`, `CREDENTIAL_ACCESS`, etc.). `effect_for_rule_id`
maps sink rule IDs to effect types.

Each `EffectSummary` carries provenance:

- `concrete_sink` — the `(file, line)` of the direct sink
- `propagated_from` — the callee qualified name from which the effect
  was inherited
- `rule_id` — the original rule that gave rise to the effect

`propagate_effects(graph, direct_sinks)` computes effect summaries
for every function via:

1. Seed each function's summary with its direct sinks.
2. Compute SCCs (Tarjan, iterative).
3. Process SCCs in reverse topological order (callees before callers).
4. Within an SCC, iterate to fixed point (bounded by `max_iterations`).
5. Mark summaries with `has_unresolved_callee=True` when a function
   calls an unresolved callee — these go on the `incomplete` list.

### TaintLattice + function_local_dataflow (`taint.py`)

The taint lattice (weakest to strongest):

```
UNTAINTED → CONSTRAINED → EXTERNAL → MODEL_DERIVED → MODEL_CONTROLLED → UNKNOWN
```

`UNKNOWN` is the **strongest** state for joins — any join with
`UNKNOWN` produces `UNKNOWN`. This is the core conservative invariant:
**a transformation NEVER downgrades taint**, and an unknown value is
never silently promoted to "safe".

`function_local_dataflow(func_node, sink_node, index, module_qname)`
traces taint from a sink's arguments back to function parameters.
Tracks:

- assignment: `x = payload`
- attribute access: `param.command`, `trackedlocal.attr`
- dict access: `param[...]`, `trackedlocal[...]`
- f-strings
- string concatenation
- `str()`, `int()`, `float()`, `Path()`, `json.loads()` — pass-through
- 1-hop wrapper functions (single `return <param>`)
- Constant arguments → no trace (untainted)

Returns a `TaintTrace` with `parameter_name`, ordered `operations`
list, `final_state`, and `certainty` ("proven" / "heuristic" /
"unknown").

### AnalysisCertainty (`certainty.py`)

Six explicit certainty levels:

| Level | Meaning |
|-------|---------|
| `PROVEN` | Evidence sufficient for the claim |
| `STRONG` | Strong evidence, one weak link |
| `HEURISTIC` | Name-pattern or single-candidate match |
| `UNKNOWN` | No evidence — claim NOT promoted |
| `UNSUPPORTED` | Feature not implemented for this language/case |
| `ANALYSIS_ERROR` | Analysis attempted and failed |

`combine_certainty(*levels)` returns the weakest link. `ANALYSIS_ERROR`
dominates (an error in the chain invalidates the conclusion).

## Engine integration (`engine_augment.py`)

`analyze_repository(target, findings, capabilities, reachability_cfg, ...)`
runs AFTER the per-file scan. Steps:

1. Build `RepositoryIndex` from the engine's filtered file list (so
   `.venv/`, `__pycache__/`, test directories are not parsed).
2. `discover_entrypoints(index, reachability_cfg)` finds all
   `@tool`-decorated functions and methods of tool-base classes.
3. `transitive_reachable(graph, entrypoints)` computes reachability.
4. `_seed_direct_sinks` combines:
   - per-file findings/capabilities (already classified)
   - independent `detect_sinks` run on every indexed file (catches
     sinks in functions the per-file scan skipped because they aren't
     directly agent-reachable)
5. `propagate_effects` propagates effects through the call graph.
6. For each sink-bearing function that IS reachable from an
   entrypoint:
   - If the per-file scan already caught it → augment the existing
     finding's `reachability_reason` with the call chain.
   - If the per-file scan missed it → emit a new finding with
     `transitive:<chain>` reachability reason.

**Conservative properties pinned by tests:**

- Per-file findings are never suppressed (`test_repo_layer_does_not_suppress_existing_findings`).
- Dynamic dispatch does not silently resolve (`test_dynamic_dispatch_does_not_silently_resolve`).
- Unreachable helpers are not flagged (`test_unreachable_helper_not_flagged_by_repo_layer`).
- Recursion and mutual recursion converge (`test_recursion_does_not_crash`).
- Adversarial transformations (renamed variables, aliased imports,
  cross-file moves, wrapper functions) still produce findings
  (`test_renamed_variables_still_caught`, `test_aliased_import_still_caught`,
  `test_objective2_cross_file_hidden_sink`).
- Analysis errors are surfaced in `analysis_errors`, never silently
  swallowed (`test_repo_analysis_error_is_recorded`).

## What this layer does NOT do (documented limitations)

These limitations are explicit, never silently papered over:

- **Dynamic dispatch is invisible.** `getattr(obj, name)()` produces
  an `UNRESOLVED` edge — the call site is recorded but the target
  cannot be statically resolved. Plugin registries, dynamic imports
  via `importlib.import_module(name)`, and runtime monkey-patching
  are all in this category.
- **Cross-language call graphs do not exist.** The repository layer
  is Python-only. A Python function calling into TypeScript or Go
  via FFI or shell-out produces an `UNRESOLVED` edge.
- **No interprocedural taint.** Taint analysis is function-local.
  The 1-hop wrapper case is the only inter-procedural form supported.
  Cross-function taint propagation requires per-function taint
  summaries — planned but not implemented.
- **No control-flow graph.** Guard dominance is still AST-ancestry
  based (see `guards.py:_build_parent_map`). A proper CFG with
  dominator analysis is planned but not implemented.
- **No authority/action binding.** The repository layer can prove
  a sink is reachable, but cannot verify that the authority call's
  parameters bind to the sink's parameters. This is the next major
  slice.
- **No semantic API models.** Sink rules are pattern-matched, not
  modelled as structured semantic objects (effect category,
  resource parameters, severity characteristics, etc.). The
  `EffectType` catalogue is a first step in this direction.
- **Performance is O(N) per file with parent maps; O(N+M) for call
  graph construction where M = total call sites.** Self-scan of the
  actenon-scan repo (52 production files) takes ~7s with
  `--repository-analysis` enabled, vs ~1s without. Larger repos
  will be slower; the cache (per-file content-hash) does NOT cover
  the repository layer.

## Where to add new analysis

To extend the repository layer:

1. **New effect type** — add to `EffectType` in
   `effect_summary.py`, add a mapping in `_RULE_ID_TO_EFFECT`, add a
   test in `tests/repository/test_effect_summary.py`.
2. **New taint transformation** — add a case in
   `_taint_of_expression` in `taint.py`, add a test in
   `tests/repository/test_taint.py`.
3. **New entrypoint kind** — extend `discover_entrypoints` in
   `engine_augment.py`, add an adversarial test in
   `tests/adversarial/`.
4. **New certainty level** — add to `AnalysisCertainty` in
   `certainty.py`, update `CERTAINTY_ORDER` and `combine_certainty`.

Every change MUST come with a test that fails without it and passes
with it (per the project-wide rule).

## Later-slice modules (foundations, not yet wired into the engine)

The following modules were added in subsequent slices as **standalone
primitives**. They are NOT yet called from `engine_augment.py` — they
are substrates for future integration. Each is pinned by its own test
file in `tests/repository/` plus adversarial tests in
`tests/adversarial/`.

### `guard_resolution.py` — Cross-file guard body inspection (Objective 7)

Extends the per-file guard analyzer's name-heuristic fallback with
repository-local evidence. When a guard call resolves to a function
defined elsewhere in the repo (via `RepositoryIndex`), the body is
inspected for:

- `ast.Raise` anywhere → `raises_on_failure=True` (assert-style)
- `ast.Return` at top level → `returns_bool=True` (predicate-style)

Public API:

- `GuardStyle` enum: `ASSERT` / `PREDICATE` / `UNKNOWN`
- `GuardBodyInspection` dataclass
- `GuardResolution` dataclass
- `resolve_guard_call(call_node, in_module, index)` — main entry
- `inspect_guard_body(guard_symbol, index)`

Conservative invariants:

- A guard whose body cannot be inspected → UNKNOWN, never silently
  promoted to ASSERT.
- A guard that both raises AND returns → UNKNOWN.
- The conservative name-heuristic fallback (when the guard is
  unresolved) is the SAME list as `guards.py:655-659` — it
  deliberately excludes `check_permission`, `check_access`,
  `check_auth`, `verify_token` (bias to UNKNOWN, never ASSERT).

### `guard_semantics.py` — Semantic guard taxonomy (Objective 5)

Classifies guard names into 9 semantic kinds so downstream
authority-binding can refuse to treat authentication as action
authorization.

`GuardKind` members:

- `AUTHENTICATION` — proves *who* (never authorizes an action)
- `AUTHORIZATION` — proves *what may be done* (action-specific)
- `VALIDATION` — proves input well-formed (never authorizes an action)
- `SANITIZATION` — transforms input (never authorizes an action)
- `HUMAN_APPROVAL` — separate human channel
- `POLICY_ENFORCEMENT` — OPA/Cedar/Casbin
- `CAPABILITY_PROOF` — PCC/PCCB token check
- `RATE_LIMIT` — throttles (never authorizes an action)
- `UNKNOWN_GUARD`

Public API:

- `classify_guard_name(name)` → `GuardClassification`
- `classify_guard_call(call_node)` → `GuardClassification`
- `action_authorization_strength(classification)` → `'strong'` /
  `'weak'` / `'none'`
- `extract_action_label(name)` → action label (e.g. `"refund"` from
  `"authorize_refund"`) or `None` for non-authorization guards
- `infer_sink_action_label(sink_call_name)` → action label inferred
  from the sink's name

The CRITICAL invariant: `AUTHENTICATION` and `VALIDATION` MUST NEVER
have `is_action_authorization=True`. Pinned by
`test_authenticate_is_authentication_not_authorization`,
`test_validate_email_is_validation_not_authorization`, and the
adversarial `test_authentication_does_not_authorize_refund`.

### `authority_binding.py` — Authority/action value binding (Objective 8)

Compares the parameters of an authority call (e.g.
`authorize_refund(cust, amt)`) with the parameters of a sink call
(e.g. `refund(cust, amt)`) using taint provenance.

`BindingState` members: `BOUND` / `UNBOUND` / `UNKNOWN`.

Public API:

- `compare_authority_to_sink(authority_call, sink_call, func_node, ...)`
  → `BindingResult`
- `compare_all_authority_to_sink_params(...)` → `list[BindingResult]`
- `overall_binding_state(results)` → worst-case aggregation
  (`UNBOUND` > `UNKNOWN` > `BOUND`)

**Soundness gate (runs FIRST):** the action-label check. The
authority's action label (e.g. `"read"` from `authorize_read`) is
compared against the sink's action label (e.g. `"refund"` from
`refund`). When they differ, the binding is provably `UNBOUND`
regardless of parameter matching. This is the canonical hostile
case from the brief:

```python
authorize_read(cust)
refund(cust, amt)
```

Even though `cust` matches at index 0, the authority is for the
*read* action while the sink performs the *refund* action. The
soundness gate catches this BEFORE the parameter-binding check and
returns `UNBOUND`. Pinned by
`test_authority_binding_wrong_action_unbound` (adversarial).

Conservative invariants:

- `UNKNOWN` is NEVER silently promoted to `BOUND`.
- One constant, one parameter → `UNBOUND` (provably different values).
- A taint transformation NEVER downgrades — an unrecognized call's
  result is `UNKNOWN`, not `UNTAINTED`.

### `cfg.py` — Control Flow Graph + dominator analysis (Objective 6)

Builds a per-function CFG and computes immediate dominators via the
Cooper-Harvey-Kennedy iterative algorithm. Currently a standalone
primitive — NOT yet wired into `guards.py` (the existing AST-ancestry
dominance check in `guards.py` is still the active path).

Public API:

- `CFGNode` dataclass (basic block: id, statements, successors,
  start_line, terminator)
- `CFG` dataclass (entry, nodes dict, function_name)
- `build_cfg(func_node)` → `CFG`
- `dominators(cfg)` → `{node_id: immediate_dominator_id}`
- `dominates(cfg, doms, dominator_id, dominated_id)` → `bool`
- `reverse_postorder(cfg)` → `list[int]`

Handles: sequential execution, if/elif/else, early return, raise,
for/while loops (with break/continue), nested function defs (opaque).

Documented limitations: try/except/finally and match/case are NOT
modelled (treated as opaque sequential blocks). Pinned by
`test_cfg.py`'s 14 tests including the brief's Case A
(if-cond-authorize-then-sink — does NOT dominate), Case B
(authorize-before-if-sink-after — DOES dominate), and Case C
(sink-before-authorize — NOT guarded).

### `ts_symbol_index.py` — TypeScript symbol index (Objective 11, partial)

Mirrors the Python `RepositoryIndex` API for TS/JS source files.
Uses `tree-sitter-typescript` (already a dependency via the
`[typescript]` extra). Builds the substrate for a future TS call
graph + transitive reachability layer (not yet implemented).

Public API:

- `TSSymbolKind` enum: `MODULE` / `FUNCTION` / `ARROW_FUNCTION` /
  `CLASS` / `METHOD`
- `TSSymbol`, `TSImport`, `TSResolvedTarget`, `TSCallSite` dataclasses
- `TSRepositoryIndex` with `build()`, `add_file()`, `finalize()`,
  `resolve_call_target()`, `lookup_symbol()`, `call_sites_in()`

Conservative invariants:

- Dynamic imports (`await import('mod')`) → UNRESOLVED, never silently
  resolved.
- Computed-key property access (`obj[name]()`) → UNRESOLVED.
- External bare specifiers → HEURISTIC, never silently treated as local.
- Re-uses the SAME `ResolutionCertainty` enum as the Python index.

## Conservative invariants across all later-slice modules

Every module in this section preserves the project-wide rule:
**FALSE ASSURANCE IS WORSE THAN A REVIEWABLE FALSE POSITIVE.**

- `UNKNOWN` is never silently promoted to a stronger state.
- Heuristic matches are explicitly labelled (`HEURISTIC` certainty,
  `'weak'` strength, etc.) — never silently treated as proven.
- External guards fall back to a name heuristic ONLY when no body is
  available, and the heuristic deliberately biases to UNKNOWN/weak for
  ambiguous names (`check_permission`, `check_access`, `check_auth`,
  `verify_token`).
- The authority-binding layer's soundness gate (action-label check)
  runs BEFORE the parameter-binding check, so an authority for the
  wrong action cannot slip through via parameter matching alone.

## What these modules do NOT yet do (integration is the next slice)

- `engine_augment.py` does NOT call `resolve_guard_call`,
  `classify_guard_name`, `compare_authority_to_sink`, or
  `build_cfg` yet. The existing per-file guard analyzer in
  `guards.py` is unchanged.
- The TS index is a substrate only — no TS call graph, no TS
  transitive reachability, no TS effect propagation.
- The CFG primitive is not wired into `guards.py`'s dominance check.
- The authority-binding layer's results are not yet surfaced in
  findings' evidence chains.

These integrations are the next slices. The current state is
**MATERIAL IMPROVEMENT** with foundations pinned by 95 repository
unit tests + 25 adversarial end-to-end tests.
