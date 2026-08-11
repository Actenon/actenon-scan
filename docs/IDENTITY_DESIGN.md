# Identity Design — Capability Semantic Identity

## Decision: file path is evidence, not identity

A function moved between files is **UNCHANGED**. The capability identity
key does not include the file path — only the function name and sink
characteristics.

### Why

Agent frameworks register handlers by name, not by file location. A
refactor that moves `send_update` from `tools/send.py` to `handlers/notify.py`
does not change what the agent can do. If identity included file path,
every such move would read as REMOVED_CAPABILITY + NEW_CAPABILITY,
swamping the diff with false positives and hiding real changes.

### Key fields

The capability key (`CapabilityKey` in `identity.py`) is:

  - `language` — "python" / "typescript" / "go"
  - `entry_point_kind` — "handler" / "import" / "module" (from reachability_source)
  - `function_name` — bare name of the enclosing function
  - `sink_family` — the rule_id (e.g. "EXEC-SHELL")
  - `resource_type` — the category (e.g. "shell_execution")

### What is NOT in the key

  - **File path** — evidence, not identity (see above)
  - **Line number** — changes on any edit
  - **Guard state** — comparable state, NOT part of identity. A capability
    moving from GUARD_FOUND → REVIEW_REQUIRED is a state change, not a
    different capability.
  - **Call text** — changes on parameter rename, string formatting, etc.
  - **Snippet hash** — changes on any whitespace or comment edit

### Documented limitation: name collisions

Identity depends on entry-point name uniqueness across the repository.
Two functions named `run_command` in different files share a key.

This is a deliberate trade-off: the alternative (qualified names
including class membership) would require the scanner to track class
context, which it does not currently do. Bare-name identity is correct
for the common case (most repositories have unique handler names) and
the collision case is detectable in the manifest (the key appears with
multiple evidence locations).

### Three-language parity

`function_name` is populated for:
  - **Python**: threaded from `_find_enclosing_function_with_parents`
    in `detectors/sinks.py`
  - **TypeScript**: from `_get_function_name` in `detectors/typescript.py`
  - **Go**: already present on `GoFinding.function_name` from WO1.5

### Path canonicalisation

`_normalise_path` in `engine.py` converts backslash to forward slash at
capability construction time. A Windows-style path (`src\pkg\mod.py`) and
a POSIX path (`src/pkg/mod.py`) for the same file produce the same key.
No case folding, no symlink resolution — just separator normalisation.
