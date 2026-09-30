# AREF-001 §9 — Implementation plan (specified, not executed)

**Nothing in this section was performed.** The task prohibits implementing
Resource Effect Inference. The plan exists so that the freeze is actionable by a
future work order, and so that the *sequencing* — which is itself an
architectural decision — is frozen alongside the design.

**Gate:** no slice below may begin until every decision in
[08-BLOCKED-DECISIONS.md](08-BLOCKED-DECISIONS.md) is closed by evidence and
AREF-002 supersedes this document. Slice 0 is the only exception, and only
because it consumes the evidence rather than assuming it.

## 9.1 Slices

### Slice 0 — Close the blocked decisions

Inputs: REI-001, REI-001B, REI-002. Output: AREF-002, recording B-01…B-06 as
closed, with the measured basis for each and a confirmation that no frozen
decision is contradicted (R-12).

No code. This slice is adjudication against evidence, and the options and
thresholds it must choose between are already enumerated in §8, so it is
transcription rather than design.

### Slice 1 — Schema and catalogue only

| | |
|---|---|
| Touches | `actenon_scan/rules/resource_effects.json` (new), `specs/AREF-002/schema/` |
| Does not touch | any Python module |
| Test | `AREF-001-T10` (catalogue validates; no rule ID literal in Python — trivially true at this slice, and the test is written now so it fails later if D-06 is violated) |
| Reviewable in isolation | Yes — a JSON file and a schema |

Shipping the catalogue before the code is deliberate. It is the artefact most
likely to be wrong (B-03), it is the one a domain reviewer can check without
reading Python, and it is inert until slice 2 reads it.

### Slice 2 — Inference, behind the flag, with no output

| | |
|---|---|
| Adds | `actenon_scan/repository/resource_effect.py`; `ScanResult.resource_effect_summary`; one flag-guarded call in `scan_path`; `--resource-effects`; `resource_effects.enabled`; `_KNOWN_KEYS` extension in `rules/loader.py` |
| Renders | nothing. The records exist in memory and in `ScanResult` only |
| Tests | `T01`, `T02`, `T03`, `T05`, `T06`, `T07`, `T12` |

The point of a slice that computes and shows nothing is that `T01` and `T02` —
the invariants that make every existing benchmark gate invariant under REI — are
proven *before* any consumer can depend on the output. If they fail, the layer
is deleted at a cost of one file.

### Slice 3 — JSON output and the disclosure counters, together

| | |
|---|---|
| Adds | `rei_schema_version`, `resource_effect_catalogue_version`, the four counter/breakdown keys, the per-record `resource_effect` object |
| Tests | `T09` (golden, additive), `T11` (counters, including the all-unknown case) |

The counters ship in the **same** slice as the first output, never later. D-13's
justification is the repository's own experience of a layer that shipped
enabled, resolved 2 edges against 3,297 unfollowed, caught 0 of 22 confirmed
cases, and looked fine until resolution was measured separately from findings. A
counter added one slice after the field is a counter added after the first
misreading.

### Slice 4 — Remaining output surfaces

SARIF properties bag; pretty, markdown and HTML single line under the
`certainty >= heuristic` rule; `action.yml` input. Tests: `T04`, `T08` (both
adversarial, both about the two ways a reader gets misled), plus extension of
`T11` to the new formats.

### Slice 5 — Documentation

`docs/ARCHITECTURE.md` (replace the "No semantic API models" limitation with a
description of what now exists and what still does not), `docs/COVERAGE.md`
(catalogue coverage per rule), `README.md`, `CHANGELOG.md`
(`check_version_coherence.py` requires it).

Documentation last, because until slice 4 the honest documentation would have to
describe behaviour no user can observe.

## 9.2 Sequencing constraints that are themselves frozen

| # | Constraint | Why it is not merely a preference |
|---|---|---|
| C-1 | Catalogue before code | The catalogue is the artefact most likely to be wrong and the only one a non-Python reviewer can check |
| C-2 | `T01` and `T02` before any output | They are what make precision/recall/soundness invariant under REI. Proving them after a consumer exists means the consumer has to be unwound if they fail |
| C-3 | Counters in the same slice as the first output | D-13; the alternative has a documented cost in this repository |
| C-4 | Adversarial tests (`T04`, `T08`) before default-on is even discussed | Both encode defects this repository has already shipped once: substring name matching, and entrypoint/resource conflation |
| C-5 | Documentation last | Any earlier and it documents unobservable behaviour |
| C-6 | Default-on is not a slice | It is B-05, and it is a separate decision requiring its own evidence and its own review |

## 9.3 Effort shape

Not in calendar time — in blast radius, which is what determines reviewability.

| Slice | New files | Existing files touched | Behavioural risk |
|---|---|---|---|
| 0 | 1 spec directory | 0 | none |
| 1 | 2 (catalogue, schema) | 0 | none — inert data |
| 2 | 2 (module, test) | 3 (`engine.py`, `cli.py`, `rules/loader.py`) | low — one flag-guarded call site |
| 3 | 0 | 2 (`json_out.py`, test) | low — additive keys |
| 4 | 0 | 5 (`sarif.py`, `pretty.py`, `markdown_out.py`, `html_out.py`, `action.yml`) | low — presentation only |
| 5 | 0 | 4 docs | none |

The largest single diff is slice 2's new module. No slice modifies
`detectors/sinks.py`, `detectors/reachability.py`, `detectors/guards.py`, or any
benchmark fixture — which is the mechanical restatement of "detection must not
change" and of `CONTRIBUTING.md` Rule 3.

## 9.4 Abandonment criteria

Stated now, because a plan without a stopping condition tends not to have one.

Delete the layer rather than fix it if:

- `AREF-001-T01` or `AREF-001-T02` cannot be made to pass — the non-gating
  premise (D-01) is false, and everything in this freeze rests on it;
- falsifier F-1 or F-2 fires on real measurement — the layer is honest and
  useless, which is a reason to stop, not a reason to add heuristics;
- closing B-04 requires a `WHERE`-presence regex — that produces a false
  *narrowing* claim, and shipping it would contradict the principle the whole
  codebase is organised around.

Abandonment after slice 2 costs one file and one flag. That cheapness is not an
accident; it is the reason slice 2 renders nothing.
