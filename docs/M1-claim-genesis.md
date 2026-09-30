# M1: universal claim genesis

Starting point: `641ea796a5114ac6f9a0940415f42dc25ed57889`.

An effect is a claim to be proved, not a sink to be matched. M1 enumerates
invocations reachable from callable roots and instantiates the frozen M0
`EXTERNAL_PERSISTENT_STATE_EFFECT` claim. It acquires no effect evidence.

## Reuse and production delta

Reuse the Python, TypeScript and Go repository indexes, their local import and
call resolution, existing tool registration/reachability recognizers, scanner
file-selection policy, and the frozen M0 constructors and CoverageLedger.
Keep the legacy engine, Capability, Finding, rules and reporters unchanged.

Add a language-neutral InvocationGraph, thin index adapters, and one claim
genesis engine exposed as `scan_effect_claims` and `actenon-scan claims`.
Explicit `Entrypoint(path, symbol, kind)` roots use the same traversal as
automatically discovered model-callable roots. Root kind is provenance only.
The API and CLI are additive; ordinary `scan` retains its frozen behavior.
No frozen spec or effects-package changes are needed.

## Graph and reachability

Invocation identity hashes language, repository-relative file, line, column and
lexical ordinal for nested calls sharing a start coordinate;
it excludes callee spelling and rule matches. Each reached invocation stores
caller, callee spelling, resolution certainty, possible implementations,
workspace-exit knowledge, optional rule provenance, and a shortest invocation
path for every root that reaches it. Local symbol identity includes language
and file to avoid collisions between languages and same-named packages.

Only established local edges are traversed. Heuristic matches are retained
as candidates, with an unresolved alternative, and never make an unrelated
helper reachable. Multiple candidates are never reduced to the first.
Nested callable bodies have their own caller identity; merely constructing a
callable does not execute its body. Inline registered handlers are roots.
Missing explicit roots, unsupported files, parser/index/resolution failures,
and bounded traversal gaps are disclosed. Cycles use visited sets.

## Frozen M0 integration

Emit one claim per (root, invocation, effect class), including calls with no
matching rule. M1 does not establish inertness and therefore emits obligations
for all reached calls. All obligations, CONTROL and AUTHORITY remain UNKNOWN;
resolution metadata alone is not an evidence packet. Even exact local graph
resolution conservatively retains UNRESOLVED_IDENTITY in the M0 claim.
An unknown ordinary call carries OPAQUE_EXTERNAL; computed dispatch carries
DYNAMIC_UNRESOLVED. Possible local bodies remain set-valued. No provider or
operation spelling changes semantic states.

Claims stop with CLAIM_NOT_INVESTIGATED and carry ABSTAIN. A resolution failure
on an enumerated reached call carries IMPLEMENTATION=ERROR, SELECTION_ERROR,
ACQUISITION_ERROR and ANALYSIS_ERROR. A failed file has no invented invocation
or ABSTAIN claim: it is an analysis error/coverage gap on the graph result.

CoverageLedger counts root-scoped invocation occurrences (the M0 capability
coordinate), so overlapping roots preserve the frozen claim/invocation
arithmetic. Mechanical graph accounting additionally reports unique calls
enumerated/reached, roots discovered/supplied, resolved/unresolved calls,
unsupported files, errors and traversal gaps. It adds no second verdict or
epistemic summary. Ledger.analysis_errors counts only errored claims, as its
frozen contract requires; file errors are reported separately.

Rule IDs may be supplied as call-site annotations. They never drive graph
construction, traversal, candidate selection, claim existence or proof states.

## Validation order

Write failing sink-free tests before production code: all three root kinds and
languages, rename/rule-removal invariance, unreachable helpers, set-valued
ambiguity, cycles/bounds, failure disclosure and frozen M0 round trips/schema
conformance. Then implement, run focused and legacy suites, and run the full
suite. Compare every serialized legacy Finding on the frozen regression
corpus before/after. Evaluate only already-exposed R01–R04 development evidence
after synthetics pass; never inspect R05–R07 or add provider rules.

## Use

```sh
actenon-scan claims ./workspace
actenon-scan claims ./workspace --no-discover-roots \
  --entrypoint src/main.py:run:PROGRAM_ENTRY \
  --entrypoint src/resource.ts:serve:RESOURCE_ENTRY
```

```python
from actenon_scan import Entrypoint, RootKind, scan_effect_claims

result = scan_effect_claims("./workspace", entrypoints=[
    Entrypoint("src/main.py", "run", RootKind.PROGRAM_ENTRY),
])
```

JSON includes the common graph, frozen claims and CoverageLedger, mechanical
coverage, analysis errors, unsupported files and coverage gaps. Exit code 0
means enumeration completed; claims normally ABSTAIN and have not been
investigated. Exit code 2 discloses analysis errors, unsupported source or
bounded coverage. Neither exit code asserts safety.

Automatic roots reuse configured Python callable-boundary recognizers and
structural TS/Go registration recognition. File-level framework imports and
class-instantiation heuristics do not establish that unrelated callable bodies
are reached. Explicit roots cover application-specific registration seams
without production framework rules. Anonymous callback symbols include their
line and one-based byte column; named entrypoints are preferable for stable
user configuration.

`matched_rule_ids` is an optional API mapping from `(relative_path, line,
one_based_byte_column)` to IDs. The caller can reuse existing sink matching to
provide those annotations; the graph and claims are identical when annotations
are absent. Rule-free ledger counts refer to recorded provenance. No M1
production rule matching pass is required.
