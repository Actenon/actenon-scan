# AREF-001 §5 — Invariants and test obligations

Twelve invariants. Each has a named test obligation. `CONTRIBUTING.md` states
the project rule these follow: *"Every change MUST come with a test that fails
without it and passes with it."* The freeze's contribution is to name the tests
before the code exists, so the implementing work order cannot choose its own
easier ones.

The obligations are numbered `AREF-001-T01` … `AREF-001-T12` and belong in
`tests/repository/test_resource_effect.py`, except T01/T02/T09, which need a
full scan and belong in a top-level `tests/test_resource_effect_additive.py`.

**No test in this section has been written.** Writing it would modify `tests/`,
which this task prohibits.

---

## I-01 — REI never changes the finding set

Scanning a fixture with `--resource-effects` and without it must yield
identical `findings` lists: same length, same order, same
`(file, line, col, rule_id, severity, effective_severity, confidence,
suppressed)` for every element.

**Obligation `AREF-001-T01`.** Scan one fixture twice through `scan_path`, once
with the flag and once without; assert the projected tuples are equal as
ordered lists. Must also assert `capability_count` is equal.

*Why first.* This is the invariant that makes every benchmark gate in the
repository invariant under REI without re-running any of them. If T01 passes,
precision 16/16, recall 9/10 and soundness 6/6 cannot have moved. If T01 is
weakened to "same set" rather than "same order", it stops proving that, because
a reordering changes the most-exposed ranking in
`report/blast_radius.py`.

---

## I-02 — REI never changes severity

For every finding, `severity` and `effective_severity` are identical with and
without the flag, including for records whose `scope` is `all` and whose
`controllability` is `model_controlled`.

**Obligation `AREF-001-T02`.** A fixture containing a deliberately
maximum-alarm site (unbounded scope, model-controlled selector) must produce
the same severity both ways. The fixture must be *new*, not an adjusted
benchmark fixture — `CONTRIBUTING.md` Rule 3 forbids moving a benchmark number
by changing a fixture, and the same logic forbids reusing one to make a new
assertion convenient.

---

## I-03 — Every annotated site has a record

When the layer runs, every `Capability` has a non-`None`
`resource_effect`. There is no code path that skips a site.

**Obligation `AREF-001-T03`.** Scan a fixture containing at least one rule with
a `frozen` catalogue entry, one with `blocked`, and one with no entry at all;
assert `all(c.resource_effect is not None for c in result.capabilities)` and
that the three produce `catalogue_status` `frozen`, `blocked`, `absent`
respectively.

---

## I-04 — No name-based resource inference

A rule ID absent from the catalogue yields `unknown_resource` even when the
call's identifiers are maximally suggestive.

**Obligation `AREF-001-T04`.** Adversarial. A call site with an unmapped rule ID
whose receiver is named `users_table`, whose argument is named
`production_database`, and which lives in a file named `db_admin.py`, must
produce `kind == unknown_resource` and
`unresolved_reason == "rule_id_not_in_catalogue"`. A second case must assert the
converse direction of the historical defect: a receiver named `sandbox` must
never yield `database_row_set`.

*Why this specific fixture.* The second case is the shape of a defect this
repository actually shipped: `_name_looks_db` matched by unanchored substring,
so `"sandbox"` contained `"db"` and a shell executor was reported as
destructive SQL at HIGH severity. The test exists to make the regression
impossible in the new layer rather than merely unlikely.

---

## I-05 — Certainty never exceeds reachability certainty

For every record, `CERTAINTY_ORDER[record.certainty] <=
CERTAINTY_ORDER[reachability_certainty]`.

**Obligation `AREF-001-T05`.** Unit test over the cross product of
`AnalysisCertainty` × catalogue statuses, calling `infer_resource_effect`
directly with a `frozen` entry and a fully resolvable literal selector, and
asserting the cap holds in all cases — including `analysis_error`, which must
dominate.

---

## I-06 — `proven` is unreachable in v0

No input produces `certainty == PROVEN`.

**Obligation `AREF-001-T06`.** Property-style: enumerate every catalogue entry
in the shipped catalogue, construct a best-case call for each (literal
argument, proven reachability), and assert the result is at most `strong`.

*Why an explicit test for an absence.* The ceiling table in
[03-DATA-MODEL.md](03-DATA-MODEL.md) §3.7 is a claim about a `max_certainty`
field in a data file. Data files get edited. A test is the only thing that keeps
a future catalogue edit from quietly minting proofs.

---

## I-07 — Effect verbs come only from `EffectType`

Every `ResourceEffect.effect` is a member of `EffectType`.

**Obligation `AREF-001-T07`.** Assert `set(e.effect for e in records) <=
set(EffectType)`, and separately assert that the JSON schema's `effect` enum
equals `[e.value for e in EffectType]` — so a future `EffectType` addition
fails the test until the schema is bumped (D-04).

---

## I-08 — `resource_boundary` and `resource_effect` stay independent

The entrypoint-class concept and the resource concept do not interact.

**Obligation `AREF-001-T08`.** Scan a fixture with
`--resource-boundary --resource-effects`; assert (a) no record has a `kind`
derived from the route decorator, (b) the set of `ResourceKind` values contains
no member denoting an entrypoint, and (c) toggling `--resource-boundary` changes
*which* sites are reported but never the `resource_effect` of a site reported
both ways.

*Why.* Commit `f472a57` records the root cause of a shipped defect as exactly
this conflation: "`resource_boundary` signals produce HIGH confidence
reachability, but the pretty output said 'agent entry point' for ALL signals."
T08 is the regression test for the *next* instance of that defect, in the layer
most likely to cause it.

---

## I-09 — Output is additive and absent when off

With the layer off, JSON output is byte-identical to the pre-REI output for the
same input. With it on, every added key is new.

**Obligation `AREF-001-T09`.** Golden-file comparison of `format_json` output
with the flag off against a committed golden produced before the REI change;
plus a key-set assertion that the on/off difference is exactly the documented
key list and contains no removal and no type change.

---

## I-10 — The catalogue is data-only

No rule ID requires Python to determine its resource kind or selector location.

**Obligation `AREF-001-T10`.** Structural. Load the shipped catalogue, assert
every entry validates against
`schema/resource-effect-catalogue.schema.json`, and assert
`resource_effect.py` contains no string literal equal to any rule ID, module
name, or provider name — i.e. the module is generic over the catalogue. A grep
assertion is crude but it is the only mechanical guard against the catalogue
being quietly reimplemented in code (D-06).

---

## I-11 — Unknowns are disclosed

`resource_effect_known_count` and `resource_effect_unknown_count` appear in
every output format whenever the layer ran, including on a scan with zero
findings, and `known + unknown == capability_count`.

**Obligation `AREF-001-T11`.** Assert the identity holds, and assert the
counters are present in JSON, SARIF properties, pretty, markdown and HTML. A
separate case must assert they are present when `unknown_count ==
capability_count` — the all-unknown case, which is the one a shipped
mis-implementation would produce and the one a reader must not mistake for "no
resources here".

*Why.* The repository has already shipped an analysis layer that resolved
almost nothing while appearing to work: 2 followed edges against 3,297
unfollowed, 0 of 22 confirmed cases caught, invisible until resolution was
measured separately from findings. `transitive_unfollowed_count` was the fix.
T11 is that fix, installed before the mistake rather than after.

---

## I-12 — Determinism

Two runs over identical inputs produce identical records.

**Obligation `AREF-001-T12`.** Run `annotate_capabilities` twice over the same
parsed ASTs and assert the serialised records are equal strings. Must also
assert `selector.text` equals the exact source segment, so a future
reconstruction-based implementation fails.

---

## 5.1 Obligation summary

| ID | Invariant | Kind | Location |
|---|---|---|---|
| `AREF-001-T01` | I-01 finding set unchanged | end-to-end | `tests/test_resource_effect_additive.py` |
| `AREF-001-T02` | I-02 severity unchanged | end-to-end | `tests/test_resource_effect_additive.py` |
| `AREF-001-T03` | I-03 record always present | unit | `tests/repository/test_resource_effect.py` |
| `AREF-001-T04` | I-04 no name-based inference | adversarial | `tests/adversarial/` |
| `AREF-001-T05` | I-05 certainty cap | unit | `tests/repository/test_resource_effect.py` |
| `AREF-001-T06` | I-06 no `proven` in v0 | property | `tests/repository/test_resource_effect.py` |
| `AREF-001-T07` | I-07 effect vocabulary | unit + schema | `tests/repository/test_resource_effect.py` |
| `AREF-001-T08` | I-08 boundary/effect independence | adversarial | `tests/adversarial/` |
| `AREF-001-T09` | I-09 additive output | golden | `tests/test_resource_effect_additive.py` |
| `AREF-001-T10` | I-10 catalogue is data | structural | `tests/repository/test_resource_effect.py` |
| `AREF-001-T11` | I-11 disclosure counters | end-to-end | `tests/test_repository_disclosure_gate.py` (extend) |
| `AREF-001-T12` | I-12 determinism | unit | `tests/repository/test_resource_effect.py` |

T11's home is an existing file (`tests/test_repository_disclosure_gate.py`)
because the disclosure-gate idea already lives there and splitting it would let
one half be satisfied while the other rots. That file is **not** modified by
this task.

## 5.2 What no test can establish

Every invariant above is a *safety* property — a statement that REI does not
make things worse. **None of them is a usefulness property.** No test in this
list shows that a single inferred resource is correct, that the twenty
`ResourceKind` members are the right twenty, or that a reader's decision
improves.

Those are measurement questions, and they are exactly what the unavailable
REI-001 / REI-001B / REI-002 evidence would answer. A reviewer should read
§5.1 as "this layer is provably harmless", never as "this layer is proven
useful". The distinction is the substance of the verdict in
[REPORT.md](REPORT.md) §30.
