# AREF-001 — Architecture Freeze: Resource Effect Inference (REI)

**Artefact class:** architecture freeze (specification + research). **Not** an
implementation.

**Status:** FROZEN WITH BLOCKED DECISIONS — see
[08-BLOCKED-DECISIONS.md](08-BLOCKED-DECISIONS.md).

**Verdict:** `ARCHITECTURE NOT READY` — see
[REPORT.md](REPORT.md) §28 and §30.

**Frozen against:** `actenon-scan` @ `b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16`
(branch `main`, version `1.5.0`, working tree clean at freeze time).

---

## What this directory is

`actenon-scan` today answers: *is a consequential sink reachable from an
agent boundary, and does a recognised guard dominate it?* It reports a rule
ID (`DATA-DELETE-SQL`) and a consequence category (`data_destruction`).

It does **not** answer: *which resource does this call act on, and what does
it do to it?* `docs/ARCHITECTURE.md` records this gap in its own words:

> **No semantic API models.** Sink rules are pattern-matched, not modelled as
> structured semantic objects (effect category, resource parameters, severity
> characteristics, etc.). The `EffectType` catalogue is a first step in this
> direction.

Resource Effect Inference (REI) is the capability that closes that gap. AREF-001
freezes its architecture — data model, interfaces, invariants, output surface,
gating, and validation plan — **before** any line of it is implemented, so that
the design is reviewable independently of the code that would realise it.

## What this directory is NOT

- It is not an implementation. No file here is imported by `actenon_scan/`.
- It is not evidence. The one empirical claim it makes about the shipped
  scanner (§10 of [10-CONTRADICTION-CHECK.md](10-CONTRADICTION-CHECK.md)) is
  reproducible with a stated command.
- It does not modify `actenon_scan/`, `tests/`, production configuration, or
  any existing research artefact. See [REPORT.md](REPORT.md) §29 for the proof.

## Read in this order

| # | File | What it settles |
|---|---|---|
| 0 | [00-SCOPE-AND-FREEZE.md](00-SCOPE-AND-FREEZE.md) | What is frozen, what is out of scope, what the freeze forbids |
| 1 | [01-EVIDENCE-AVAILABILITY.md](01-EVIDENCE-AVAILABILITY.md) | Which REI evidence was sought, which is accessible, which is missing |
| 2 | [02-ARCHITECTURE.md](02-ARCHITECTURE.md) | Pipeline placement, module layout, data flow, the twelve frozen decisions |
| 3 | [03-DATA-MODEL.md](03-DATA-MODEL.md) | `ResourceEffect`, `ResourceKind`, `ResourceScope`, certainty and UNKNOWN semantics |
| 4 | [04-INTERFACES.md](04-INTERFACES.md) | Frozen signatures and output-surface deltas (no bodies) |
| 5 | [05-INVARIANTS.md](05-INVARIANTS.md) | Twelve invariants, each with a named test obligation |
| 6 | [06-ARCHITECTURE-QUESTIONS.md](06-ARCHITECTURE-QUESTIONS.md) | The seven architecture questions, answered |
| 7 | [07-RISKS-AND-FALSIFICATION.md](07-RISKS-AND-FALSIFICATION.md) | Risk register and the results that would falsify this architecture |
| 8 | [08-BLOCKED-DECISIONS.md](08-BLOCKED-DECISIONS.md) | Decisions that cannot be closed without the missing REI evidence |
| 9 | [09-IMPLEMENTATION-PLAN.md](09-IMPLEMENTATION-PLAN.md) | The slice plan — specified, deliberately not executed |
| 10 | [10-CONTRADICTION-CHECK.md](10-CONTRADICTION-CHECK.md) | Cross-document consistency audit and its findings |
| — | [REPORT.md](REPORT.md) | The 30-section final report |

## Machine-readable artefacts

```
schema/resource-effect.schema.json            one inferred resource-effect record
schema/resource-effect-catalogue.schema.json  the rule-ID -> resource mapping catalogue
schema/rei-report-fragment.schema.json        the additive JSON-report delta
schema/aref-001-manifest.schema.json          this directory's own manifest
catalogue/resource-effect-catalogue.draft.json  DRAFT v0 catalogue, 49 entries
                                              (31 Python + 9 TypeScript + 9 Go
                                               rule IDs; 0 frozen, 38 draft,
                                               11 blocked)
examples/*.json                               positive and negative schema instances
MANIFEST.json / MANIFEST.sha256                SHA-256 of every artefact
```

## Validating this directory

```bash
python3 -m pip install jsonschema
python3 specs/AREF-001/validate.py
```

55 checks: every schema is itself a valid JSON Schema (2020-12); every
positive example validates; every negative example is *rejected*; the draft
catalogue conforms, has unique keys, contains no `frozen` entry and names a
blocked decision on every blocked entry; the vocabularies agree; the catalogue
covers every shipped rule ID exactly and the schema's effect enum equals
`EffectType`; and the manifest matches the files on disk.

The validator contains no detection logic, writes nothing, and imports nothing
from `actenon_scan` — it reads three scanner files by path, because a spec
checker that imports the thing it specifies can be satisfied by a change to
either side.
