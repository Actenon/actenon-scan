# specs/AREF-002 — Resource Effect Inference, corrected architecture freeze

**Status:** AUTHORITATIVE.
**Supersedes:** [specs/AREF-001](../AREF-001/) — retained unmodified as
`SUPERSEDED DESIGN CANDIDATE / NOT AUTHORITATIVE`.
**Frozen against:** `actenon-scan` @ `b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16`.

> **A consequential effect is a claim to be proved, not a sink to be matched.**

This directory is a specification. **No production code, configuration, rule,
test or existing artefact was created or modified.** `actenon_scan/`, `tests/`
and `specs/AREF-001/` are byte-identical to `HEAD`.

## Start here

| Read this | For |
|---|---|
| [AREF-002.md](AREF-002.md) | the architecture itself — pipeline, central domain object, states, verdicts, obligations |
| [REPORT.md](REPORT.md) | the final report, the ten questions, the recommendation |
| [aref_001_delta.md](aref_001_delta.md) | what changed from AREF-001 and why, decision by decision |
| [validation_protocol.md](validation_protocol.md) | the preregistered R05/R06 protocol |

## Normative documents

| File | Contents |
|---|---|
| [AREF-002.md](AREF-002.md) | the architecture freeze |
| [proof_obligations.md](proof_obligations.md) | obligations, proof states, the verdict function, contradiction handling, the counter-evidence probe registry |
| [evidence_acquisition.md](evidence_acquisition.md) | the nine-tier evidence ladder, admissibility, evidence fidelity |
| [dependency_descent.md](dependency_descent.md) | bounded descent, the seven budgets, the frontier, determinism |
| [aref_001_delta.md](aref_001_delta.md) | every AREF-001 decision classified KEEP / MODIFY / REJECT / DEFER |
| [validation_protocol.md](validation_protocol.md) | held-out validation, preregistered before any repository was selected |
| [implementation_plan.md](implementation_plan.md) | fourteen slices, specified and not executed |
| [REPORT.md](REPORT.md) | the final report and the recommendation |

## Machine-readable artefacts

| File | Contents |
|---|---|
| `evidence.schema.json` | evidence and counter-evidence packets |
| `effect_claim.schema.json` | the central domain object |
| `effect_receipt.schema.json` | the eleven-answer receipt |
| `coverage_ledger.schema.json` | the coverage ledger |
| `architecture_manifest.schema.json` | schema for the manifest below |
| `architecture_manifest.json` | vocabularies, obligations, effect classes, ladder, budgets, probes, AREF-001 dispositions, invariants |
| `examples/` | one positive and one negative instance per schema |
| `MANIFEST.json`, `MANIFEST.sha256` | SHA-256 inventory of 26 files |

## Validating

```bash
python3 -m pip install --user jsonschema
python3 specs/AREF-002/validate.py
sha256sum -c specs/AREF-002/MANIFEST.sha256   # run from the repository root
```

`validate.py` checks the schemas, the examples in both directions, agreement
between the manifest and the schema enums, cross-document consistency, and that
`specs/AREF-001/` is still byte-identical.

## What this freeze does not claim

Readiness for implementation is not a claim of real-world effectiveness. The
evidence behind AREF-002 is controlled-corpus only, and the one real-world
measurement available — R04 — found **0 of 17** consequential paths, **13 of 17**
first broken at semantic effect recognition. R05 and R06 exist to falsify this
architecture; the protocol is frozen before any candidate repository has been
selected, inspected or identified. See [REPORT.md](REPORT.md) sections 24 and 29.
