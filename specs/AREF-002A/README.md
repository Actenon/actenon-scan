# AREF-002A — Normative amendment to AREF-002

**Status: normative amendment, ready for M0 repair.** This is a bounded amendment,
not a new architecture. It adjudicates H1–H6 and M1–M5 from the adversarial review
of M0 commit `a93b013383ce773b10708d3f30b2a1660e141527`. That implementation remains
**M0 FAIL — ARCHITECTURE VIOLATION**. Readiness here does not authorize its merge.

> A consequential effect is a claim to be proved, not a sink to be matched.

AREF-002 is immutable historical evidence. Read it **as amended here**; its
unaffected requirements remain in force. AREF-001 remains historical wherever
AREF-002 superseded it. No production implementation or existing test was changed.

Start with [AMENDMENT.md](AMENDMENT.md), then the mechanical
[M0 repair contract](m0_repair_contract.md). [REPORT.md](REPORT.md) records the
adjudication, results, limitations and twelve requested answers.

| Normative file | Responsibility |
|---|---|
| [aggregation.md](aggregation.md) | Exception-preserving candidate aggregation |
| [selection.md](selection.md) | Opaque genesis and selection transitions |
| [assertion_compatibility.md](assertion_compatibility.md) | Typed, directional admissibility |
| [precedence.md](precedence.md) | Selected-body provenance, not tier preference |
| [closure_and_receipts.md](closure_and_receipts.md) | C1–C6, uncertainty and receipt consistency |
| [ledger_consistency.md](ledger_consistency.md) | Sound bounds on aggregate populations |
| [probe_semantics.md](probe_semantics.md) | Completion versus evidence meaning |
| [schema_conformance.md](schema_conformance.md) | Required verifier and versioned schemas |
| [validation.md](validation.md) | Executable conformance coverage and limits |

The four `*.schema.json` files replace the affected AREF-002 wire schemas for
version `0.1.1`. `assertion_registry.json` freezes the admitted typed combinations;
`amendment_contract.json` records the unchanged ontology and amended selection
vocabulary. `validate.py` checks proof records; it is not an inference engine.
Examples are authored normative records, not source programs or experimental
evidence. `build_examples.py` is an authoring helper, not part of CI execution.

From the repository root, in a validation environment:

```sh
python -m pip install -r specs/AREF-002A/requirements-validation.txt
python -B specs/AREF-002A/validate.py
shasum -a 256 -c specs/AREF-002A/MANIFEST.sha256
```

Missing schema-verifier dependencies are fatal. `--no-seal` is authoring-only and
MUST NOT be used as a conformance gate. Do not regenerate fixtures or manifests
to obtain a passing gate after a normative release.

M0 repairs and later milestones remain separate tasks. No provider signature,
held-out repository inspection, real-world validation or effect acquisition is
part of this amendment.
