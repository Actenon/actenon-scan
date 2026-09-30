# AREF-002B — Budget-provenance adjudication

This is a single-issue delta to AREF-002 as amended by AREF-002A. It preserves all
three historical packages and the M0R1 checkpoint. It neither authorizes merge
nor starts M1. Read [AMENDMENT.md](AMENDMENT.md), [budget_provenance.md](budget_provenance.md),
[m0r1_delta.md](m0r1_delta.md) and [REPORT.md](REPORT.md).

The missing budget identities are a concrete fixture defect. Repairing those
identities alone leaves a normative representation gap: AREF-002A accepts a
bare unrelated-frontier label plus C4=true while deferring its provenance.
This package reconciles that gap with the requested evidence requirement.
Budget identity remains mandatory. Only NO_EFFECT with recorded exhaustion
acquires a supplied exclusion-witness requirement. No other proof semantics change.

The claim and receipt schemas are budget-only profiles of the inherited 0.1.1
wire records with distinct AREF-002B schema IDs. They add one optional acquisition
field, `budget_provenance`, conditionally required for exhausted NO_EFFECT. The
old version number does not imply that an old record passed the new profile.
The evidence schema, assertion registry, effect classes and ledger schema remain
unchanged. The receipt profile only redirects inherited claim-schema references.

Examples remain authored normative records, not source programs or empirical
validation. The chosen budget name is an authored premise, not a reconstruction
of missing historical evidence. A supplied witness is not automatically true.

Run from the repository root, with the unchanged AREF-002A validation dependencies:

```sh
python -B specs/AREF-002B/validate.py
shasum -a 256 -c specs/AREF-002B/MANIFEST.sha256
```

The validator requires jsonschema/referencing, resolves schemas locally, exercises
Cases A–F and verifies the upstream and local seals. It reuses unchanged AREF-002A
proof-record checks; it performs no source acquisition. It also reports the exact
M0R1 rejection and bare-label acceptance pressure point. M0R1 cannot yet read the
new witness field; the bounded mechanical delta is documented, not implemented.
