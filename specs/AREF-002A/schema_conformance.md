# Mandatory schema conformance

The architecture-conformance job MUST install and require
[requirements-validation.txt](requirements-validation.txt), then run
`python -B specs/AREF-002A/validate.py` from the repository root. A missing
`jsonschema` or `referencing` verifier is a gate failure. It MUST NOT become a
skipped test, warning-only check, or CI success. No fallback to shape-free checks
is allowed. Runtime production may remain free of these dependencies.

The amended schemas use JSON Schema Draft 2020-12 with IDs under
`https://actenon.dev/schema/aref-002a/`, version `0.1.1`. Those URLs are identifiers;
the validator resolves them through a local registry, without network retrieval.
`additionalProperties=false` is preserved on proof objects.

| Schema | Normative amendment |
|---|---|
| `evidence.schema.json` | Typed assertion/source compatibility; explicit binding witnesses; unknown hypotheses permitted without probative authority |
| `effect_claim.schema.json` | Declared conditional closure; UNRESOLVED_IDENTITY; recorded precedence provenance |
| `effect_receipt.schema.json` | Required validated claim snapshot and consistent conditional closure |
| `coverage_ledger.schema.json` | Versioned references and clarified analysis-error counting; necessary arithmetic is semantic validation |

These four complete replacement schemas supersede their corresponding AREF-002
schemas for amended records. The original files and IDs remain unchanged.
`amendment_contract.json` overrides only the amended vocabulary in the old
architecture manifest; all other inherited vocabularies, probe definitions and
budgets remain frozen. Version `0.1.0` records must not be silently loaded as
amended-conformant records. Future migration must validate, retain uncertainties
and reject missing provenance rather than invent it.

## Required layers of the gate

1. Validate all four schemas themselves.
2. Validate the registry's exact encoding in the evidence schema and amended
   vocabulary agreement.
3. Accept positive examples for each verdict, including NO_EFFECT with closure
   and the all-UNKNOWN opaque singleton with no sink matches.
4. Reject each adversarial example for its registered intended reason. A different
   unrelated failure does not count as a pass.
5. Run the semantic proof-record checks as well as schema shape checks.
6. Verify dependency absence actually exits nonzero, and verify the sealed inventory.

`validate.py` exits 0 only on success; 1 on failed conformance assertions; 2 on
missing verifier or invalid conformance infrastructure. Its `-S` subprocess
simulates unavailable site-packages and must report the required fatal exit.
The authoring-only `--no-seal` switch is explicitly forbidden in CI. The CI job
must not run `build_examples.py`, regenerate expected answers, or rewrite a manifest.

The implementation repair MUST replace optional/import-skipping architecture
checks with a required dependency and failing import. This task specifies that
job; it does not edit CI, production dependency declarations or existing tests.

## The original NO_EFFECT contradiction

The frozen claim schema conditionally requires `closure`, but never declares it
in top-level `properties` while declaring `additionalProperties=false`. Omitting
closure violates the conditional requirement; supplying it violates the top-level
restriction. This is an actual normative schema defect, not an implementation
interpretation. AREF-002A declares the property and tests both branches. Historical
AREF-002 remains intact; its defective schema must not be the authority for repaired
M0 serialization. Preserving the defect as a historical note would not be enough.
