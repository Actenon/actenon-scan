# AREF-002C — Contract version-provenance adjudication

Status: validated proposal for a single-issue normative amendment. It is outside
the candidate checkout and has not been adopted, committed or used to repair M0.
Date: 2026-09-30. Candidate: c3e044218ba246cbbcb73746f3f8bd0064cc8b52.

This resolves only the recorded-version requirement for PROBATIVE L6 formal
contract evidence. AREF-001/002/002A/002B, the candidate and the prior review are
immutable inputs. B remains authoritative for budgets; A for its other amendments.
No effect class, obligation, proof state, verdict, acquisition tier or provider rule
changes. Source-truth verification and acquisition remain outside M0.

The package contains a precise adjudication, additive schema profiles, normative
examples, an independent compatibility validator and a mechanical repair contract.
Run `python -B validate.py --upstream /absolute/path/to/candidate` with the existing
mandatory jsonschema/referencing verifier environment. The validator fails if that
verifier is absent. Validation does not make the production candidate ready.

Do not silently edit earlier sealed packages. Adoption is a separate authorized
step; production repair must then be tested against this exact decision.
