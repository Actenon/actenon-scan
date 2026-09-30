# Mechanical future repair contract

No repair is performed by this package. After adoption:

1. EvidencePacket.__post_init__: reject PROBATIVE L6 packets whose version is absent
   or whose version_resolution is absent/UNPINNED. Keep SourceLocator's existing
   package/version/resolution guards and the dependency-body guard. This is a
   representation/admissibility check, not version acquisition or tier precedence.
2. Keep rejection semantics: do not silently rewrite the packet or claim state.
   Legitimate HYPOTHESIS_ONLY retention and independent proofs remain valid.
3. Conformance fixtures/profiles: use the new evidence, claim and receipt profiles;
   keep A/B schemas registered for inherited references and ledger schema unchanged.
4. Conformance oracle: enforce exactly the new L6 predicate before inherited proof
   evaluation. Require the verifier; never skip when missing.
5. Tests first: the reviewed four unpinned OPERATION/PERSISTENCE packets must fail
   on unrepaired M0 and reject after repair. Include all six contract kinds, both
   polarities, registered uncertainty and every existing resolution mode; also
   BOUNDARY's registered L6 facts. Reject missing package/version/resolution and
   invented UNPINNED versions for claims and receipts.
6. Positive controls: pinned equivalents retain their verdicts. Unpinned hypotheses
   retain UNKNOWN/ABSTAIN when sole facts; independent positive/negative proofs
   remain admissible, including FOUND probes reporting only hypotheses.
7. Preserve fresh ERROR/CONFLICTING, opaque genesis, aggregation permutations,
   selected-body precedence, negative closure and B budget A–F controls. Run focused,
   legacy, full feasible and new-profile conformance suites; seal raw observations.

Expected outcome: no new method/provider knowledge; same sink-independent ontology;
no unsupported settling packet solely because an L6 source exists. Implement no M1
acquisition. Do not modify old specifications or rewrite the historical candidate.
