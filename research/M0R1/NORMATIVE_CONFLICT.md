# Frozen budget-provenance conflict — M0R1 readiness blocker

AREF-002A's sealed `examples/valid_unrelated_frontier_negative.json` is registered
as valid NO_EFFECT. Its acquisition says BUDGET_EXHAUSTED without recording an
exhausted budget, and its unopened frontier edge says BUDGET_EXHAUSTED without a
budget_name. The edge could settle OPERATION, whereas the refutation concerns
PERSISTENCE; that irrelevance is not the problem. Negative closure need not fail
solely because an unrelated frontier exists.

Unamended AREF-002 `dependency_descent.md` §4.3 item 3 (line 156) requires the
specific exhausted budget name; §6.1 (line 242) requires a budget name on an
exhausted frontier edge. AREF-002A does not supersede this provenance requirement.
The existing M0 FrontierEntry and Acquisition validations already enforce it;
M0R1 retains them. Thus this frozen example is rejected on budget provenance,
before its otherwise unrelated frontier can be considered.

The AREF-002A validator omits these inherited budget checks. Its normative checks
pass, but that does not resolve the conflict. The runtime conformance test
`test_sealed_amendment_examples[valid_unrelated_frontier_negative]` stays a real
failure. No skip, xfail, fixture rewrite, or weakened runtime check was used.
A versioned normative correction must reconcile the example with the inherited
provenance requirement before M0R1 can be ready. This task makes no such correction.

There is a separate validation-context issue: the amendment's input_preservation
seal pins all failed-M0 source and test bytes. In the repaired checkout the
unchanged validator reports 84/86, failing only historical byte preservation and
inventory preservation. `scripts/validate_aref002a.py` runs that exact validator
against a local archive of a93b013 plus the exact amendment bytes, after checking
that current AREF-001 and AREF-002 bytes are unchanged. It reports 86/86. CI also
requires current-runtime pytest conformance, which fails on the budget example.
The two gates are distinct. Snapshot validation is not a pass for the repaired
runtime, and the direct-checkout failures are preserved in raw output.
