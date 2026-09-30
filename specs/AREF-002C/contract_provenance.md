# Admissibility without a blanket veto

The rule applies to all six L6 formal-contract kinds admitted by A's registry:
openapi_operation, protobuf_service_method, graphql_schema_field, json_schema_node,
sdk_operation_metadata and command_specification. These are generic acquisition
formats, not provider identities or method-verb detection rules. It applies to
positive and negative facts and to registered uncertainty alike, not just OPERATION
or PERSISTENCE. The existing registry is unchanged; L6 cannot establish an assertion
outside its exact registered tuple.

LOCKFILE, EXACT_MANIFEST_PIN and INSTALLED_TREE_METADATA are existing ways to
record an established version. This is not a new requirement for a lockfile alone.
Missing version/resolution/package is invalid for a falsely probative L6 packet.
UNPINNED with an invented version remains invalid even for a hypothesis.

When a producer cannot establish version provenance, it may emit the retained
packet HYPOTHESIS_ONLY. Recompute candidate states using admissible facts, then
aggregate and evaluate verdict/closure using the unchanged kernel rules:

| Situation | Consequence |
|---|---|
| Sole necessary positive contract fact is unpinned | It cannot support the obligation; normally UNKNOWN/ABSTAIN |
| Sole refutation is unpinned | It cannot refute the obligation or establish NO_EFFECT |
| Independent probative body establishes every obligation | An unpinned hypothesis does not veto PROVEN_EFFECT |
| Another obligation has independently closed all-candidate refutation | An unknown obligation from unpinned material need not prevent NO_EFFECT; C1–C6 still apply |
| Opposing pinned probative facts remain | CONFLICTING survives; version policy is not contradiction resolution |
| Necessary analysis ERROR exists | ANALYSIS_ERROR survives unchanged |
| Falsely probative unpinned packet is supplied | Reject malformed proof record; do not guess its replacement state |

For illustration, UNKNOWN OPERATION may coexist with a legitimate PERSISTENCE
refutation and valid NO_EFFECT closure. Requiring every obligation SUPPORTED for
a positive is not the rule for a negative. A blanket 'unpinned anywhere -> ABSTAIN'
would weaken valid proofs and is expressly not authorized.

Receipts must apply the same profile to their snapshot and packet projections,
then perform inherited self-consistency checks. There is no cryptographic assurance
or ability to discover a producer deleting facts. Budget exclusions, C4 representation,
candidate identity preservation, selection and precedence remain unchanged.
