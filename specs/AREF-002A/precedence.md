# Selected-implementation precedence

Evidence tier alone MUST NEVER resolve a contradiction. Neither package provenance
nor a string naming a body establishes that this body executes. Retain both sides
as CONFLICTING unless **all** the following are established and recorded:

1. Selection is SINGLE_ESTABLISHED and the candidate is RESOLVED_LOCAL or
   RESOLVED_DEPENDENCY_SOURCE, with a body locator.
2. A PROBATIVE `implementation_is` packet has a SELECTED_TARGET binding from this
   invocation to exactly that candidate body. The packet is the selection witness.
3. Winning evidence is from that body, or a recorded chain of resolved body calls
   beginning there. It addresses the same candidate and obligation as the loser.
4. Losing evidence is machine-readable contract/declaration evidence describing
   that same proposition, represented by the registered L6 contract kinds.
5. The contradiction record retains all positive, negative and overridden packet
   IDs plus the provenance of this precedence relationship.

Here the proposition is the named obligation of this candidate at this claim's
invocation, effect class and recorded conditions. A packet about another operation,
candidate or conditional context cannot be reassigned to that proposition by
editing a locator. M0 checks the structured identity links; the acquisition
producer remains responsible for the truthful semantic association.

The contradiction's `precedence` object contains `selection_packet_id` and
`winning_paths`. Each winning path names one `packet_id` and an ordered
`binding_packet_ids` list. That list may be empty only for evidence directly
within the selected body. Each nonempty step must be a PROBATIVE RESOLVED_CALL
binding for this invocation and candidate, starting at the previous body locator.
The last body contains the winning packet's source span.

Containment requires the same path, package, version and version-resolution
identity, with an enclosing line/column span. A matching line range in another
source identity is insufficient. The referenced selection and call-edge packets
carry their own ordinary locator and verbatim-extract provenance. A chain of
locator strings without those independent binding packets fails validation.

This profile resolves one entire opposing side, retaining the other as winners.
Every winning packet requires a body path; every overridden packet must be a
registered contract packet. Mixed unresolved opposition cannot be suppressed by
cherry-picking one favorable packet. No precedence applies to AGREEMENT_INVARIANT,
UNRESOLVED_IDENTITY, UNRESOLVED_DIVERGENT or SELECTION_ERROR. The rule is symmetric:
a selected body can establish mutation or observation against a contrary contract.

Before precedence, the contradiction must contain exactly the complete positive
and negative fact sets for that candidate/obligation. After precedence, both sets
and the resolution remain in claims and receipts. Unknown commit outcome may
still prevent proof; it never erases the recorded contradiction.

## M0 assurance boundary

M0 validates structured provenance and reference consistency. It does not acquire
bindings, re-read source extracts, prove the truth of a supplied call edge or run
the program. Later evidence acquisition and fidelity checks must substantiate
these declared witnesses. The authored examples test this representation and
admissibility rule only. They do not turn a locator or an assertion supplied by
an untrusted producer into independently verified source truth.
