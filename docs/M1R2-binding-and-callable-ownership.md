# M1R2: evidence-monotonic lexical binding engine

Reviewed failure baseline: `7d0e559396089492ba95a4f87007a57d2b5650a0`.
Architectural repair starts from `1b4edf1c6c982d4afbe9f9c72450770efea956ac`.
The six independent failures are reproduced against the reviewed baseline before
production edits. Earlier syntax controls remain regression tests.

## Three passes

1. **Scope and Binding Construction.** Language adapters construct lexical
   namespaces, parent relations, declarations, receiver identities and writes.
   A name's existence is distinct from its target. A shadow blocks outer lookup
   even if its value is unknown. Writes are applied to the nearest completed
   lexical binding, including possible destinations in summarized block scopes.
   Multiple declarations and conditional imports retain all alternatives.
2. **Callable Execution Ownership.** Enumerate invocation syntax using the
   constructed scopes and body boundaries. Lexical scope and execution owner are
   separate fields. Every callable syntax form owns its body. Class definition
   expressions execute in their defining body; deferred initializers, generators
   and coroutines require independent execution evidence. Outer call collection
   never adopts the contents of an uncalled nested callable.
3. **Binding Claim Resolution.** Follow bounded declaration, import, receiver,
   self-name and exact alias provenance. Produce one BindingClaim per candidate
   with positive and counter-evidence. Repository same-name lookup supplies only
   possible candidates, never binding proof. Sorting is presentation only.

## Claim authority

A BindingClaim identifies its invocation subject and implementation candidate.
Its state is ESTABLISHED, POSSIBLE, REFUTED or UNKNOWN. ESTABLISHED requires one
structurally justified stable target and no unresolved binding step. Evidence is
accumulated as sets; counter-evidence cannot be erased by a later positive fact.
Ambiguity, conditional provenance, writes, unknown decorators, unresolved aliases
and incompatible receivers prevent establishment. Concrete incompatible receiver
or lexical exclusion can refute a candidate without deleting the invocation.

The graph follows only an ESTABLISHED local claim. ResolutionCertainty is a
compatibility projection and cannot authorize traversal independently. Every
other call remains a frontier and generates the same frozen M0 UNKNOWN/ABSTAIN
obligation; parser/resolver failures remain analysis errors. Binding evidence is
not effect evidence and supplies no new M0 predicates or semantic support.

Named function expressions have an inner self-binding. Python decorators rebind
names to unknown outputs. TypeScript instance and static namespaces are distinct.
Go type-switch aliases are declarations. Exact aliases are limited to simple
lexical identifiers whose complete provenance and stability can be established;
computed values and richer semantics stay POSSIBLE/UNKNOWN. The model deliberately
summarizes some block scopes conservatively rather than building a type checker.
Go literal values retain their body candidates but do not yet establish value
dispatch. Simple stable aliases to package functions can establish a target.

Python global/nonlocal writes resolve against completed lexical namespaces,
including intervening empty scopes. Stores through receiver/module aliases
invalidate the possible namespaces before resolution. Unknown object stores
conservatively destabilize matching local member namespaces, including mutable
Python modules. This can reduce resolution; it cannot create a binding proof.
Counters for candidate edges are distinct from invocation counts: a single call
can have several POSSIBLE/REFUTED candidates and an UNKNOWN frontier. Analysis
errors have no binding authority and remain separate error accounting.

## Validation

Tests precede implementation: six reviewed failures, original controls, seven
metamorphic invariants and a generated supported-combination matrix. Validation
includes 216 generated binding/receiver combinations, including conservative
Go value frontiers. Additional declaration controls cover Go select bindings,
named results and const specifications, and TypeScript value/type declarations
and separate namespace scopes. Type-only declarations may conservatively block
value resolution when this model does not distinguish their namespaces. Validation
also covers all root kinds, sink-free genesis, bounds, errors, deterministic
identity, effects, legacy Finding serialization, the full suite and pinned R04.
M0, AREF, legacy scanner behavior, M2 and held-out R05/R06/R07 remain untouched.
