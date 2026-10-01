# M1R4: trusted reachability kernel

The frontend supplies normalized lexical environments, execution regions,
resolution paths, writes and escapes. It cannot choose the sufficient obligation
set or issue a traversal-authoritative proof. The kernel derives obligations from
structural path and invocation/candidate context, checks witness identities, and
issues an immutable, content-bound attestation. Direct/partial proof construction
and modified issued proofs retain their diagnostic facts but cannot authorize
traversal. No legacy resolution projection grants authority.

Every local edge requires TARGET_EXACT, LEXICAL_ENVIRONMENT_EXACT,
EXECUTION_OWNER_EXACT, EVALUATION_EAGER and WRITE_SET_CLOSED. Import and receiver
steps add obligations centrally. Unknown/missing context, witnesses or relevant
closure declines authority. Counter-evidence and duplicate UNKNOWN facts remain
monotonic; candidate uniqueness is enforced independently by the graph.

Lexical environments distinguish syntactic containment, lookup parent and
execution ownership. Python compiler symbol tables provide production evidence
for ordinary blocks. Comprehensions use explicit implicit environments, with the
outer iterable in its containing environment and computation skipping a class
namespace. Compiler mapping or name-classification uncertainty declines lexical
exactness. Inlined class comprehensions on newer Python versions decline lexical
exactness: their compiler mapping is outside this bounded supported subset.
Ordinary module/function comprehensions can use the enclosing compiler table
when the bounded mapping is justified. The kernel independently obtains compiler
name classifications; frontend labels cannot strengthen them. Runtime and compiler
differentials exercise this mapping.

Passing a mutable receiver/namespace/callable object to a callable without a
proved non-mutation frame produces an EscapeEvent. Identity/alias normalization
and escape accounting are independent of resource effects or dangerous names.
The bounded frame model proves only trivial local bodies non-mutating; otherwise
escape opens closure, including for exact local calls. Standard mutation
intrinsic identities may be recognized through exact aliases, but unresolved
callee identity still triggers the escape fallback. No chronology exemptions are
claimed without structural proof; possible writes/escapes are accumulated.
Captured containers, callable closures and prototype identities retain their
mutable destinations. Bounded alias/capture expansion opens closure explicitly
on exhaustion. JavaScript object escape does not itself replace a lexical
variable cell or a function's executable body; member, receiver and import
closure still open, including mutable identities captured by that callable.
Invoking a captured callable exposes its mutable captures without treating an
ordinary function/constructor invocation as an argument escape to itself.
Unmodeled declaration containers retain file-owned UNKNOWN environments; an
empty namespace cannot join observations from unrelated files.

Closure witnesses identify the audited scope, source digest, grammar policy,
lexical environment and execution region. Required SUPPORTED facts without
matching witnesses cannot authorize an edge. The attestation binds subject,
candidate, context, path, facts and witnesses; deleting or replacing structural
material invalidates authority. This is an internal correctness boundary, not a
sandbox against arbitrary Python code that can introspect private implementation.
Witnesses include source and grammar identities and normalized write/escape
and binding ledger hashes. Canonical declarations are sealed before resolution;
the kernel checks nearest lexical lookup, alias hops, import namespaces and
receiver namespaces against that common ledger. Caller candidate lists cannot
hide a shadow, conditional declaration or unresolved alias. The actual binding
kinds add contextual obligations even when caller path/evidence metadata omits
them. The graph also checks the issued proof against the actual
invocation location, execution region and implementation identity. Reusing a
valid proof to redirect a node into another body does not authorize traversal.
The inventory also seals actual invocation sites and coroutine-resumption
observations. A fabricated location or dropping a suspended target's activation
counter cannot obtain authority from another genuine site's inventory.

`BindingEdgeProof.required` remains diagnostic serialization metadata. The kernel
derives it; caller construction, deserialization or modifying it cannot issue
authority. Root registration may identify a unique source callable even when
its body contains a semantic frontier. That identifies the capability root;
recursive call traversal still requires the complete kernel proof. Two older
monotonicity tests now use a genuinely issued proof rather than treating a
manually constructed SUPPORTED record as authoritative.

Legacy Finding behavior, frozen M0/AREF and effect evidence remain unchanged.
All new semantic facts concern possible local reachability only. Unsupported
language semantics are frontiers, not a reason to add further language machinery.
