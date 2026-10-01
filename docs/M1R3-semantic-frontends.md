# M1R3: proof-carrying semantic frontends

The parent reproduces all 52 third-review false-reachability regressions. The
binding state machine is retained, but a declaration is no longer sufficient
authority to traverse a body. Parsing lowers into execution regions, normalized
write events, and completeness certificates before resolution.

An invocation has separate lexical scope and execution region. A callable body
owns its calls; deferred generator computations have synthetic owners; annotation
semantics that are not established are excluded from eager runtime evaluation.
Defaults, decorators and eager class definitions remain with their executing
owner. The bounded model deliberately declines dynamic activation and historical
annotation evaluation rather than proving it from spelling.

Every binding path accumulates a certificate. TARGET_EXACT, EXECUTION_OWNER_EXACT,
EVALUATION_EAGER and WRITE_SET_CLOSED are required on every local edge. Receiver
and import obligations are additionally required where their provenance is used.
One unique candidate with supported required obligations and no counter-evidence
can be ESTABLISHED. An absent certificate is UNKNOWN, including for manually
constructed graph edges. Counter-facts and unknown closure facts accumulate;
merging evidence cannot erase them.

Writes are lowered with recursive target walkers, including nested destructuring,
deletion, computed members, Go range/receive forms, and short declarations. The
common write consumer resolves lexical destinations and receiver/module aliases;
it never reparses targets. Unknown targets/grammar conservatively open the relevant
scope/namespace certificate. Candidate declarations and possible implementations
are retained; uncertainty never licenses descent or effect semantics.

The grammar inventory records the installed parser families and classifications.
Unlisted named nodes default to CONSERVATIVELY_UNKNOWN, with a visible coverage
gap. This is a bounded syntactic certificate, not a whole-language, runtime, or
dependency proof. Dynamic reflection and unresolved write destinations are outside its
closure and downgrade exactness. Precision controls and runtime differential
fixtures accompany that boundary. Legacy Finding analysis and M0 remain isolated.

Python global/nonlocal redirects and Go nested-block short declarations retain
their conservative candidate/write accounting but decline a complete scope
certificate. Metadata with uncertain annotation evaluation, defer activation,
and unclassified grammar also disclose explicit limitations. Unsupported semantics
cannot become an empty write set. Stable functions, imports, methods, literal
destructuring and Go local function values have positive proof controls.

Receiver closure excludes unproved inheritance, metaclass and custom attribute
lookup. Such constructs may introduce competing implementations; the bounded
model does not establish a receiver hierarchy or descriptor identity. These
limitations propagate to receiver proofs rather than preserving exactness from
an original method declaration.
