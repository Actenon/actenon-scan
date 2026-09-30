# M1R2: binding identity and callable ownership

Reviewed parent: `7d0e559396089492ba95a4f87007a57d2b5650a0`.

The repeat independent review found six invented-reachability cases despite
the original M1R1 controls passing. This repair changes only the M1 language
adapters. It does not change the graph, traversal, proof kernel, legacy indexes
or Finding output.

A source body, a lexical binding and activation of that body are separate
facts. An exact edge needs one justified binding to an ordinary callable body.
A named function expression has its own internal name, separate from the
variable receiving it. Go type-switch aliases are local declarations. Static
and instance members belong to separate scopes tied to the class declaration,
not just its spelling.

Decorators can replace a Python callable. Retain its original body as a possible
candidate, but do not treat the decorated name as an exact binding. Generator
bodies have their own callable ownership; neither declaring a generator nor
calling it proves resumption. Such calls remain a frontier with their possible
body candidate, invocation and UNKNOWN/ABSTAIN claim intact.
Python coroutine creation also defers execution. A directly awaited call may
follow an exact coroutine binding, including a local import or direct receiver;
an unawaited call or a call merely passed as an argument may not. This records
language execution structure without supplying any M0 effect proof.

Assignments are writes, not declarations. Resolve their lexical destination
after collecting all declarations, so source order cannot manufacture a local
binding or leave an outer binding falsely exact. A write invalidates exactness
of the destination. Where block summarisation makes the destination uncertain,
invalidate the possible outer destinations conservatively as well. This is
binding invalidation, not value propagation or an attempt to infer effects.
Local initializers later than a call cannot establish that call's target;
compare columns as well as lines, including captured enclosing bindings.

Regressions precede production changes. They cover the six fresh counterexamples
under every root kind, variants of each binding form, and valid recursive,
receiver and unmodified outer bindings. Validation then reruns the independent
probes, M1R1/M1/effect suites, legacy and full suites, frozen Finding comparison,
and the pinned R04 development scan. No provider-specific logic or held-out
data is used. M0 and AREF remain frozen.
