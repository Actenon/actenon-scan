# M1R1: conservative invocation bindings

Parent candidate: `cb02ba862c7014ec2c673dcc61e9188f7b5004ad`.

The graph, claim model and traversal stay unchanged. The repair is confined to
M1's adapters; legacy indexes remain available to legacy Finding consumers.

A lexical scope records each name that it binds and the provenance of every
binding. Parameters, stores, declarations, patterns and imports all count as
name existence. Lookup stops at the nearest scope containing the name: an
unknown local value shadows a known module function. Block constructs may be
summarized conservatively within their callable scope; this may lose precision,
but must never manufacture a global binding through a local declaration.

Bindings distinguish callable declarations, scoped imports, structurally
established receivers and unknown values. Callable declarations identify their
own source symbol. Imports retain their lexical scope and source reference;
conditional imports remain alternatives. A name with several bindings, a
conditional binding, rebinding, or a dynamic value is ambiguous/unresolved.
Possible local candidates are retained together with an unknown alternative;
no ambiguous edge is traversed. Exact local declaration/import lookup is
separate from repository-wide name candidates.

`RESOLVED` requires exactly one structurally justified target and no unresolved
binding alternative. The legacy index's flattened Python import dictionary is
not evidence of this condition. Python import targets are looked up using the
recorded import reference and the target module's lexical bindings, rather than
the index's last same-name import. Unsupported export/rebinding forms abstain
from exact resolution. Resolver exceptions and the 32-step local import resolution limit retain
the existing analysis-error path. Cyclic aliases stay unresolved.

Direct receiver lookup requires a two-component member access and a receiver
binding tied to the enclosing class/method. Python's first positional method
parameter qualifies only in a real class method, excluding static/class method
forms; an ordinary parameter named `self` does not. TypeScript's instance
`this` is tied to a non-static method and inherited only by lexical arrows.
Go uses its explicit method receiver declaration. Receiver stores/shadowing
invalidate exactness. Longer chains such as `self.client.helper()` retain an
unresolved invocation and claim without descending into `Class.helper`.

Every unresolved/ambiguous call remains enumerated, root-reached and claimed.
All frozen proof obligations remain UNKNOWN. No effect knowledge, provider
logic, sink catalogue, M0/spec changes or dependency descent is introduced.

Validation starts with the nine independent-review failures, then exercises
binding forms and direct-receiver/local-call positives, the original M1 and
frozen effect suites, legacy/full tests, the 263-input frozen Finding comparison
plus repository scans, and R04 before/after graph accounting.

Unsupported TypeScript default/re-export forms and unknown function values stay
unresolved. Relative named imports use the importer directory and require a
local named export declaration. Python lambdas, like methods, skip the class
namespace when looking up free names.
