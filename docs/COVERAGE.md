# Coverage — what scan verifies, and what it structurally cannot

Scan is a static analyser. This document states precisely where its guarantees
end. It exists because the most valuable thing a security tool can publish is
the boundary of its own competence: a scanner that implies more coverage than
it has converts a real risk into a false sense of safety, which is worse than
no scanner at all.

Everything below is pinned by tests. The benchmark
(`python scripts/benchmark.py`) reports three numbers, and the cases behind
them live in `tests/benchmark/{recall,precision,soundness}/`.

---

---

## The coverage contract

Each agent architecture is a row. **A row may claim COVERED only when a
hand-triaged true positive exists on a pinned commit of a real repository**,
recorded in [`tests/benchmark/corpus-evidence.json`](../tests/benchmark/corpus-evidence.json).
A synthetic fixture is not sufficient: it proves the detector fires on code we
wrote, which is not evidence that it fires on code anyone else wrote.

`scripts/check_coverage_contract.py` enforces this table in CI. It fails if a
row claims COVERED without matching triaged evidence, if a non-COVERED row
cites evidence, if the COVERED count disagrees with `baseline.recall_corpus`,
or if a recall fixture has no row here.

| ID | Architecture | Status | Corpus evidence |
|---|---|---|---|
| `r01` | MCP tool decorator — `@mcp.tool` | COVERED | `r01_mcp_tool` |
| `r02` | MCP request handler — TS `setRequestHandler` | COVERED | `r02_langchain_tool` |
| `r03` | Tool base class — `BaseTool` subclass `_run`/`_execute` | COVERED | `r03_basetool` |
| `r04` | Function-tool decorator — `@function_tool` | PARTIAL | - |
| `r05` | Custom agent loop — LLM output flows to a sink | NOT COVERED | - |
| `r06` | Action/observation dispatcher — `run_action` | NOT COVERED | - |
| `r07` | Raw tool-schema dispatch — switch on tool name | PARTIAL | - |
| `r08` | SMTP `send_message` — `smtplib.SMTP(...).send_message(...)` | PARTIAL | - |

**COVERED (3)** — detector fires, and it has been shown to fire on real code
that a third party wrote.

**PARTIAL (2)** — the detector exists and fires on its synthetic fixture, but
no corpus true positive has been produced yet. `r04` fires on
`r04_openai_function_tool.py`; the only corpus candidate found so far
(openai-agents `streamablehttp_example/main.py:91`) was triaged a **false**
positive and fixed by the `__main__` exclusion, so the architecture stays
PARTIAL rather than being credited. `r07` produces zero candidates across
21,308 corpus files at zero precision cost.

**NOT COVERED (2)** — recorded negative results, detail below. These are
listed rather than omitted because a missing row reads as "not applicable"
when the truth is "tried, and it did not work".

### Minimal examples

```python
# r01 — COVERED
@mcp.tool()
def run(cmd: str):
    subprocess.run(cmd, shell=True)      # flagged

# r03 — COVERED
class DeleteFileTool(BaseTool):
    def _execute(self, path: str):
        os.remove(path)                  # flagged

# r04 — PARTIAL (fires on fixture, no corpus TP yet)
@function_tool
def run(cmd: str):
    subprocess.run(cmd, shell=True)      # flagged

# r05 — NOT COVERED: indistinguishable from framework plumbing
class Loop:
    def chat(self, msg): return self.run(self.llm(msg))
    def run(self, cmd): subprocess.run(cmd, shell=True)   # NOT flagged
```

```typescript
// r02 — COVERED
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  await fs.writeFile(req.params.path, req.params.content);  // flagged
});
```


## What scan verifies

For a consequential sink reachable from an agent tool boundary, scan answers
three questions about the guard that precedes it.

### 1. Does a guard exist?

Lexical match against 145 guard patterns covering Actenon, OAuth, JWT, OPA,
Casbin, Cedar, MCP-native elicitation, LangChain human-in-the-loop, and common
naming conventions. Vendor-neutral by construction: a codebase with its own
guard vocabulary configures it and gets a clean scan.

### 2. Does the guard dominate the sink?

A guard only protects a sink if it lies on **every** path to it. Scan walks the
guard's ancestors and rejects it when the guard sits in a branch the sink does
not share:

| Defeated pattern | Benchmark case |
|---|---|
| `if False:` around the guard | `s01_if_false.py` |
| `if cfg.enforce:` — guard behind a config flag | `s03_cfg_enforce.py` |
| guard only in an `except` handler | `s04_except_guard.py` |
| guard placed *after* the sink | `s05_guard_after.py` |
| guard inside a nested function or lambda | — |

Dominance is the check that catches guards which exist, read correctly in
review, and never run.

### 3. Is the guard's result actually enforced?

A guard that returns a decision which is then discarded enforces nothing
(`s06_result_discarded.py`). Scan distinguishes:

- **assert-style** guards (`authorize`, `require_*`, `enforce_*`, `verify_pccb`,
  `ctx.elicit`, …) — conventionally raise on failure, so a discarded return
  value is normal and correct;
- **predicate-style** guards (`check_permission`, `has_role`, …) — return a
  value that must be branched on. Discarding it is a `-WEAK` finding.

---

## What scan cannot verify

### The central limitation: parameter binding

Scan can tell you a guard exists and dominates. It **cannot** tell you the
guard authorizes *this* action on *these* parameters.

The obstacle is not implementation effort. It is that the correct idioms and
the defeated ones are syntactically identical. Consider four call sites, all
guarding `stripe.Refund.create(payment_intent=pi)`:

```python
authorize("refund")                              # correct — authorize by action name
casbin_enforce("user", "record", "delete")       # correct — Casbin subject/object/action
verify_pccb(proof, intent, action)               # correct — Actenon's own PCCB pattern
authorize(other_payment_intent)                  # DEFEATED — authorizes the wrong object
```

Not one of them shares an identifier with the sink. A binding rule strict
enough to flag the fourth flags the first three, and the first three are how
real authorization code is written. Scan therefore exempts assert-style guards
from binding intersection, and the fourth case goes undetected. This is pinned
as a known limitation in `tests/test_counterfeit_binding.py`.

Two narrower things scan *does* catch:

- **Predicate-style guards** are still binding-checked. A `check_permission`
  that inspects one variable while the sink acts on another is `-UNBOUND`.
- **Counterfeit binding** — a guard passing variables that *appear* to carry
  runtime data, where every one of them provably resolves to a compile-time
  constant (`attacker = "evil_intent"; authorize(attacker)`). This is
  soundness case `s02_unbound.py`. It is separable precisely because the
  legitimate idioms above either pass no variables at all, or pass real
  function parameters.

The rule is deliberately conservative: an argument scan cannot resolve — an
attribute, a call result, a global, a loop variable — is treated as genuine
data-dependence and the guard passes. A false `-UNBOUND` on a correct guard
costs more than a missed one.

### Why Actenon's own guard pattern is the clearest example

This limitation surfaced from an unexpected direction, and it is worth stating
plainly rather than burying.

Actenon's thesis is that authorization must be **bound to the exact action and
its parameters** — that upstream approval of "a refund" is not approval of
*this* refund for *this* amount to *this* account. That is the execution gap.

Actenon's own recommended guard is:

```python
verify_pccb(proof, intent, action)
stripe.Refund.create(amount=amount)
```

The binding this pattern asserts is real. It is *cryptographic*: the proof
commits to the action, the target, and the parameter values, and the kernel
rejects it if any of them differ at execution time. But that commitment lives
**inside the proof object**. At the call site there is nothing to read — three
opaque variables, and a sink that shares none of them. A static analyser
looking at this code sees exactly what it sees in the defeated case.

So: **scan cannot verify the property Actenon's thesis is built on, in
Actenon's own idiom.**

That is not a defect in scan, and it does not weaken the thesis. It sharpens
it. The binding is cryptographic, and cryptography is a runtime property —
you verify a signature by checking it, not by reading the code that checks it.
Static analysis can establish that a guard *exists* and that it *runs on every
path*; it cannot establish that the guard is *bound*. The gap between those two
is not a gap in tooling maturity. It is the gap the runtime kernel exists to
close.

The honest framing, which belongs in any argument about scan's scope:

> Static analysis can prove a guard is present and unavoidable. It cannot
> prove the guard is bound to the action it precedes. That binding is
> cryptographic, and it can only be checked at the moment of execution.

Scan is the reconnaissance instrument: it finds every place a consequential
action is reachable and tells you whether *anything* stands in front of it.
Deciding whether that thing is bound to the action is the kernel's job. The
two tools answer different questions, and the reason they must both exist is
visible in this limitation rather than in spite of it.

---

## Other coverage boundaries

### Agent-boundary recall

Scan recognises MCP tool decorators, LangChain `@tool` and `BaseTool`
subclasses, OpenAI `@function_tool`, and CrewAI tool patterns. Architectures
that do not announce themselves through a decorator or base class are missed
today — custom agent loops, action/observation dispatchers, raw tool-schema
switches. These are recorded as failing recall cases (`r05`–`r07`) rather than
quietly omitted; the benchmark reports 4/7 for exactly this reason.

### Interprocedural flow

Analysis is per-function. A guard in a caller does not protect a sink in a
callee, and scan will report the callee's sink as unguarded. This produces
false positives on codebases that centralise authorization at a dispatch layer.

### Dynamic dispatch

`getattr(obj, name)()`, registry lookups, and plugin systems are invisible.

### Language support

Python and TypeScript/JavaScript. Files in other languages are reported as
**unsupported**, never counted as clean — silence must never imply safety.

---

## Reading the benchmark honestly

The scores are not interchangeable, and only some of them are hard gates.

- **Precision (11/11)** must stay at 100%. A precision regression fails the
  build. False positives are how a security tool gets uninstalled.
- **Soundness (6/6)** counts defeated-guard patterns that scan correctly
  refuses to accept.
- **Recall (synthetic) (4/7)** counts agent architectures scan can see on
  fixture files. Informational only — a number that moves on synthetic
  fixtures without a corresponding real-world true positive encodes
  capability that does not exist.
- **Recall (corpus-demonstrated) (3/7)** counts architectures with a
  hand-triaged true positive on a pinned commit of a real repository.
  This is the number that gates CI. It ratchets: it may not decrease.

One discipline matters more than the numbers: **the fixtures are the
specification.** A benchmark case may be changed when it was wrong about the
world, never to match what the code happens to do. `s02_unbound.py` was once
rewritten from `authorize(attacker)` into an all-literal guard call so a
candidate rule would pass it. The score read 6/6 and the original defect was
still undetected — and the rule that "passed" it also flagged
`casbin_enforce("user", "record", "delete")`, a correct Casbin call, as
unbound. A benchmark edited to fit the implementation measures nothing.

## Closed: the guard false-negative class (v0.7.0)

Recorded because the *reason* it was wrong outlives the fix.

Guard style used to be inferred from the guard's **name**. Names in a fixed
assert-style list (`authorize`, `require_*`, `enforce_*`, …) were assumed to
raise on failure, so discarding their return value was fine. Everything else
was predicate-style and had to be branched on.

Name-based classification cannot work, because the same name is written both
ways in real code:

```python
def check_permission(user, action):     # boolean-style
    return user.role in ALLOWED         # discarding this enforces NOTHING

def check_permission(user, action):     # assert-style
    if user.role not in ALLOWED:
        raise PermissionError           # discarding this is correct
```

`check_permission` was on the assert-style list, so the first form — a real
defect — was reported clean. That is a false negative in the one place a
security tool must not have one: a guard that runs, returns "no", and is
ignored.

v0.7.0 resolves guards **by definition** instead. When the guard is defined in
the scanned module its AST decides: contains a `raise` → assert-style; returns
a value and never raises → boolean-style, so a discarded result is `-WEAK`;
both → assert-style, because the raise dominates.

When the guard is imported and cannot be resolved, a deliberately **narrow**
name heuristic applies. `check_permission`, `check_access`, `check_auth` and
`verify_token` are excluded from it: they are ambiguous names that could
return a bool. Per the operating rule that **ambiguity resolves to WEAK, never
to clean**, an unresolvable ambiguous guard is reported WEAK rather than
assumed safe.

All six cases now behave correctly, including the imported-and-unresolvable
one. The general lesson is the transferable part: **a guard's contract is a
property of its body, not of its name**, and where the body cannot be seen the
safe default is to doubt it.

## Negative result: custom agent loop detection (r05)

The custom agent loop strategy (2.1) was rejected after detection-only
pre-triage on a 9-repo corpus. It produced 10/10 false positives across
autogen wsbridge, agno A2A, semantic-kernel process routing, and OpenHands
integrations. The dominant category was framework message-passing plumbing —
`send_message` on internal event buses — which the heuristic matched because
the signal decomposes into "module talks to an LLM" and "function runs what
it was passed", which describes most of an agent framework.

This is a useful negative result. The custom agent loop pattern is too broad
to distinguish from framework internals without interprocedural dataflow
analysis. The strategy is recorded as not-yet-viable rather than abandoned;
a future version with interprocedural analysis may revisit it.

## r06: action/observation classes (OpenHands)

The r06 fixture models OpenHands' `CmdRunAction` shape: a dataclass with
command/code/path fields consumed by a dispatcher method (`run_action`,
`execute_action`). OpenHands has restructured away from this shape in its
current main branch. The fixture is marked **historical** — it tests a
pattern that was common in agent frameworks and may reappear. It is excluded
from the synthetic recall denominator (7 → 6 effective) because the pattern
no longer exists in the primary reference implementation. The detector code
remains active and may fire on codebases that use the action/observation
pattern.

## r07: raw tool-schema dispatch

The r07 detector (raw tool-schema dispatch) is active but produces zero
candidates on the 7,354-file corpus. It costs exactly zero precision. It
remains in the codebase because a codebase not in the corpus may use the
pattern. It simply does not count toward corpus-demonstrated recall until it
produces a hand-triaged true positive.
