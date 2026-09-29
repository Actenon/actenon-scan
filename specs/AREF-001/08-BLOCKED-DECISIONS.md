# AREF-001 §8 — Blocked decisions

Six decisions cannot be taken without the REI evidence identified in
[01-EVIDENCE-AVAILABILITY.md](01-EVIDENCE-AVAILABILITY.md). They are listed
here, unresolved, rather than guessed.

Each entry states: the decision, why it cannot be taken now, the candidate
options with what each costs, the specific measurement that would close it, and
**what breaks if it is taken anyway**. The last column is the point of the
section — a blocked decision that is harmless to guess wrong is not blocking.

---

## B-01 — Does `scope: all` escalate severity?

**Blocked because** escalation changes exit codes and therefore breaks builds.
The only defensible basis is a measured false-positive rate for the scope
inference, and no such measurement is accessible.

| Option | Cost if wrong |
|---|---|
| Never escalate (frozen as the **v0 default**, D-09) | Real unbounded-blast-radius sites stay at their base severity. A recall-shaped loss, invisible to the user |
| Escalate `all` + `model_controlled` to HIGH | Every false `all` becomes a failed build. The repository's precision gate is 100% and a drop fails CI; a wrongly-escalated finding is the most expensive single error the tool can make |
| Escalate only with `certainty >= strong` | Middle path, but `strong` is the v0 ceiling (§3.7), so this is nearly identical to unconditional escalation |

**Closed by:** a measured scope-classification error rate, per rule family, on
real code. Hypothesised source: REI-002.

**If taken anyway:** the guess is unfalsifiable after the fact. Once escalation
ships, every subsequent precision measurement conflates "the sink rule was
wrong" with "the scope inference was wrong", because both now produce the same
symptom — a HIGH finding a triager rejects. The two error sources become
inseparable, permanently.

---

## B-02 — Is the twenty-member `ResourceKind` vocabulary right?

**Blocked because** the v0 list was derived from what the *shipped rules*
suggest, not from what real code contains. Those are different populations, and
the difference is the whole question.

| Option | Cost if wrong |
|---|---|
| Ship the twenty (current draft) | A member absorbing most sites makes the field useless; a missing member makes it misleading. Falsifier F-3 |
| Ship a coarser set (~8) | Loses the distinction that justified a *new* enum over reusing `category`, which already has sixteen members |
| Ship open free-text and cluster later | Destroys diffability, schema validation, and authority mapping — the three reasons D-05 closed the enum |

**Closed by:** a frequency table of resource kinds over real sink sites, with an
explicit "needed a member that does not exist" bucket. Hypothesised source:
REI-001.

**If taken anyway:** the vocabulary churns after release. A closed enum's value
is that its diff means something — "this release grants a new resource class" is
only computable if the class set is stable. Churn in the first releases destroys
exactly the property that motivated closing it, and it cannot be recovered
retroactively because the earlier reports are already written in the old
vocabulary.

---

## B-03 — Which rules can actually have their selector extracted declaratively?

**Blocked because** the draft catalogue's argument positions are inferences from
each rule's `match` block and from library conventions, not observations of real
call sites. A position that is right in the documentation and absent in practice
yields `declared_argument_absent` — which is countable, but only after shipping.

| Option | Cost if wrong |
|---|---|
| Ship all 40 draft entries | Some fraction silently yields `absent`. Recoverable, and visible in `by_unresolved_reason` — the cheapest wrong answer here |
| Ship only entries confirmed against real code | Cannot be done: no measurement is accessible |
| Ship the 12 entries whose selector is a documented required positional | Highest confidence, lowest coverage; the report would be mostly unknown |

**Closed by:** per-rule selector-resolution rates on real call sites.
Hypothesised source: REI-001.

**If taken anyway:** this is the *least* damaging of the six to guess, because
D-13's counters make the error self-reporting and `by_unresolved_reason` names
the exact failing entries. It is listed as blocked rather than decided because
it determines whether v0 is worth shipping at all (falsifier F-1), not because
guessing it is unsafe.

---

## B-04 — Is SQL statement parsing in v0?

**Blocked because** it is the only way to distinguish `single` from `all` for the
four `database_row_set` rules, and it is also the highest-risk extraction in the
catalogue. The four rules in question (`DATA-DELETE-SQL`,
`DATA-DELETE-SQL-RAW`, `DATABASE-MUTATE`, `DATABASE-ORM-MUTATE`) are also where
this repository's recorded receiver-matching defect lived.

| Option | Cost if wrong |
|---|---|
| No SQL parsing (frozen as **v0 default**; catalogue status `blocked`) | The four rules report `scope: unknown`. Since they are a large share of the corpus's findings, this is most of falsifier F-2 |
| Regex `WHERE`-presence check | A predicate that is present but tautological (`WHERE 1=1`) reads as `single`. A false *narrowing* — the worst direction of error, because it under-alarms |
| A real SQL parser dependency | New dependency, new parse-failure mode, and dynamic SQL (f-strings, concatenation) defeats it anyway — and dynamic SQL is precisely what `DATA-DELETE-SQL-RAW` exists to catch |

**Closed by:** the share of real SQL sinks whose statement is a parseable
literal, versus dynamically constructed. Hypothesised source: REI-001B.

**If taken anyway:** the middle option is the trap. A `WHERE`-presence regex
produces a *narrowing* claim from a syntactic accident, which is the one error
direction `docs/ARCHITECTURE.md` principle 1 exists to forbid — "nothing
labelled `unknown` is ever silently promoted to `safe`". Reporting `scope:
single` because a tautological predicate is present is that promotion, wearing a
different name.

---

## B-05 — What threshold makes REI default-on?

**Blocked because** default-on is the point at which every consumer of every
output format sees the field, and there is no measured annotation error rate to
justify it.

| Option | Cost if wrong |
|---|---|
| Opt-in indefinitely | Nobody uses it; the layer is dead code that must still be maintained and tested |
| Default-on after one release with no reported defects | "No reports" from an opt-in feature nobody enabled is not evidence of correctness |
| Default-on at a stated accuracy threshold | Requires the instrument that does not exist |

**Closed by:** an annotation error rate against human adjudication, plus a
stated threshold. Hypothesised source: REI-002.

**If taken anyway:** risk R-01 realises at full scale. A wrong `resource:` line
on a *correct* finding teaches the reader that the tool guesses, and that lesson
transfers to the finding it is attached to. The repository's own stance —
"FALSE ASSURANCE IS WORSE THAN A REVIEWABLE FALSE POSITIVE" — is about
assurance; this is its mirror image, a reviewable annotation that costs
credibility rather than safety. The cost is real and is not recoverable by
turning the flag back off.

---

## B-06 — Does `resource_effect` feed authority binding in v1?

**Blocked because** wiring REI into `authority_binding.py` changes a *soundness*
verdict, not a presentation field, and that is a different risk class entirely.

Today `compare_authority_to_sink` runs an action-label soundness gate first:
`authorize_read(cust)` against `refund(cust, amt)` is `UNBOUND` regardless of
parameter matching. Adding a resource term would let the gate also reject
`authorize_delete(user)` against a sink whose resource is a different object —
which is the six-term binding problem's actual point.

| Option | Cost if wrong |
|---|---|
| Keep REI presentation-only (frozen for v0) | The `resource` term of the binding problem stays missing. No soundness gain |
| Resource participates as an additional `UNBOUND` trigger | A wrong resource inference now produces a wrong *soundness* verdict. `UNBOUND` is a claim about correctness, not a label |
| Resource participates only to *weaken* a `BOUND` verdict to `UNKNOWN`, never to assert `UNBOUND` | Strictly conservative, and the only option compatible with "`UNKNOWN` is never silently promoted". Still needs a measured error rate to size the `UNKNOWN` inflation |

**Closed by:** an annotation error rate plus a measurement of how many `BOUND`
verdicts would become `UNKNOWN`. Hypothesised source: REI-002.

**If taken anyway:** a presentation error becomes a soundness error. Everything
in `docs/ARCHITECTURE.md` about `UNBOUND` and `UNKNOWN` — the action-label gate
running first, `UNKNOWN` never promoted to `BOUND` — rests on those verdicts
being derived from evidence at the call site. An inferred resource is not
evidence at the call site; it is a catalogue lookup. Feeding it into a soundness
gate without a measured error rate would make the gate's guarantee weaker than
it currently claims to be, silently.

---

## 8.1 Why these six force `ARCHITECTURE NOT READY`

The distinction that decides the verdict: a decision is **deferrable** if
guessing wrong costs a later revision, and **blocking** if guessing wrong costs
something unrecoverable.

| ID | Wrong-guess cost | Recoverable? |
|---|---|---|
| B-01 | Precision-gate failures; error sources permanently conflated | No |
| B-02 | Vocabulary churn destroys release-to-release diffability | No |
| B-03 | Some entries yield `absent`, visible in the counters | **Yes** |
| B-04 | A false *narrowing* claim — the forbidden error direction | No |
| B-05 | Credibility loss that survives turning the flag off | No |
| B-06 | A presentation error becomes a soundness error | No |

Five of six are unrecoverable. One is recoverable and self-reporting.

An architecture is ready for implementation when its unresolved questions are
the recoverable kind. This one's are not, and the evidence that would close them
is not accessible. The honest verdict is therefore `ARCHITECTURE NOT READY` —
not because the architecture is wrong, but because nobody here can yet tell
whether it is right, and the frozen decisions are deliberately arranged so that
finding out does not require rewriting them.

## 8.2 What would flip the verdict

Nothing in D-01…D-14 needs to change. Specifically:

1. Make REI-001, REI-001B and REI-002 accessible in the working environment.
2. Re-derive B-01…B-06 against them — the options and thresholds are already
   enumerated above, so this is adjudication, not design.
3. Confirm that no *frozen* decision is contradicted (risk R-12). The
   contradiction check in [10-CONTRADICTION-CHECK.md](10-CONTRADICTION-CHECK.md)
   is written to be re-runnable for exactly this step.
4. Supersede AREF-001 with AREF-002 recording the closed decisions. Do not edit
   this document — §0.7.

If step 3 finds no contradiction, step 4 is a mechanical transcription. That is
the freeze doing its job: the expensive thinking is already done and does not
have to be redone when the evidence arrives.
