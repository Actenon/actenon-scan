# AREF-001 §10 — Cross-document contradiction check

A freeze that contradicts itself is worse than no freeze, because each reader
takes the half that suits them. This section is the audit, including the
contradictions it found. Three were found and all three were resolved; they are
recorded rather than quietly fixed.

Mechanically checkable items are checked by `validate.py`; the check name is
given so a reviewer can re-run rather than re-read.

## 10.1 Method

| Axis | What was compared |
|---|---|
| A-1 | Every frozen decision D-01…D-14 against every other, for mutual consistency |
| A-2 | Every documented enum value list against the JSON schemas |
| A-3 | Every JSON schema against the examples, positive and negative |
| A-4 | Every schema enum against the shipped Python enum it claims to mirror |
| A-5 | The draft catalogue against the rule IDs the shipped detectors actually emit |
| A-6 | Every invariant I-01…I-12 against the decision it claims to protect |
| A-7 | Every blocked decision B-01…B-06 against the frozen decisions, to confirm no frozen decision presupposes a blocked one |
| A-8 | Every cross-document reference and relative link |
| A-9 | Claims about the shipped scanner against the scanner at the frozen commit |

## 10.2 Enum and schema agreement — PASS

Checked by `validate.py` (`schema effect enum equals EffectType`,
`resourceKind carries the unknown_resource sentinel`, `catalogue uses only
declared resource kinds`, plus the full positive/negative example suite).

```
effectType         schema 20 members  ==  EffectType         20 members   identical
analysisCertainty  schema  6 members  ==  AnalysisCertainty   6 members   identical
taintLattice       schema  6 members  ==  TaintLattice        6 members   identical
resourceKind       schema 20 members  (new; 19 used by the draft catalogue)
```

Reproduce:

```bash
python3 - <<'PY'
import sys, json; sys.path.insert(0, '.')
from actenon_scan.repository.effect_summary import EffectType
from actenon_scan.repository.certainty import AnalysisCertainty
from actenon_scan.repository.taint import TaintLattice
d = json.load(open('specs/AREF-001/schema/resource-effect.schema.json'))['$defs']
for name, py in (('effectType', EffectType), ('analysisCertainty', AnalysisCertainty),
                 ('taintLattice', TaintLattice)):
    print(name, set(d[name]['enum']) == {e.value for e in py})
PY
```

The one `ResourceKind` member the draft catalogue does not use is
`database_table`, which is intentional and is stated as such in
[03-DATA-MODEL.md](03-DATA-MODEL.md) §3.3: it is the member blocked decision
B-04 would activate. **This is a deliberate asymmetry, not a contradiction** —
but it is the kind of thing that reads as an oversight, so it is named here.

## 10.3 Catalogue coverage — PASS

Checked by `validate.py` (`catalogue covers every <language> rule ID exactly`).

```
python      catalogue 31  detector 31  exact match
typescript  catalogue  9  detector  9  exact match
go          catalogue  9  detector  9  exact match   (keyed after -GO normalisation)
            ─────────────
            49 entries, 49 unique (normalised_rule_id, language) keys
            38 draft, 11 blocked, 0 frozen
```

Zero `frozen` entries is the catalogue's substantive statement and it is
*checked*, not merely asserted: `validate.py` fails if one appears. See
[08-BLOCKED-DECISIONS.md](08-BLOCKED-DECISIONS.md) B-03.

## 10.4 Observation: the effect map carries one rule ID no Python rule emits

Reproducible at the frozen commit:

```bash
python3 - <<'PY'
import json, re, pathlib
rule_ids = {s['id'] for s in json.load(
    open('actenon_scan/rules/default_rules.json'))['sinks']}
src = pathlib.Path('actenon_scan/repository/effect_summary.py').read_text()
block = src.split('_RULE_ID_TO_EFFECT: dict[str, EffectType] = {')[1].split('}')[0]
mapped = set(re.findall(r'"([A-Z0-9\-]+)":', block))
print('sinks in default_rules.json      :', len(rule_ids))
print('rule IDs in _RULE_ID_TO_EFFECT   :', len(mapped))
print('mapped but not a Python sink rule:', sorted(mapped - rule_ids))
print('Python sink rule with no mapping :', sorted(rule_ids - mapped))
PY
```

Output:

```
sinks in default_rules.json      : 31
rule IDs in _RULE_ID_TO_EFFECT   : 32
mapped but not a Python sink rule: ['EXEC-SHELL-GO']
Python sink rule with no mapping : []
```

Every Python sink rule has an effect mapping — good. The extra entry is
`EXEC-SHELL-GO`, a Go rule ID handled by adding it to the map directly rather
than by normalising the suffix. That is the seam §10.5 examines.

**Recorded, not fixed.** No change was made to `effect_summary.py`.

## 10.5 Observation: 8 of 9 Go rule IDs have no effect mapping

`effect_for_rule_id` strips only `-WEAK` and `-UNBOUND`. The Go detector emits
nine rule IDs, all suffixed `-GO`, and only `EXEC-SHELL-GO` is in the map.
Reproducible:

```bash
python3 -c "
import sys; sys.path.insert(0, '.')
from actenon_scan.repository.effect_summary import effect_for_rule_id
for i in ['DATA-DELETE-OS-GO','DATA-DELETE-SQL-GO','EXEC-SHELL-GO','FILE-WRITE-GO',
          'NET-EGRESS-GO','PAY-GENERIC-REFUND-GO','PAY-STRIPE-REFUND-GO',
          'PROVIDER-SDK-CALL-GO','SECRET-READ-GO']:
    print(f'{i:24} -> {effect_for_rule_id(i)}')
"
```

Output:

```
DATA-DELETE-OS-GO        -> None
DATA-DELETE-SQL-GO       -> None
EXEC-SHELL-GO            -> EffectType.SHELL_EXECUTION
FILE-WRITE-GO            -> None
NET-EGRESS-GO            -> None
PAY-GENERIC-REFUND-GO    -> None
PAY-STRIPE-REFUND-GO     -> None
PROVIDER-SDK-CALL-GO     -> None
SECRET-READ-GO           -> None
```

**Recorded, not fixed.** Fixing it is a scanner change, which this task
prohibits. Its relevance to the freeze is direct: it is the empirical basis for
**D-14**, and the reason the draft catalogue is keyed on normalised IDs and
carries Go entries. Without D-14, REI would reproduce this hole in a second
place — and this time on a user-facing field rather than on an internal effect
lookup.

## 10.6 Contradictions found and resolved

### C-1 — Two meanings of "resource" in one report

**Found in:** the initial framing of the capability itself. The repository
already uses "resource boundary" for an *entrypoint class* — a route handler
driven by an external client rather than a model
(`reachability_cfg["resource_boundary_decorators"]`, the `resource_boundary`
signal). Introducing "resource" for *the object a sink acts on* would put two
unrelated meanings of the word in the same report, and in the same JSON object
if the config key had been nested under `reachability`.

**Why it is a real contradiction rather than a style quibble:** the repository
has already shipped this defect. Commit `f472a57` records the root cause as
"`resource_boundary` signals produce HIGH confidence reachability, but the
pretty output said 'agent entry point' for ALL signals — conflating
externally-callable HTTP endpoints with model-callable entrypoints."

**Resolved by:** frozen decision **D-12** (naming mandate: existing names keep
`resource_boundary`; every REI name is `resource_effect*` / `ResourceKind` /
`ResourceScope`; no `ResourceKind` member may denote an entrypoint), the
top-level config key placement in §4.4, and invariant **I-08** with an
adversarial test obligation.

### C-2 — A catalogue ceiling that the catalogue could raise by itself

**Found in:** the first draft of the certainty model, which capped `certainty`
via the catalogue's `max_certainty` field but left `max_certainty` free to take
any `AnalysisCertainty` value. A catalogue edit could then mint `proven` for
any rule, which contradicts §3.7's claim that `proven` is unreachable in v0 —
a claim the freeze relies on when it argues that every annotation is
overridable by the reader.

**Resolved by:** three layers rather than one, because a single one is an
honour system. (a) The catalogue schema restricts `max_certainty` to
`strong` / `heuristic` / `unknown`, so `proven` cannot be written. (b) The
record schema rejects `certainty: proven` outright. (c) Invariant **I-06** is a
test obligation over every shipped entry. Negative examples
`resource-effect.invalid.json[0]` and `catalogue.invalid.json[4]` pin (a) and
(b), and both are checked by `validate.py`.

### C-3 — A "frozen" catalogue in a freeze that is NOT READY

**Found in:** the first draft of the catalogue, which marked well-known
positional rules (`open()`, `os.remove()`, `eval()`) as `status: frozen` with
`max_certainty: strong`. This contradicts B-03 and §1: promoting an entry to
`frozen` asserts that its declared selector location is correct **on real call
sites**, and no such measurement is accessible. It would also have produced the
odd result of a document that declares itself not ready while shipping
entries that claim to be settled.

**Resolved by:** every entry in the draft catalogue is `draft` or `blocked`;
none is `frozen`. The schema's `frozen` branch keeps its coverage through
`examples/catalogue.valid.json`, which is labelled an illustration rather than
a proposal. `validate.py` fails if a `frozen` entry ever appears in the draft
catalogue, so the resolution is enforced rather than remembered.

## 10.7 Consistency of the frozen decisions against each other — PASS

Every pair of D-01…D-14 was compared. The four pairs with a real interaction:

| Pair | Interaction | Consistent? |
|---|---|---|
| D-01 (non-gating) × D-09 (no severity change) | D-09 is a special case of D-01 — severity is the gating channel. Stated separately because severity changes exit codes and deserves its own invariant | Yes; I-02 exists as well as I-01 |
| D-04 (reuse `EffectType`) × D-05 (new `ResourceKind`) | One vocabulary reused, one introduced. Asymmetric, and the asymmetry is justified: an effect taxonomy already exists, a resource taxonomy does not | Yes |
| D-06 (data-only catalogue) × D-14 (normalisation in code) | D-14 puts *suffix* handling in code while D-06 keeps *per-rule* knowledge in data. Compatible because normalisation is rule-independent — it is the same three suffix rules for every rule ID | Yes; I-10 tests that no rule ID literal appears in the module |
| D-07 (no name-based inference) × the catalogue's `arg_keywords` | A keyword match is a name match against an argument label. Tension is real | Resolved: keywords are matched **exactly**, never by substring (catalogue schema `arg_keywords` description), and the keyword policy in the draft catalogue's `_comment` restricts them to lowercase vendor-neutral names. The historical defect was *substring* matching on *receiver identifiers*, which this permits nowhere |

## 10.8 Invariants against decisions — PASS

Each invariant maps to at least one decision, and each decision with a
mechanically checkable consequence maps to at least one invariant.

| Decision | Invariant(s) |
|---|---|
| D-01 | I-01 |
| D-02 | I-03 |
| D-03 | I-02 (scope must not escalate), I-07 |
| D-04 | I-07 |
| D-05 | I-04, I-07 |
| D-06 | I-10 |
| D-07 | I-04 |
| D-08 | I-05, I-06 |
| D-09 | I-02 |
| D-10 | I-09 |
| D-11 | I-09 |
| D-12 | I-08 |
| D-13 | I-11 |
| D-14 | I-03 (a normalisation miss must still produce a record) |

Unmapped: none. D-11 is only partially testable — a default value is a config
assertion, and I-09's golden file covers the observable half.

## 10.9 Blocked decisions against frozen decisions — PASS

Confirmed that no frozen decision presupposes the answer to a blocked one.
The two that come closest:

- **D-09 (no severity change) and B-01 (does `all` escalate?).** D-09 freezes
  the v0 default; B-01 remains open for v1. Consistent, because D-09 is scoped
  "for v0" explicitly in §2.4.
- **D-05 (closed `ResourceKind`) and B-02 (is the vocabulary right?).** D-05
  freezes *closure*; B-02 concerns *membership*. §2.4 and Q3 both state the
  distinction. Consistent — and it is the reason a wrong answer to B-02 costs a
  vocabulary revision rather than an architecture revision.

## 10.10 Links and references — PASS

Every cross-document link in this directory is relative and resolves to a file
that exists. No external URL is used, so
`.github/workflows/link-check.yml` cannot fail on this directory's account.
Section numbers referenced across files were checked individually.

## 10.11 Residual inconsistency, disclosed

One thing is inconsistent and is not resolvable here.

`schema/resource-effect.schema.json` restates the `EffectType`,
`AnalysisCertainty` and `TaintLattice` member lists as JSON Schema `enum`s.
That is duplication of exactly the kind D-04 forbids inside the codebase. It is
unavoidable — a JSON Schema cannot import a Python enum — and it is mitigated
rather than removed: `validate.py` checks the effect enum against
`effect_summary.py` on every run, and invariant **I-07** makes the same check a
test obligation. A future `EffectType` addition therefore fails a check rather
than drifting silently.

Recorded here rather than in a footnote because it is the one place where this
freeze does something it tells the implementation not to do.
