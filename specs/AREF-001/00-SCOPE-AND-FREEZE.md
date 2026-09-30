# AREF-001 §0 — Scope and freeze declaration

## 0.1 Freeze baseline

| | |
|---|---|
| Repository | `actenon-scan` |
| Branch | `main` |
| Commit at freeze | `b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16` |
| Commit subject | `Feat/cross language reachability (#95)` |
| Package version | `1.5.0` (`pyproject.toml`) |
| Working tree before work | clean (`git status --short` produced no output) |
| Artefact root | `specs/AREF-001/` (created by this task; did not previously exist) |

Every statement in AREF-001 about the shipped scanner is a statement about
that commit. If the commit moves, the freeze must be re-validated: see
[07-RISKS-AND-FALSIFICATION.md](07-RISKS-AND-FALSIFICATION.md) §7.6.

## 0.2 What "architecture freeze" means here

A freeze fixes the **shape** of a capability so that the shape can be
reviewed, contradicted and rejected before implementation cost is incurred.
Concretely, AREF-001 fixes:

1. where the capability sits in the existing pipeline;
2. the data it produces, as a closed type model with a JSON schema;
3. the public interfaces it exposes, as signatures without bodies;
4. the invariants it must never violate, each bound to a named test
   obligation;
5. the output-surface delta, versioned and additive;
6. the gating and rollout policy;
7. the validation plan and the results that would falsify the design.

A freeze deliberately does **not** fix: algorithmic internals, performance
characteristics, per-provider behaviour, or anything whose correct answer
depends on evidence that is not in hand. Those are recorded as blocked
decisions in [08-BLOCKED-DECISIONS.md](08-BLOCKED-DECISIONS.md) rather than
guessed.

## 0.3 In scope

| ID | In scope |
|---|---|
| S-01 | A per-sink-call-site structured record naming the *effect verb*, *resource kind*, *resource selector*, *scope*, *controllability* and *certainty* of that call |
| S-02 | A data-only catalogue mapping shipped sink rule IDs to resource extraction declarations |
| S-03 | Additive, versioned output of that record in JSON, with narrower renderings in SARIF / pretty / markdown |
| S-04 | Composition rules against the existing reachability, guard, effect-summary and authority-binding layers |
| S-05 | Opt-in configuration and a rollout gate mirroring the `--resource-boundary` precedent |
| S-06 | The invariants and test obligations that make the layer provably non-regressive |
| S-07 | A validation plan stated as falsifiable predictions |

## 0.4 Out of scope

| ID | Out of scope | Why |
|---|---|---|
| X-01 | Any implementation of REI | This task is a freeze; `actenon_scan/` is untouched |
| X-02 | Any change to sink matching, reachability, or guard analysis | Detection must not change (`report/blast_radius.py` design constraint "RULE 5") |
| X-03 | Provider-specific rules (Stripe-only, FastAPI-only, Tavily-only logic) | Explicitly prohibited by the task, and the repository's own recorded FP mechanism is provider/name heuristics |
| X-04 | Scanner improvements of any kind | Explicitly prohibited by the task |
| X-05 | Severity changes, escalation, or new gating thresholds | Blocked on evidence — see [08-BLOCKED-DECISIONS.md](08-BLOCKED-DECISIONS.md) B-01 |
| X-06 | Interprocedural resource propagation | The repository has no interprocedural taint (`docs/ARCHITECTURE.md`, "No interprocedural taint"); REI v0 must not assume one |
| X-07 | Runtime or dynamic analysis | Out of the scanner's model entirely |
| X-08 | Cross-language resource unification | The repository layer is Python-only; TS/Go are separate detectors with their own rule IDs |
| X-09 | Selection, identification or inspection of future validation repositories | Explicitly prohibited by the task; no such repository is named, searched for, or referenced anywhere in this directory |
| X-10 | Re-running REI-001 / REI-001B / REI-002, or any other experiment | Explicitly prohibited by the task |

## 0.5 Prohibitions honoured

The task imposed nine prohibitions. Each is recorded here with how it was
honoured, so a reviewer can check compliance without reading the transcript.

| Prohibition | How it was honoured |
|---|---|
| Must not modify `actenon_scan/` | No file under `actenon_scan/` was written. Proof: [REPORT.md](REPORT.md) §29 |
| Must not modify `tests/` | No file under `tests/` was written. Proof: [REPORT.md](REPORT.md) §29 |
| Must not modify production configuration | `.actenon-scan.json`, `pyproject.toml`, `action.yml`, `.github/**`, `Makefile`, `wrangler.toml` untouched |
| Must not modify existing REI evidence | No existing evidence artefact was modified. (None named REI-001/001B/002 exists — see §1) |
| Must not modify existing production source files | Nothing outside `specs/AREF-001/` was created or edited |
| Must not inspect, search for, clone, identify, select or browse R05/R06/R07 | No such search was performed. No repository was cloned or fetched. No network access to any forge was used for repository discovery. See §0.6 for the one adjacent detail that required care |
| Must not search GitHub for future validation repositories | No GitHub search of any kind was performed |
| Must not implement Resource Effect Inference | No executable REI code exists. `validate.py` is a schema/manifest checker with no detection logic and no import of `actenon_scan` |
| Must not improve the scanner | No behavioural change was made. Two pre-existing observations were *recorded*, not fixed — see [10-CONTRADICTION-CHECK.md](10-CONTRADICTION-CHECK.md) §10.4 and §10.5 |
| Must not create provider-specific rules | The catalogue is keyed by *existing* rule ID and declares argument positions only. It introduces no new provider pattern, no new module name, and no new function name |
| Must not open or modify a PR | No PR was opened or modified |
| Must not push anything | Nothing was pushed. The artefacts are left as untracked files so that `git status --short` is itself the non-modification proof |

## 0.6 A naming hazard worth stating explicitly

`docs/COVERAGE.md`, `docs/RECALL.md` and `tests/benchmark/recall_methodology.md`
contain *architecture coverage row* identifiers of the form `r01`…`r09`. These
are tool-exposure archetypes internal to the coverage contract (for example,
`r01` is "MCP tool decorator"). They are **not** repositories, and they are not
the `R05`/`R06`/`R07` referred to in the task.

AREF-001 does not depend on any coverage row, does not enumerate rows `r05`–`r07`,
and does not cite them. This paragraph exists so that a reviewer who greps for
`r05` in the repository and finds a hit does not mistake it for a prohibition
breach.

## 0.7 Relationship to future work orders

AREF-001 is a *precondition* artefact. It does not authorise implementation.
Implementation is authorised only when every decision in
[08-BLOCKED-DECISIONS.md](08-BLOCKED-DECISIONS.md) is closed by evidence, at
which point AREF-001 should be superseded by AREF-002 (the unblocked freeze)
rather than edited in place. Editing a freeze in place destroys the property
that made it useful.
