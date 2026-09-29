# AREF-001 §4 — Interface freeze

Signatures only. No bodies. Nothing here has been written into `actenon_scan/`;
the module paths are the *proposed* locations for a future work order.

## 4.1 `actenon_scan/repository/resource_effect.py` (proposed)

```python
"""Resource Effect Inference — annotate a sink call site with the resource
it acts upon. Non-gating: see AREF-001 D-01."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal

from actenon_scan.capability import Capability
from actenon_scan.repository.certainty import AnalysisCertainty
from actenon_scan.repository.effect_summary import EffectType
from actenon_scan.repository.symbol_index import RepositoryIndex
from actenon_scan.repository.taint import TaintLattice


class ResourceKind(str, Enum):
    """Closed catalogue of resource classes. See AREF-001 §3.3.

    `UNKNOWN_RESOURCE` is mandatory and is the default.
    """
    ...


class ResourceScope(str, Enum):
    SINGLE = "single"
    SET = "set"
    ALL = "all"
    UNKNOWN = "unknown"


class SelectorOrigin(str, Enum):
    """See AREF-001 §3.6."""
    ...


CatalogueStatus = Literal["frozen", "draft", "blocked", "absent"]

UnresolvedReason = Literal[
    "rule_id_not_in_catalogue", "catalogue_entry_blocked",
    "declared_argument_absent", "selector_is_dynamic",
    "selector_not_decomposable", "scope_requires_predicate_analysis",
    "taint_state_unavailable", "call_site_not_located",
    "language_not_supported", "analysis_error",
]


@dataclass(frozen=True)
class ResourceSelector:
    text: str
    origin: SelectorOrigin
    certainty: AnalysisCertainty


@dataclass(frozen=True)
class ResourceEffect:
    effect: EffectType
    kind: ResourceKind
    scope: ResourceScope
    controllability: TaintLattice
    certainty: AnalysisCertainty
    rule_id: str
    normalised_rule_id: str
    language: Literal["python", "typescript", "go"]
    catalogue_status: CatalogueStatus
    selector: ResourceSelector | None = None
    unresolved_reason: UnresolvedReason | None = None

    def is_determined(self) -> bool:
        """True when kind is not UNKNOWN_RESOURCE and certainty > UNKNOWN.

        The single predicate every consumer must use. Consumers MUST NOT
        test `kind != UNKNOWN_RESOURCE` alone — that admits a determined
        kind carried on an unknown-certainty record.
        """
        ...


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SelectorDeclaration:
    """Where the resource lives in the call. Data, never code — D-06."""
    arg_positions: tuple[int, ...] = ()
    arg_keywords: tuple[str, ...] = ()
    from_receiver: bool = False


@dataclass(frozen=True)
class CatalogueEntry:
    normalised_rule_id: str
    resource_kind: ResourceKind
    selector: SelectorDeclaration
    scope_rule: Literal["single", "set", "all", "unknown"]
    max_certainty: AnalysisCertainty
    status: CatalogueStatus
    note: str = ""


@dataclass(frozen=True)
class ResourceEffectCatalogue:
    version: str
    entries: dict[str, CatalogueEntry]

    def lookup(self, normalised_rule_id: str) -> CatalogueEntry | None: ...


def load_catalogue(path: str | Path | None = None) -> ResourceEffectCatalogue:
    """Load `actenon_scan/rules/resource_effects.json`.

    Raises `ConfigError` (the existing `rules.loader` exception) on a
    malformed catalogue. A malformed catalogue MUST fail loudly at load
    rather than degrade to all-unknown at render — a silent degrade is
    indistinguishable from a repository with no resources.
    """


# ---------------------------------------------------------------------------
# Normalisation — D-14
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NormalisedRuleId:
    base: str                                    # catalogue key
    qualifiers: tuple[str, ...]                  # ("WEAK",) / ("UNBOUND",)
    language: Literal["python", "typescript", "go"]


def normalise_rule_id(rule_id: str) -> NormalisedRuleId:
    """Split an emitted rule ID into catalogue key, qualifiers and language.

    Total: every input returns a value. `-GO` sets language and is removed
    from `base`; `-WEAK` / `-UNBOUND` become qualifiers. Unrecognised
    suffixes are left on `base`, which then misses the catalogue and yields
    `rule_id_not_in_catalogue` — a countable outcome, not a crash.
    """


# ---------------------------------------------------------------------------
# Inference — the single entry point
# ---------------------------------------------------------------------------

def infer_resource_effect(
    *,
    rule_id: str,
    call_node: ast.Call | None,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef | None,
    catalogue: ResourceEffectCatalogue,
    reachability_certainty: AnalysisCertainty,
    index: RepositoryIndex | None = None,
    module_qname: str = "",
    language: Literal["python", "typescript", "go"] = "python",
) -> ResourceEffect:
    """Infer the resource effect of one sink call site.

    TOTAL: never raises, never returns None. Any internal failure yields a
    record with `certainty=ANALYSIS_ERROR` and
    `unresolved_reason="analysis_error"`.

    `call_node=None` (the site could not be located in the AST) yields
    `unresolved_reason="call_site_not_located"`, NOT a crash and NOT a skip.
    """


def annotate_capabilities(
    capabilities: list[Capability],
    *,
    catalogue: ResourceEffectCatalogue,
    asts_by_file: dict[str, ast.Module],
    index: RepositoryIndex | None = None,
) -> "ResourceEffectSummary":
    """Annotate in place. MUST NOT add to, remove from, or reorder the list.

    Pinned by invariant I-01.
    """


@dataclass
class ResourceEffectSummary:
    """The disclosure counters — D-13. Emitted in EVERY format, ALWAYS."""
    known_count: int = 0
    unknown_count: int = 0
    by_kind: dict[str, int] = ...
    by_unresolved_reason: dict[str, int] = ...
    catalogue_version: str = ""
```

### Frozen properties of these signatures

| | |
|---|---|
| `infer_resource_effect` is keyword-only | Positional args make argument-order mistakes silent; there are eight parameters |
| `infer_resource_effect` is total | No exception, no `None`. A crash in an annotation layer must never fail a scan that already has its findings |
| `annotate_capabilities` mutates in place and returns only counters | Returning a new list would let a caller substitute it, which is the one way a non-gating layer could become gating |
| `ResourceEffect` is frozen (immutable) | Prevents a report formatter from "fixing up" a record downstream |
| `is_determined()` is the only sanctioned predicate | Stops consumers writing `kind != UNKNOWN_RESOURCE`, which is the obvious and wrong test |
| No function takes a `Finding` | Findings are a projection of capabilities for reporting. Annotating only capabilities keeps one source of truth |

## 4.2 Engine integration (one call site)

```python
# actenon_scan/engine.py — inside scan_path, AFTER findings and
# capabilities are final, AFTER the optional repository layer.
if resource_effects_enabled:
    from actenon_scan.repository.resource_effect import (
        annotate_capabilities, load_catalogue,
    )
    result.resource_effect_summary = annotate_capabilities(
        result.capabilities,
        catalogue=load_catalogue(),
        asts_by_file=parsed_asts,
        index=repo_index,
    )
```

`ScanResult` gains one optional field:

```python
resource_effect_summary: "ResourceEffectSummary | None" = None
```

That is the entire engine delta. It is deliberately small enough to review in
one screen, and it has no branch that can reach the finding list.

## 4.3 Output-surface delta

### JSON (`report/json_out.py`)

Top level, present only when the layer ran:

```json
{
  "rei_schema_version": "0.1.0",
  "resource_effect_catalogue_version": "0.1.0-draft",
  "resource_effect_known_count": 0,
  "resource_effect_unknown_count": 0,
  "resource_effect_by_kind": {},
  "resource_effect_by_unresolved_reason": {}
}
```

Per capability (and mirrored onto each finding), present only when the layer
ran:

```json
{
  "resource_effect": {
    "effect": "file_delete",
    "kind": "filesystem_path",
    "scope": "single",
    "controllability": "model_controlled",
    "certainty": "strong",
    "rule_id": "DATA-DELETE-OS",
    "normalised_rule_id": "DATA-DELETE-OS",
    "language": "python",
    "catalogue_status": "frozen",
    "selector": {"text": "path", "origin": "parameter", "certainty": "strong"},
    "unresolved_reason": null
  }
}
```

Schema: `schema/rei-report-fragment.schema.json`. Backwards compatibility is
structural — every added key is new, no existing key changes type or meaning,
and when the layer is off the output is byte-identical to today's (invariant
I-09).

### SARIF (`report/sarif.py`)

Properties bag only, under `properties.resourceEffect`. No change to
`ruleId`, `level`, `message`, `locations`, or `partialFingerprints`. SARIF
consumers that do not know REI must be unaffected, and `level` in particular
must not move, because it drives code-scanning severity.

### Pretty / markdown / HTML

One line per finding, rendered **only** when `certainty >= heuristic`:

```
  resource: filesystem_path (single) — selector `path`, model-controlled
```

When `certainty` is `unknown` the line is either omitted or rendered as
`resource: not determined (<unresolved_reason>)`. It is **never** rendered as
anything a reader could take as a narrowing claim. The aggregate counters are
always shown, whatever the individual certainties.

## 4.4 Configuration

| Surface | Name | Default |
|---|---|---|
| CLI | `--resource-effects` / `--no-resource-effects` | off |
| Config file | `resource_effects.enabled` (boolean) | `false` |
| Config file | `resource_effects.catalogue` (path, optional override) | shipped catalogue |
| GitHub Action (`action.yml`) | `resource-effects` | `false` |

`resource_effects` is a **new top-level config key**, not a member of
`reachability`. That placement is load-bearing (D-12): REI is not a
reachability signal, and nesting it under `reachability` would put the two
meanings of "resource" in the same object.

Adding a top-level key requires `_KNOWN_KEYS` in
`actenon_scan/rules/loader.py` to be extended in the implementing work order —
otherwise the loader's own unknown-key warning fires on a key the scanner
itself documents. **This task does not make that change.** It is recorded here
as an implementation obligation so the future work order does not discover it
from a user's bug report.

## 4.5 Public API and stability

`actenon_scan/api.py` re-exports the public surface. The freeze's position:
`ResourceEffect`, `ResourceKind`, `ResourceScope` and
`ResourceEffectSummary` are exported; `infer_resource_effect`,
`annotate_capabilities`, `normalise_rule_id` and the catalogue types are
**not**. Exporting the inference entry point would invite out-of-tree callers to
depend on REI's internals during the one release in which they are most likely
to move.
