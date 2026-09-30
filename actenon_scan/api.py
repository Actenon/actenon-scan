"""Public, stable API surface for actenon-scan.

This module is the contract between actenon-scan and any code that embeds
it as a library (agent frameworks, marketplaces, IDE extensions, SAST
platforms). Symbols re-exported here are stable across minor versions;
breaking changes require a major version bump and a 2-release deprecation
cycle (see CONTRIBUTING.md).

Why this module exists:
    Before actenon_scan.api existed, integrators had to deep-import from
    actenon_scan.engine, actenon_scan.rules.loader, etc. — none of which
    were declared as public. `from actenon_scan import scan_path` failed
    with ImportError. This module fixes that by re-exporting the public
    surface with an explicit __all__.

Usage:
    from actenon_scan.api import scan_path, Finding, ScanResult, Ruleset

    result = scan_path("./my-agent-code")
    for finding in result.findings:
        if not finding.suppressed:
            print(f"{finding.file}:{finding.line} {finding.rule_id}")
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Mapping

# ── Engine: scanning ──
from actenon_scan.engine import (
    scan_path,
    scan_path_parallel,
    auto_jobs,
    ScanResult,
    Finding,
)

# ── Rules: loading + extension ──
from actenon_scan.rules.loader import (
    load_rules,
    load_default_rules,
    Ruleset,
    SinkRule,
    ConfigError,
)

# ── Cache (optional; integrators may want to control cache location) ──
from actenon_scan.cache import FileCache, get_default_cache_dir

# M1's graph types are inert; importing the proof model is deferred until the
# explicitly requested claim scan, preserving ordinary scanner isolation.
from actenon_scan.invocation_graph import Entrypoint, GraphLimits, InvocationGraph, RootKind

if TYPE_CHECKING:
    from actenon_scan.claim_genesis import ClaimGenesisResult


def scan_effect_claims(
    target: str | Path, *, entrypoints: Iterable[Entrypoint] = (),
    discover_roots: bool = True, config: str | Path | None = None,
    include_globs: list[str] | None = None, exclude_globs: list[str] | None = None,
    limits: GraphLimits | None = None,
    matched_rule_ids: Mapping[tuple[str, int, int], Iterable[str]] | None = None,
) -> "ClaimGenesisResult":
    """Create M1 claims from callable roots; see claim_genesis.scan_effect_claims."""
    from actenon_scan.claim_genesis import scan_effect_claims as run
    return run(target, entrypoints=entrypoints, discover_roots=discover_roots, config=config,
               include_globs=include_globs, exclude_globs=exclude_globs, limits=limits,
               matched_rule_ids=matched_rule_ids)


__all__ = [
    # Engine
    "scan_path",
    "scan_path_parallel",
    "auto_jobs",
    "ScanResult",
    "Finding",
    "scan_effect_claims",
    "Entrypoint",
    "GraphLimits",
    "InvocationGraph",
    "RootKind",
    # Rules
    "load_rules",
    "load_default_rules",
    "Ruleset",
    "SinkRule",
    "ConfigError",
    # Cache
    "FileCache",
    "get_default_cache_dir",
]

__version__ = "1.0.0"  # public API version; bumps with breaking changes
