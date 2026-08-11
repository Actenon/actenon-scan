"""Capability manifest — deterministic serialisation of scan results.

WO3 Phase 3: a manifest is a deterministic JSON document that records every
capability in a repository at a point in time. Two scans of the same source
and config produce byte-identical manifests, enabling semantic diffing.

Schema v1. The manifest version is independent of the protocol version.

Key properties:
  - Deterministic: sorted keys, no timestamps, no machine-specific paths
  - Complete: every capability, every coverage fact, every analysis error
  - Lossless: enough information to reconstruct the scan result for diffing
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from actenon_scan.capability import Capability
from actenon_scan.identity import capability_to_key

MANIFEST_SCHEMA_VERSION = 1


@dataclass
class CoverageBlock:
    """What was scanned, what was skipped, what failed."""

    files_discovered: int = 0
    files_analysed: int = 0
    files_unsupported: int = 0
    files_failed: int = 0
    languages: list[str] = field(default_factory=list)
    analysis_errors: list[dict[str, Any]] = field(default_factory=list)
    config_used: dict[str, Any] = field(default_factory=dict)


@dataclass
class CapabilityManifest:
    """A deterministic manifest of all capabilities in a repository.

    The manifest is the comparison unit for the diff engine. Two manifests
    with the same content produce identical JSON.
    """

    schema_version: int = MANIFEST_SCHEMA_VERSION
    capabilities: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    manifest_hash: str = ""

    def to_json(self) -> str:
        """Serialise to deterministic JSON.

        Sorts all collections. No timestamps in equality-sensitive content.
        The manifest_hash is computed from the content and included in
        the output.
        """
        # Build the content dict (without manifest_hash)
        content: dict[str, Any] = {
            "schema_version": self.schema_version,
            "capabilities": sorted(
                self.capabilities, key=lambda c: (c.get("key", ""), c.get("file", ""), c.get("line", 0))
            ),
            "coverage": self._sort_coverage(self.coverage),
        }

        # Compute manifest hash from the content (deterministic)
        content_str = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.manifest_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()[:16]

        # Add manifest_hash to the output
        output = {**content, "manifest_hash": self.manifest_hash}
        return json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"

    def _sort_coverage(self, coverage: dict[str, Any]) -> dict[str, Any]:
        """Sort all collections in the coverage block."""
        sorted_coverage: dict[str, Any] = {}
        for k, v in sorted(coverage.items()):
            if isinstance(v, list):
                sorted_coverage[k] = sorted(v, key=str)
            elif isinstance(v, dict):
                sorted_coverage[k] = self._sort_coverage(v)
            else:
                sorted_coverage[k] = v
        return sorted_coverage


def build_manifest(
    capabilities: list[Capability],
    coverage: CoverageBlock,
    config: dict[str, Any] | None = None,
) -> CapabilityManifest:
    """Build a manifest from scan results.

    Each capability is serialised with its stable key, state, guard
    information, and evidence locations. The key is derived from
    ``capability_to_key`` (see identity.py).
    """
    caps_json: list[dict[str, Any]] = []
    for cap in capabilities:
        key = capability_to_key(cap)
        caps_json.append({
            "key": str(key),
            "language": cap.language,
            "function_name": cap.function_name,
            "entry_point_kind": key.entry_point_kind,
            "sink_family": key.sink_family,
            "resource_type": key.resource_type,
            "rule_id": cap.rule_id,
            "category": cap.category,
            "severity": cap.severity,
            "state": cap.state,
            "guard_status": cap.guard_status,
            "guard_message": cap.guard_message,
            "confidence": cap.confidence,
            "reachability_source": cap.reachability_source,
            "reachability_reason": cap.reachability_reason,
            "tier": cap.tier,
            "file": cap.file,
            "line": cap.line,
            "col": cap.col,
            "call_text": cap.call_text,
            "snippet_hash": cap.snippet_hash,
        })

    coverage_dict: dict[str, Any] = {
        "files_discovered": coverage.files_discovered,
        "files_analysed": coverage.files_analysed,
        "files_unsupported": coverage.files_unsupported,
        "files_failed": coverage.files_failed,
        "languages": sorted(coverage.languages),
        "analysis_errors": sorted(coverage.analysis_errors, key=lambda e: str(e)),
        "config_used": config or {},
    }

    return CapabilityManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        capabilities=caps_json,
        coverage=coverage_dict,
    )


def load_manifest(path_or_text: str) -> CapabilityManifest:
    """Load a manifest from a file path or JSON text."""
    import pathlib

    p = pathlib.Path(path_or_text)
    if p.exists():
        text = p.read_text(encoding="utf-8")
    else:
        text = path_or_text  # assume it's JSON text
    data = json.loads(text)
    return CapabilityManifest(
        schema_version=data.get("schema_version", MANIFEST_SCHEMA_VERSION),
        capabilities=data.get("capabilities", []),
        coverage=data.get("coverage", {}),
        manifest_hash=data.get("manifest_hash", ""),
    )


__all__ = [
    "MANIFEST_SCHEMA_VERSION",
    "CoverageBlock",
    "CapabilityManifest",
    "build_manifest",
    "load_manifest",
]
