"""Rule loader — loads default rules from JSON and merges user config."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SinkRule:
    id: str
    category: str
    severity: str
    description: str
    match: dict[str, Any]


@dataclass
class Ruleset:
    version: str = "1"
    sinks: list[SinkRule] = field(default_factory=list)
    guard_patterns: list[str] = field(default_factory=list)
    reachability: dict[str, Any] = field(default_factory=dict)


def _default_rules_path() -> Path:
    return Path(__file__).resolve().parent / "default_rules.json"


def load_default_rules() -> Ruleset:
    """Load the shipped default ruleset."""
    return _load_rules_from_file(_default_rules_path())


def load_rules(config_path: str | Path | None = None) -> Ruleset:
    """Load default rules, then merge user config if provided.

    User config can add new sinks, extend guard patterns, or override
    reachability signals. Existing rules are not removed — only extended.
    """
    rules = load_default_rules()
    if config_path is None:
        return rules

    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"config file not found: {config_file}")

    suffix = config_file.suffix.lower()
    if suffix == ".json":
        user = _load_rules_from_file(config_file)
    elif suffix in (".yml", ".yaml"):
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML is required to load YAML config. Install with: pip install actenon-scan[yaml]")
        with open(config_file) as f:
            raw = yaml.safe_load(f)
        user = _parse_rules_dict(raw)
    else:
        raise ValueError(f"unsupported config format: {suffix}")

    # Merge: extend, don't replace
    rules.sinks.extend(user.sinks)
    rules.guard_patterns.extend(user.guard_patterns)
    for key, val in user.reachability.items():
        if key in rules.reachability and isinstance(rules.reachability[key], list):
            rules.reachability[key].extend(val)
        else:
            rules.reachability[key] = val
    return rules


def _load_rules_from_file(path: Path) -> Ruleset:
    with open(path) as f:
        raw = json.load(f)
    return _parse_rules_dict(raw)


def _parse_rules_dict(raw: dict[str, Any]) -> Ruleset:
    sinks = [
        SinkRule(
            id=s["id"],
            category=s["category"],
            severity=s["severity"],
            description=s.get("description", ""),
            match=s.get("match", {}),
        )
        for s in raw.get("sinks", [])
    ]
    guard_patterns = []
    for g in raw.get("guards", []):
        guard_patterns.extend(g.get("patterns", []))
    return Ruleset(
        version=raw.get("version", "1"),
        sinks=sinks,
        guard_patterns=guard_patterns,
        reachability=raw.get("reachability", {}),
    )
