"""Rule loader — loads default rules from JSON and merges user config.

Handles malformed config gracefully: instead of crashing with a traceback,
prints the accepted schema and the specific error.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# The accepted config schema, printed on error.
_CONFIG_SCHEMA_EXAMPLE = """\
actenon-scan: config file could not be loaded.

Accepted format: JSON (.json) or YAML (.yml/.yaml, requires the [yaml] extra).

The top-level object may contain:

  {
    "guard_patterns": ["your_guard_function", "another_guard"],
    "sinks": [
      {
        "id": "YOUR-RULE-ID",
        "category": "your_category",
        "severity": "high",
        "description": "Description of the rule",
        "match": {
          "type": "qualified_call",
          "qualified_patterns": ["your.module.call"]
        }
      }
    ],
    "reachability": {
      "agent_framework_imports": ["your_framework"],
      "tool_decorators": ["your_tool_decorator"]
    }
  }

The most common use is adding custom guard patterns:

  {"guard_patterns": ["policy_gate", "assert_can", "my_authorization_check"]}

Note: the key is "guard_patterns" (not "guards" or "patterns").
"""


class ConfigError(Exception):
    """Raised when a config file is malformed. The message includes the
    accepted schema so the user knows exactly what to fix."""
    pass


@dataclass(frozen=True)
class SinkRule:
    id: str
    category: str
    severity: str
    description: str
    match: dict[str, Any]
    cwe: str = ""
    owasp: str = ""
    escalate_when: dict[str, Any] | None = None
    priority: int = 20


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

    Raises ConfigError (not a raw traceback) if the config is malformed.
    The error message includes the accepted schema.
    """
    rules = load_default_rules()
    if config_path is None:
        return rules

    config_file = Path(config_path)
    if not config_file.exists():
        raise ConfigError(f"config file not found: {config_file}")

    suffix = config_file.suffix.lower()
    try:
        if suffix == ".json":
            user = _load_rules_from_file(config_file)
        elif suffix in (".yml", ".yaml"):
            try:
                import yaml
            except ImportError:
                raise ConfigError(
                    "PyYAML is required to load YAML config. "
                    "Install with: pip install actenon-scan[yaml]"
                )
            with open(config_file) as f:
                raw = yaml.safe_load(f)
            if not isinstance(raw, dict):
                raise ConfigError(
                    f"config file must be a YAML mapping at the top level, "
                    f"got {type(raw).__name__}"
                )
            user = _parse_rules_dict(raw)
        elif suffix in (".toml",):
            raise ConfigError(
                f"TOML config is not supported. Use JSON (.json) or YAML (.yml/.yaml).\n"
                f"  {suffix} files are not accepted."
            )
        else:
            raise ConfigError(
                f"unsupported config format: {suffix}\n"
                f"Use .json, .yml, or .yaml."
            )
    except ConfigError:
        raise
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
        raise ConfigError(
            f"could not parse config file {config_file}: {e}\n\n"
            f"{_CONFIG_SCHEMA_EXAMPLE}"
        ) from e

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
    if not isinstance(raw, dict):
        raise ConfigError(
            f"config file must be a JSON object at the top level, "
            f"got {type(raw).__name__}"
        )
    return _parse_rules_dict(raw)


def _parse_rules_dict(raw: dict[str, Any]) -> Ruleset:
    sinks = []
    for s in raw.get("sinks", []):
        if not isinstance(s, dict):
            raise ConfigError(
                f"each sink rule must be an object, got {type(s).__name__}"
            )
        if "id" not in s or "category" not in s or "severity" not in s:
            raise ConfigError(
                f"each sink rule must have 'id', 'category', and 'severity' fields"
            )
        sinks.append(SinkRule(
            id=s["id"],
            category=s["category"],
            severity=s["severity"],
            description=s.get("description", ""),
            match=s.get("match", {}),
            cwe=s.get("cwe", ""),
            owasp=s.get("owasp", ""),
            escalate_when=s.get("escalate_when"),
            priority=s.get("priority", 20),
        ))
    guard_patterns = []
    # Support both the old "guards" array format and the newer top-level
    # "guard_patterns" array format.
    old_guards = raw.get("guards", [])
    if isinstance(old_guards, list):
        for g in old_guards:
            if isinstance(g, dict):
                guard_patterns.extend(g.get("patterns", []))
            elif isinstance(g, str):
                guard_patterns.append(g)
            else:
                raise ConfigError(
                    f"each guard entry must be an object or string, got {type(g).__name__}"
                )
    elif isinstance(old_guards, dict):
        # User wrote {"guards": {"patterns": [...]}} — a plausible mistake
        guard_patterns.extend(old_guards.get("patterns", []))
    elif old_guards is not None:
        raise ConfigError(
            f"'guards' must be an array or object, got {type(old_guards).__name__}"
        )
    guard_patterns.extend(raw.get("guard_patterns", []))
    return Ruleset(
        version=raw.get("version", "1"),
        sinks=sinks,
        guard_patterns=guard_patterns,
        reachability=raw.get("reachability", {}),
    )
