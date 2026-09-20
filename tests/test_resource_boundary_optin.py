"""Web route handlers are entry points only when asked for.

`reachability.resource_boundary_decorators` was on by default and contained
BARE names — "get", "post", "put", "delete", "patch", "route", "api_route".
Any decorator called `@get` in any codebase matched. Scanning pallets/flask,
a repository this project pins with category "control" (where
corpus-triage.json states that any finding is a precision failure by
definition), reported a parameterised INSERT in a plain tutorial view as
HIGH DATABASE-MUTATE, with no agent framework imported anywhere in the repo.

Two changes: bare names removed, keeping only qualified forms; and the whole
signal moved behind an opt-in. The README asks "what can your AI agent do
without permission?" — a Flask view is not an answer to that question unless
the user says it is.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from actenon_scan.engine import scan_path
from actenon_scan.rules.loader import load_rules

FIXTURE = (
    Path(__file__).resolve().parent
    / "benchmark" / "precision" / "p20_flask_route_no_agent.py"
)

BARE_NAMES = frozenset(
    {"get", "post", "put", "delete", "patch", "route", "api_route",
     "head", "options"}
)


def test_default_ruleset_has_no_bare_decorator_names():
    """A bare name matches any decorator with that name, anywhere."""
    decorators = load_rules(None).reachability["resource_boundary_decorators"]
    bare = sorted(d for d in decorators if d in BARE_NAMES)
    assert bare == [], (
        f"bare decorator names still present: {bare}. Any @{bare[0]} in any "
        f"codebase matches these."
    )
    assert all("." in d for d in decorators), decorators
    # The qualified forms must survive — this is an opt-in, not a deletion.
    assert "app.route" in decorators
    assert "router.post" in decorators
    assert "bp.get" in decorators


def test_resource_boundary_is_off_by_default():
    assert load_rules(None).reachability["resource_boundary_enabled"] is False


def test_the_flask_shape_yields_nothing_at_defaults():
    result = scan_path(FIXTURE)
    findings = [f for f in result.findings if not f.suppressed]
    assert findings == [], [(f.rule_id, f.line) for f in findings]


def test_the_flask_shape_returns_when_explicitly_asked_for():
    """Opt-in, not deletion. The user who asks for it gets it."""
    result = scan_path(FIXTURE, resource_boundary=True)
    findings = [f for f in result.findings if not f.suppressed]
    assert [f.rule_id for f in findings] == ["DATABASE-MUTATE"]
    assert findings[0].severity == "high"


def test_the_config_key_enables_it_without_the_flag(tmp_path: Path):
    config = tmp_path / "cfg.json"
    config.write_text('{"reachability": {"resource_boundary_enabled": true}}')
    result = scan_path(FIXTURE, config=config)
    assert [f.rule_id for f in result.findings if not f.suppressed] == [
        "DATABASE-MUTATE"
    ]


def test_an_agent_tool_in_the_same_shape_is_still_found(tmp_path: Path):
    """Turning the route signal off must not turn off tool detection."""
    (tmp_path / "t.py").write_text(
        "from agents import tool\nimport sqlite3\n\n\n"
        "@tool\n"
        "def register(username, password):\n"
        "    db = sqlite3.connect('a.db')\n"
        "    db.execute('INSERT INTO user (username) VALUES (?)', (username,))\n"
    )
    findings = [f for f in scan_path(tmp_path).findings if not f.suppressed]
    assert [f.rule_id for f in findings] == ["DATABASE-MUTATE"]


@pytest.mark.parametrize("enabled", [False, True])
def test_the_flag_is_part_of_the_cache_key(tmp_path: Path, enabled):
    """A scan with the flag on must not serve results cached with it off."""
    from actenon_scan.cache import FileCache

    cache = FileCache(tmp_path / "c")
    scan_path(FIXTURE, cache=cache, resource_boundary=not enabled)
    result = scan_path(FIXTURE, cache=cache, resource_boundary=enabled)
    findings = [f for f in result.findings if not f.suppressed]
    assert bool(findings) is enabled
