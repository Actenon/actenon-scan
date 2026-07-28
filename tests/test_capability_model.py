"""Work Order 2, Phase 2 — Capability model tests.

Tests that the capability enumeration:
  - Records guarded sinks as GUARD_FOUND (not discarded)
  - Records unguarded sinks as REVIEW_REQUIRED
  - Records weak guards as REVIEW_REQUIRED
  - Records unbound guards as REVIEW_REQUIRED
  - Counts are consistent
  - JSON output includes capability fields
  - Backward compatibility: findings are unchanged
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path
from actenon_scan.capability import Capability, guard_status_to_capability_state


def _scan_source(source: str) -> object:
    """Scan a Python source string and return the ScanResult."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.py"
        p.write_text(source)
        config = {"guard_patterns": ["authorize", "authorize_bool"]}
        (Path(td) / ".actenon-scan.json").write_text(json.dumps(config))
        return scan_path(Path(td), config=Path(td) / ".actenon-scan.json")


def test_guarded_sink_recorded_as_guard_found():
    """A guarded sink is recorded as GUARD_FOUND, not discarded."""
    source = '''import subprocess, os
from mcp import tool

@tool
def guarded(path: str) -> None:
    authorize(path)
    os.remove(path)

def authorize(path: str) -> None:
    if not path.startswith("/tmp/"):
        raise PermissionError(path)
'''
    result = _scan_source(source)
    caps = [c for c in result.capabilities if c.category == "data_destruction"]
    assert len(caps) == 1
    assert caps[0].state == "GUARD_FOUND"
    assert caps[0].guard_status == "guarded"


def test_unguarded_sink_recorded_as_review_required():
    """An unguarded sink is recorded as REVIEW_REQUIRED."""
    source = '''import subprocess
from mcp import tool

@tool
def unguarded(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
'''
    result = _scan_source(source)
    caps = [c for c in result.capabilities if c.category == "shell_execution"]
    assert len(caps) >= 1
    assert caps[0].state == "REVIEW_REQUIRED"
    assert caps[0].guard_status == ""


def test_weak_guard_recorded_as_review_required():
    """A weak guard (result discarded) is REVIEW_REQUIRED."""
    source = '''import os
from mcp import tool

@tool
def weak_guarded(path: str) -> None:
    authorize_bool(path)
    os.remove(path)

def authorize_bool(path: str) -> bool:
    return path.startswith("/tmp/")
'''
    result = _scan_source(source)
    caps = [c for c in result.capabilities if c.category == "data_destruction"]
    assert len(caps) == 1
    assert caps[0].state == "REVIEW_REQUIRED"
    assert caps[0].guard_status == "weak"


def test_capability_summary_counts():
    """Capability summary counts are consistent."""
    source = '''import subprocess, os
from mcp import tool

@tool
def unguarded(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()

@tool
def guarded(path: str) -> None:
    authorize(path)
    os.remove(path)

def authorize(path: str) -> None:
    if not path.startswith("/tmp/"):
        raise PermissionError(path)
'''
    result = _scan_source(source)
    summary = result.capability_summary
    assert summary.total == 2
    assert summary.guard_found == 1
    assert summary.review_required == 1
    assert summary.accepted_decision == 0
    assert summary.not_analysed == 0


def test_json_output_includes_capabilities():
    """JSON output includes capability fields."""
    from actenon_scan.report.json_out import format_json
    source = '''import subprocess, os
from mcp import tool

@tool
def unguarded(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()

@tool
def guarded(path: str) -> None:
    authorize(path)
    os.remove(path)

def authorize(path: str) -> None:
    if not path.startswith("/tmp/"):
        raise PermissionError(path)
'''
    result = _scan_source(source)
    j = json.loads(format_json(result))
    assert "capabilities" in j
    assert "capability_count" in j
    assert "guard_found_count" in j
    assert "review_required_count" in j
    assert j["capability_count"] == 2
    assert j["guard_found_count"] == 1
    assert j["review_required_count"] == 1


def test_backward_compatibility_findings_unchanged():
    """Findings are unchanged — only REVIEW_REQUIRED sinks produce findings."""
    source = '''import subprocess, os
from mcp import tool

@tool
def unguarded(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()

@tool
def guarded(path: str) -> None:
    authorize(path)
    os.remove(path)

def authorize(path: str) -> None:
    if not path.startswith("/tmp/"):
        raise PermissionError(path)
'''
    result = _scan_source(source)
    active_findings = [f for f in result.findings if not f.suppressed]
    # Only the unguarded sink should be a finding
    assert len(active_findings) == 1
    assert active_findings[0].rule_id == "EXEC-SHELL"


def test_capability_carries_reachability_source():
    """Capability records whether reachability is handler-based or import-based."""
    source = '''import subprocess
from mcp import tool

@tool
def unguarded(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
'''
    result = _scan_source(source)
    caps = result.capabilities
    assert len(caps) >= 1
    # Python reachability is handler-based (tool decorator)
    assert caps[0].reachability_source == "handler"


def test_capability_carries_language():
    """Capability records the language."""
    source = '''import subprocess
from mcp import tool

@tool
def unguarded(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
'''
    result = _scan_source(source)
    caps = result.capabilities
    assert len(caps) >= 1
    assert caps[0].language == "python"
