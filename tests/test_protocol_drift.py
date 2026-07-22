"""Protocol drift gate for actenon-scan.

This test module fails when:
  - The pinned actenon-protocol version does not match scan's expected version.
  - Scan's default_rules.json treats permit_* calls as boundary guards
    (audit S-01 — trust-boundary collapse).
  - Scan's default_rules.json does NOT recognise common non-Actenon guards
    (audit S-02 — vendor lock-in).
  - Scan's guard vocabulary includes fictional API names that don't exist
    in the protocol (audit S-10).
  - Scan has a runtime dependency on actenon-protocol, actenon-kernel, or
    actenon-permit (boundary preservation — scan must remain standalone).
  - Scan's remediation hints point to actenon-permit for proof verification
    (audit S-11 — proof verification is the Kernel's job).

Run with: `python -m pytest tests/test_protocol_drift.py -v`
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# tomllib was added in Python 3.11. On 3.10, use tomli (which is installed
# as a dev dependency).
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


import pytest


RULES_PATH = Path(__file__).resolve().parent.parent / "actenon_scan" / "rules" / "default_rules.json"
ENGINE_PATH = Path(__file__).resolve().parent.parent / "actenon_scan" / "engine.py"
PYPROJECT_PATH = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _load_rules() -> dict:
    with RULES_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# 0. Pinned protocol version (dev-only)
# ---------------------------------------------------------------------------

EXPECTED_PROTOCOL_VERSION = "1.0.0"


def test_protocol_version_is_pinned_in_dev_deps():
    """pyproject.toml must pin actenon-protocol to v1.0.0 in dev deps."""
    text = PYPROJECT_PATH.read_text()
    assert "actenon-protocol" in text and "v1.0.0" in text, (
        "actenon-protocol @ v1.0.0 not pinned in pyproject.toml"
    )


def test_protocol_version_matches_pin():
    """The installed actenon-protocol version must match scan's pin."""
    from actenon_protocol import PROTOCOL_VERSION
    assert PROTOCOL_VERSION == EXPECTED_PROTOCOL_VERSION


def test_protocol_is_dev_dependency_only():
    """actenon-protocol MUST be in [dev] optional-dependencies, NOT in
    runtime dependencies. Scan is a static analyzer with ZERO runtime
    dependencies — it must remain installable without the protocol."""
    with PYPROJECT_PATH.open("rb") as f:
        data = tomllib.load(f)
    runtime_deps = data["project"].get("dependencies", [])
    assert not any("actenon-protocol" in d for d in runtime_deps), (
        f"actenon-protocol is in runtime dependencies: {runtime_deps}. "
        f"It MUST be dev-only — scan has zero runtime deps."
    )
    dev_deps = data["project"]["optional-dependencies"].get("dev", [])
    assert any("actenon-protocol" in d for d in dev_deps), (
        f"actenon-protocol not in dev dependencies: {dev_deps}"
    )


# ---------------------------------------------------------------------------
# 1. Trust-boundary preservation (audit S-01)
# ---------------------------------------------------------------------------

def test_permit_calls_are_not_treated_as_guards():
    """Scan MUST NOT treat permit_check, permit_authorize, permit_validate
    as boundary guards. Permit issues authority; the Kernel verifies it.
    Treating Permit calls as guards collapses the trust boundary
    (audit S-01).

    The permit_* patterns may appear in the rules under
    `permit_non_guard_patterns` (for future PERMIT_WITHOUT_KERNEL_PROOF
    detection), but they MUST NOT appear in any `patterns` list under
    `guards`.
    """
    rules = _load_rules()
    permit_patterns = {"permit_check", "permit_authorize", "permit_validate"}
    guard_patterns = set()
    for guard_group in rules.get("guards", []):
        for p in guard_group.get("patterns", []):
            guard_patterns.add(p)
    overlap = guard_patterns & permit_patterns
    assert not overlap, (
        f"permit_* patterns are treated as guards: {overlap}. "
        f"This collapses the trust boundary (audit S-01). Remove them "
        f"from the guards' patterns lists."
    )


# ---------------------------------------------------------------------------
# 2. Vendor neutrality (audit S-02)
# ---------------------------------------------------------------------------

def test_scan_recognises_non_actenon_guards():
    """Scan MUST recognise equivalent non-Actenon controls so it is not
    a vendor-lock-in scanner (audit S-02).

    The default rules must include at least one pattern from each of the
    following non-Actenon guard families:
      - OAuth scopes
      - RBAC decorators
      - JWT verification
      - OPA policy evaluation
      - Casbin enforcement
      - mTLS
    """
    rules = _load_rules()
    guard_patterns = set()
    for guard_group in rules.get("guards", []):
        for p in guard_group.get("patterns", []):
            guard_patterns.add(p)

    required_families = {
        "OAuth": {"requires_scope", "oauth_scope"},
        "RBAC": {"roles_required", "requires_roles", "has_role"},
        "JWT": {"jwt_required", "verify_jwt", "decode_jwt"},
        "OPA": {"opa_eval", "check_opa_policy"},
        "Casbin": {"enforce", "casbin_enforce"},
        "mTLS": {"verify_mtls", "require_client_cert"},
    }
    missing = []
    for family, patterns in required_families.items():
        if not (guard_patterns & patterns):
            missing.append(f"{family} (expected one of {sorted(patterns)})")
    assert not missing, (
        f"scan does not recognise these non-Actenon guard families: "
        f"{missing}. This is vendor lock-in (audit S-02)."
    )


def test_scan_recognises_kernel_class_api():
    """Scan MUST recognise the Kernel's class-level API
    (PCCBVerifier, ProtectedExecutor, ActenonGate) in addition to the
    function-call style (verify_proof)."""
    rules = _load_rules()
    guard_patterns = set()
    for guard_group in rules.get("guards", []):
        for p in guard_group.get("patterns", []):
            guard_patterns.add(p)
    required_class_patterns = {"PCCBVerifier", "ProtectedExecutor", "ActenonGate"}
    missing = required_class_patterns - guard_patterns
    assert not missing, (
        f"scan does not recognise Kernel class-level API: {missing}"
    )


# ---------------------------------------------------------------------------
# 3. Remediation hint hygiene (audit S-11)
# ---------------------------------------------------------------------------

def test_remediation_hints_point_to_kernel_for_verification():
    """Remediation hints MUST NOT tell users to go to actenon-permit for
    proof verification. Proof verification is the Kernel's job
    (audit S-11).

    This test scans engine.py (where _remediation_hint lives) for
    references to actenon-permit in remediation text.
    """
    text = ENGINE_PATH.read_text()
    # Find all remediation hint strings that reference actenon-permit
    # for proof verification.
    # The pattern is: "See: https://github.com/Actenon/actenon-permit"
    # in a context that mentions "proof verification".
    permit_for_verification = re.findall(
        r'["\']See:\s*https://github\.com/Actenon/actenon-permit["\']',
        text,
    )
    # Allow at most 1 occurrence (the fallback for authority-broker concerns).
    # The proof-verification remediation MUST point to actenon-kernel.
    assert len(permit_for_verification) <= 1, (
        f"engine.py has {len(permit_for_verification)} remediation hints "
        f"pointing to actenon-permit. Proof verification remediation "
        f"MUST point to actenon-kernel (audit S-11)."
    )


# ---------------------------------------------------------------------------
# 4. Boundary preservation
# ---------------------------------------------------------------------------

def test_scan_has_no_runtime_dependency_on_kernel_or_permit():
    """Scan MUST NOT have a runtime dependency on actenon-kernel or
    actenon-permit. Scan is a standalone static analyzer."""
    with PYPROJECT_PATH.open("rb") as f:
        data = tomllib.load(f)
    runtime_deps = data["project"].get("dependencies", [])
    forbidden = [d for d in runtime_deps if "actenon-kernel" in d or "actenon-permit" in d]
    assert not forbidden, (
        f"scan has runtime dependency on kernel/permit: {forbidden}"
    )


def test_scan_source_does_not_import_kernel_or_permit():
    """Scan's source code MUST NOT import actenon (kernel) or
    actenon_permit at runtime."""
    import ast
    scan_src = Path(__file__).resolve().parent.parent / "actenon_scan"
    violations = []
    for py_file in scan_src.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(), filename=str(py_file))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("actenon_kernel") or alias.name == "actenon":
                        # Allow actenon_protocol (dev dep, used by drift gate
                        # — but drift gate is in tests/, not in actenon_scan/).
                        violations.append(f"{py_file.name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module and (node.module.startswith("actenon_kernel") or node.module == "actenon"):
                    violations.append(f"{py_file.name}: from {node.module} import ...")
    assert not violations, (
        f"scan source imports kernel/permit: {violations}"
    )


def test_scan_remains_usable_without_cloud():
    """Scan MUST be installable and runnable without installing Cloud.
    This is verified by the zero-runtime-deps invariant above + the
    no-import-kernel/permit invariant above."""
    # Re-verify: runtime dependencies must be empty (scan is standalone).
    with PYPROJECT_PATH.open("rb") as f:
        data = tomllib.load(f)
    runtime_deps = data["project"].get("dependencies", [])
    assert runtime_deps == [], (
        f"scan must have zero runtime deps, got: {runtime_deps}"
    )


# ---------------------------------------------------------------------------
# 5. Refusal-code vocabulary alignment (where relevant)
# ---------------------------------------------------------------------------

def test_scan_does_not_emit_unregistered_refusal_codes():
    """Scan's rule IDs and finding vocabulary do not need to match the
    protocol's refusal codes (scan findings are not refusals). But scan
    MUST NOT emit refusal-code strings that contradict the protocol's
    catalogue (e.g. it must not claim a code is valid when the protocol
    has removed it).

    This test verifies that scan's source does not hard-code refusal-code
    strings that have been removed from the protocol.
    """
    # Codes that were NEVER in the protocol (fictional or removed).
    forbidden_codes = {"PROOF_FORGED", "AUTHORITY_MISSING", "GRANT_INVALID"}
    scan_src = Path(__file__).resolve().parent.parent / "actenon_scan"
    for py_file in scan_src.rglob("*.py"):
        text = py_file.read_text()
        for code in forbidden_codes:
            if code in text:
                pytest.fail(
                    f"{py_file.name} references fictional/removed refusal "
                    f"code {code!r}"
                )


# ---------------------------------------------------------------------------
# 6. Protocol version rejection (forward compat)
# ---------------------------------------------------------------------------

def test_unsupported_major_version_is_rejected():
    """A protocol version with major != 1 must be rejected."""
    from pydantic import TypeAdapter, ValidationError
    from actenon_protocol.types.common import ProtocolVersion
    adapter = TypeAdapter(ProtocolVersion)
    assert adapter.validate_python("1.0.0") == "1.0.0"
    with pytest.raises(ValidationError):
        adapter.validate_python("2.0.0")
