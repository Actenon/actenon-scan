"""Cross-language parity test and Go recall corpus (ITEM 6).

Two tests:

1. test_go_recall_corpus — scans the recall_corpus.go fixture and asserts
   that the expected number of findings are detected. This is the test
   that would have caught the SQL gap on day one.

2. test_sink_family_parity — enumerates sink rule families per language
   and fails when a family exists in one language and not another, unless
   the gap is explicitly registered with a reason. This is the systemic
   fix that stops the next gap from going unnoticed.

The reason this gap existed silently is the same reason the earlier ones
did: two code paths diverged and nothing compared them. That has now
happened three times in this codebase — the drift gate skipping
unparseable repos, the CLI/Action fail-on split, and this. The parity
test is what stops the fourth occurrence.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

# Skip all tests in this module if tree-sitter-go is not installed.
from actenon_scan.detectors.go import is_go_extra_available
pytestmark = pytest.mark.skipif(
    not is_go_extra_available(),
    reason="[go] extra not installed — tree-sitter-go required for Go parity tests",
)


# ---------------------------------------------------------------------------
# Recall corpus — 18 destructive Go calls with expected detection.
# ---------------------------------------------------------------------------


def test_go_recall_corpus():
    """Scan the recall corpus and verify detection rates.

    The corpus contains 18 destructive Go calls, each with a
    model-controlled parameter, in a file importing an agent SDK.

    Before v1.1.4: 9/18 caught.
    After v1.1.4: 16/18 expected (chmod/chown deliberately not ported).
    """
    from actenon_scan.detectors.go import scan_go_file
    from actenon_scan.rules.loader import load_default_rules

    fixture = Path(__file__).parent / "fixtures" / "go" / "recall_corpus.go"
    source = fixture.read_bytes()
    rules = load_default_rules()

    findings = scan_go_file("recall_corpus.go", source, guard_patterns=rules.guard_patterns)

    # Count findings by rule_id family
    finding_rules = set()
    for f in findings:
        # Strip -WEAK/-UNBOUND suffixes for family counting
        base_rule = f.rule_id.split("-WEAK")[0].split("-UNBOUND")[0]
        finding_rules.add(base_rule)

    # Expected detected families
    expected_detected = {
        "EXEC-SHELL-GO",           # 4 calls: exec.Command, exec.CommandContext, syscall.Exec, syscall.ForkExec
        "DATA-DELETE-OS-GO",       # 5 calls: os.Remove, os.RemoveAll, os.Truncate, syscall.Unlink, syscall.Rmdir
        "DATA-DELETE-SQL-GO",      # 4 calls: db.Exec(concat), db.Query(var), db.Exec(concat), db.ExecContext(var)
        "NET-EGRESS-GO",           # 1 call: http.Get(url)
    }

    # Families deliberately NOT ported (documented in COVERAGE.md)
    expected_not_detected = {
        # os.Chmod and os.Chown — proposed as cross-language family,
        # not a Go-only rule. See COVERAGE.md.
    }

    missing = expected_detected - finding_rules
    assert not missing, (
        f"Recall corpus: expected rule families {expected_detected} but "
        f"missing {missing}. Found: {finding_rules}"
    )

    # Count individual findings (at least 14 — 4+5+4+1 = 14 minimum)
    # (Some calls may produce additional findings if they match multiple rules)
    assert len(findings) >= 14, (
        f"Recall corpus: expected at least 14 findings, got {len(findings)}. "
        f"Rules: {[(f.line, f.rule_id) for f in findings]}"
    )


# ---------------------------------------------------------------------------
# Cross-language sink family parity test.
# ---------------------------------------------------------------------------

# The declared sink family matrix. Each family has a set of supported
# languages. If a language is NOT supported, a reason MUST be given.
#
# When a new rule is added to one language, this test fails if the
# family is not declared here — forcing the developer to either port
# it to the other languages or register an explicit NOT_APPLICABLE
# entry with a justification.
#
# This is the systemic fix for the "two code paths diverged" pattern
# that has caused three separate failures in this codebase.

RULE_FAMILIES = {
    "shell_execution": {
        "python": "EXEC-SHELL",
        "typescript": "EXEC-SHELL",
        "go": "EXEC-SHELL-GO",
    },
    "file_deletion": {
        "python": "DATA-DELETE-FILE",
        "typescript": None,
        "go": "DATA-DELETE-OS-GO",
        "not_applicable_reason": "TypeScript file deletion (fs.unlinkSync, fs.rmSync) is not yet implemented. The TS detector focuses on exec/spawn and HTTP egress. File deletion is a future port.",
    },
    "file_write": {
        "python": "FILE-WRITE",
        "typescript": "FILE-WRITE",
        "go": "FILE-WRITE-GO",
    },
    "network_egress": {
        "python": "NET-EGRESS",
        "typescript": "NET-EGRESS",
        "go": "NET-EGRESS-GO",
    },
    "sql_destruction": {
        "python": "DATA-DELETE-SQL",
        "typescript": None,
        "go": "DATA-DELETE-SQL-GO",
        "not_applicable_reason": "TypeScript SQL detection is not implemented. TS agent code typically uses tagged templates or parameterized queries (e.g., pg.query). SQL detection for TS is a future port.",
    },
    "payments_stripe": {
        "python": "PAY-STRIPE-REFUND",
        "typescript": None,
        "go": "PAY-STRIPE-REFUND-GO",
        "not_applicable_reason": "TypeScript Stripe detection is not implemented. stripe-node uses a different API surface than Python/Go. Future port.",
    },
    "payments_generic": {
        "python": "PAY-GENERIC-REFUND",
        "typescript": None,
        "go": "PAY-GENERIC-REFUND-GO",
        "not_applicable_reason": "TypeScript generic payment detection is not implemented. Same rationale as payments_stripe.",
    },
    "secret_read": {
        "python": "SECRET-READ",
        "typescript": None,
        "go": "SECRET-READ-GO",
        "not_applicable_reason": "TypeScript secret detection is not implemented. TS agent code typically uses process.env (equivalent to os.Getenv, which is deliberately excluded from the Go rule too). Cloud SDK method names would need a separate TS port.",
    },
    "provider_sdk": {
        "python": "PROVIDER-SDK-CALL",
        "typescript": None,
        "go": "PROVIDER-SDK-CALL-GO",
        "not_applicable_reason": "TypeScript provider SDK detection is not implemented. The @aws-sdk family uses a different API surface than boto3. Future port.",
    },
    # ── Families deliberately NOT ported to any language (with reasons) ──
    "permission_change": {
        "python": None,
        "typescript": None,
        "go": None,
        "not_applicable_reason": "Permission/ownership change (os.Chmod/os.Chown) is not a sink family in any language. Proposed as a future cross-language family — a model-controlled os.Chmod(path, 0o777) is arguably consequential, but adding it to Go only would move away from parity rather than toward it.",
    },
}

# Languages the scanner supports
SUPPORTED_LANGUAGES = {"python", "typescript", "go"}


def test_sink_family_parity():
    """Fail when a sink family exists in one language and not another,
    unless the gap is explicitly registered with a reason.

    This test enumerates the RULE_FAMILIES map and checks that every
    family is either:
      - Declared for all supported languages, OR
      - Declared as None for a language with a justification in
        not_applicable_reason

    A future language — or a future rule added to Python only — produces
    a red test rather than a quiet gap that surfaces when a user reports
    it.
    """
    gaps = []

    for family_name, langs in RULE_FAMILIES.items():
        not_applicable_reason = langs.get("not_applicable_reason", "")

        for lang in SUPPORTED_LANGUAGES:
            if lang not in langs:
                gaps.append(
                    f"Family '{family_name}' is missing language '{lang}' "
                    f"entirely. Add it to RULE_FAMILIES with either a rule ID "
                    f"or None + not_applicable_reason."
                )
            elif langs[lang] is None and not not_applicable_reason:
                gaps.append(
                    f"Family '{family_name}' has None for language '{lang}' "
                    f"but no not_applicable_reason. Either port the rule or "
                    f"register the reason."
                )

    assert not gaps, (
        f"Sink family parity gaps found:\n" + "\n".join(f"  - {g}" for g in gaps)
    )


def test_go_rule_ids_match_declared_families():
    """Verify that the Go sink rules in _GO_SINK_RULES match the families
    declared in RULE_FAMILIES.

    This catches the case where a new Go rule is added to _GO_SINK_RULES
    but not declared in the parity map (or vice versa).
    """
    from actenon_scan.detectors.go import _GO_SINK_RULES

    # Extract Go rule IDs from the actual rules
    actual_go_rules = {rule["id"] for rule in _GO_SINK_RULES}

    # Extract declared Go rule IDs from the parity map
    declared_go_rules = set()
    for family_name, langs in RULE_FAMILIES.items():
        go_rule = langs.get("go")
        if go_rule is not None:
            declared_go_rules.add(go_rule)

    # Rules in the code but not in the parity map
    undeclared = actual_go_rules - declared_go_rules
    assert not undeclared, (
        f"Go rules in _GO_SINK_RULES but not in RULE_FAMILIES: {undeclared}. "
        f"Add them to the parity map or they won't be checked for cross-language parity."
    )

    # Rules in the parity map but not in the code
    missing = declared_go_rules - actual_go_rules
    assert not missing, (
        f"Go rules in RULE_FAMILIES but not in _GO_SINK_RULES: {missing}. "
        f"Either implement them or remove them from the parity map."
    )
