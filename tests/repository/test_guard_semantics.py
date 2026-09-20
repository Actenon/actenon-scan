"""Unit tests for the semantic guard taxonomy (Slice 5, Objective 5).

These tests pin the CRITICAL hostile-test invariant from the brief:

    A call such as ``authenticate(user)`` must NOT automatically prove
    ``user is authorized to refund £10,000``. A call such as
    ``validate_email(addr)`` must NOT automatically prove
    ``sending external email is authorized``.

Concretely: AUTHENTICATION and VALIDATION must NEVER have
``is_action_authorization == True``.
"""
from __future__ import annotations

import ast
import unittest

from actenon_scan.repository.guard_semantics import (
    GuardClassification,
    GuardKind,
    action_authorization_strength,
    classify_guard_call,
    classify_guard_name,
)


def _first_call(src: str) -> ast.Call:
    """Parse ``src`` and return the first ``ast.Call`` node encountered."""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            return node
    raise AssertionError(f"no ast.Call found in {src!r}")


class GuardSemanticsTests(unittest.TestCase):
    # ------------------------------------------------------------------
    # Hostile-test invariant (the brief's central requirement)
    # ------------------------------------------------------------------

    def test_authenticate_is_authentication_not_authorization(self) -> None:
        # authenticate(user) → AUTHENTICATION, is_action_authorization=False
        call = _first_call("authenticate(user)\n")
        c = classify_guard_call(call)
        self.assertEqual(c.kind, GuardKind.AUTHENTICATION)
        self.assertFalse(
            c.is_action_authorization,
            "authenticate() must NOT be treated as action authorization",
        )
        self.assertTrue(
            c.is_identity_only,
            "authenticate() proves identity only, not authorization",
        )

    def test_validate_email_is_validation_not_authorization(self) -> None:
        # validate_email(addr) → VALIDATION, is_action_authorization=False
        call = _first_call("validate_email(addr)\n")
        c = classify_guard_call(call)
        self.assertEqual(c.kind, GuardKind.VALIDATION)
        self.assertFalse(
            c.is_action_authorization,
            "validate_email() must NOT be treated as action authorization",
        )
        self.assertFalse(c.is_identity_only)

    # ------------------------------------------------------------------
    # Positive authorization classifications
    # ------------------------------------------------------------------

    def test_authorize_refund_is_authorization(self) -> None:
        # authorize_refund(user, amount) → AUTHORIZATION, is_action_authorization=True
        call = _first_call("authorize_refund(user, amount)\n")
        c = classify_guard_call(call)
        self.assertEqual(c.kind, GuardKind.AUTHORIZATION)
        self.assertTrue(c.is_action_authorization)
        self.assertFalse(c.is_identity_only)

    def test_require_admin_is_authorization(self) -> None:
        # require_admin(user) → AUTHORIZATION (NOT authentication — the
        # `require_` prefix is authorization when the suffix isn't
        # login/session/pcc/human).
        call = _first_call("require_admin(user)\n")
        c = classify_guard_call(call)
        self.assertEqual(c.kind, GuardKind.AUTHORIZATION)
        self.assertTrue(c.is_action_authorization)
        self.assertFalse(c.is_identity_only)

    def test_check_permission_is_authorization(self) -> None:
        # check_permission(user, "read") → AUTHORIZATION (NOT VALIDATION —
        # even though it starts with `check_`, the `_permission` suffix
        # overrides).
        call = _first_call('check_permission(user, "read")\n')
        c = classify_guard_call(call)
        self.assertEqual(c.kind, GuardKind.AUTHORIZATION)
        self.assertTrue(c.is_action_authorization)

    # ------------------------------------------------------------------
    # Other kinds
    # ------------------------------------------------------------------

    def test_sanitize_input_is_sanitization(self) -> None:
        # sanitize_input(x) → SANITIZATION (NOT validation — sanitize is
        # SANITIZATION, the brief's "split" note resolves in favour of
        # SANITIZATION per this test).
        call = _first_call("sanitize_input(x)\n")
        c = classify_guard_call(call)
        self.assertEqual(c.kind, GuardKind.SANITIZATION)
        self.assertFalse(c.is_action_authorization)
        self.assertFalse(c.is_identity_only)

    def test_external_execution_is_human_approval(self) -> None:
        # external_execution(True) (as a function call) → HUMAN_APPROVAL
        call = _first_call("external_execution(True)\n")
        c = classify_guard_call(call)
        self.assertEqual(c.kind, GuardKind.HUMAN_APPROVAL)
        self.assertFalse(c.is_action_authorization)
        self.assertFalse(c.is_identity_only)

    def test_verify_pccb_is_capability_proof(self) -> None:
        # verify_pccb(action, capability) → CAPABILITY_PROOF
        call = _first_call("verify_pccb(action, capability)\n")
        c = classify_guard_call(call)
        self.assertEqual(c.kind, GuardKind.CAPABILITY_PROOF)
        self.assertTrue(c.is_action_authorization)
        self.assertFalse(c.is_identity_only)

    def test_rate_limit_is_rate_limit(self) -> None:
        # rate_limit(user) → RATE_LIMIT
        call = _first_call("rate_limit(user)\n")
        c = classify_guard_call(call)
        self.assertEqual(c.kind, GuardKind.RATE_LIMIT)
        self.assertFalse(c.is_action_authorization)

    def test_unknown_name_is_unknown(self) -> None:
        # do_thing() → UNKNOWN_GUARD
        call = _first_call("do_thing()\n")
        c = classify_guard_call(call)
        self.assertEqual(c.kind, GuardKind.UNKNOWN_GUARD)
        self.assertFalse(c.is_action_authorization)
        self.assertFalse(c.is_identity_only)

    # ------------------------------------------------------------------
    # action_authorization_strength
    # ------------------------------------------------------------------

    def test_action_authorization_strength_for_authentication_is_none(
        self,
    ) -> None:
        c = classify_guard_name("authenticate")
        self.assertEqual(c.kind, GuardKind.AUTHENTICATION)
        self.assertEqual(action_authorization_strength(c), "none")

    def test_action_authorization_strength_for_authorization_is_strong(
        self,
    ) -> None:
        c = classify_guard_name("authorize_refund")
        self.assertEqual(c.kind, GuardKind.AUTHORIZATION)
        self.assertEqual(action_authorization_strength(c), "strong")

    # ------------------------------------------------------------------
    # Direct call-node classification via classify_guard_call
    # ------------------------------------------------------------------

    def test_call_node_classification_works(self) -> None:
        # Verify classify_guard_call works on ast.Call directly and
        # returns a GuardClassification with consistent fields.
        call = _first_call("authorize_refund(user, amount)\n")
        c = classify_guard_call(call)
        self.assertIsInstance(c, GuardClassification)
        self.assertEqual(c.kind, GuardKind.AUTHORIZATION)
        self.assertTrue(c.is_action_authorization)
        self.assertFalse(c.is_identity_only)
        self.assertIsInstance(c.evidence, str)
        self.assertIn("authorize", c.evidence)

        # And via the Attribute-call form (self.authorize_refund(...)):
        call_attr = _first_call("self.authorize_refund(user, amount)\n")
        c_attr = classify_guard_call(call_attr)
        self.assertEqual(c_attr.kind, GuardKind.AUTHORIZATION)
        self.assertTrue(c_attr.is_action_authorization)


if __name__ == "__main__":
    unittest.main()
