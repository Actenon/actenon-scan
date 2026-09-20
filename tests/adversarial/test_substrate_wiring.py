"""Adversarial tests for substrate-module wiring (Task 5-A2).

These tests prove that the three substrate modules
(``guard_resolution``, ``guard_semantics``, ``authority_binding``)
now AFFECT the scan's output: every existing per-file finding or
capability that has a guard nearby gets RICHER evidence in its
``reachability_reason`` field — appended, never replacing.

Hostile invariants pinned by these tests (the brief's
NON-NEGOTIABLE constraints):

- AUTHENTICATION and VALIDATION guards MUST be explicitly labelled
  "does NOT authorize this action" in the evidence — never silently
  treated as authorizing an action like a refund or shell exec.

- The action-label soundness gate (inside compare_authority_to_sink)
  refuses to bind an ``authorize_read`` authority to a ``refund``
  sink even when parameters match — the action labels differ.

- The substrate pass NEVER suppresses or downgrades an existing
  finding — the scan WITH substrate wiring produces a SUPERSET of
  findings vs the scan WITHOUT.

- Best-effort: the substrate pass must NEVER crash the scan, even
  on dynamic dispatch (``getattr(x, 'guard'); fn()``) that the
  substrate modules cannot resolve.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from actenon_scan.engine import scan_path


def _write_repo(files: dict[str, str]) -> str:
    """Write a temp repo and return its root path.

    Mirrors the helper in tests/adversarial/test_transitive_reachability.py.
    """
    tmp = tempfile.mkdtemp()
    for rel, src in files.items():
        p = Path(tmp) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    return tmp


def _all_reasons(result) -> list[str]:
    """Collect reachability_reason strings from BOTH findings and
    capabilities — substrate evidence may land on either, since the
    per-file scan suppresses assert-style-guarded sinks into a
    Capability (state=GUARD_FOUND) rather than a Finding.
    """
    return [
        (f.reachability_reason or "")
        for f in list(result.findings) + list(result.capabilities)
    ]


class SubstrateWiringTests(unittest.TestCase):
    """Six adversarial tests proving the substrate modules affect output."""

    # ------------------------------------------------------------------
    # 1. Cross-file guard resolution — evidence surfaces the qname
    #    and the ASSERT style of a guard imported from another file.
    # ------------------------------------------------------------------
    def test_cross_file_guard_evidence_in_finding(self) -> None:
        """A guard imported from another file (``from security import
        require_admin``) is resolved cross-file; the finding's
        reachability_reason contains the cross-file qname and the
        ASSERT style classification.
        """
        root = _write_repo({
            "security.py": (
                "def require_admin(user):\n"
                "    if user != 'admin':\n"
                "        raise PermissionError('admin required')\n"
            ),
            "main.py": (
                "from langchain.tools import tool\n"
                "from security import require_admin\n"
                "import subprocess\n"
                "\n"
                "@tool\n"
                "def f(x):\n"
                "    require_admin(x)\n"
                "    subprocess.run(x, shell=True)\n"
            ),
        })
        result = scan_path(root, repository_analysis=True, cache=None)
        # Scan must complete without analysis errors.
        self.assertEqual(
            result.analysis_errors, [],
            f"Scan should not error: {result.analysis_errors}",
        )
        # Aggregate reachability_reason across findings + capabilities.
        reasons = _all_reasons(result)
        self.assertTrue(
            reasons,
            "No findings or capabilities produced — substrate wiring "
            "had nothing to augment.",
        )
        # At least one reason must contain all three required substrings.
        ok = [
            r for r in reasons
            if "cross-file guard" in r
            and "ASSERT" in r
            and "security.require_admin" in r
        ]
        self.assertTrue(
            ok,
            "Cross-file guard evidence not surfaced. Reasons observed:\n  "
            + "\n  ".join(repr(r) for r in reasons),
        )

    # ------------------------------------------------------------------
    # 2. AUTHENTICATION guards MUST be explicitly labelled as
    #    "does NOT authorize this action" — the CRITICAL hostile
    #    invariant. ``authenticate(user)`` does NOT authorize a
    #    ``subprocess.run`` sink.
    # ------------------------------------------------------------------
    def test_authentication_guard_evidence_says_not_authorization(self) -> None:
        """``def f(user): authenticate(user); subprocess.run(user, shell=True)``
        — the finding's evidence contains "AUTHENTICATION" AND
        "does NOT authorize" (explicit hostile-invariant label).
        """
        root = _write_repo({
            "main.py": (
                "from langchain.tools import tool\n"
                "import subprocess\n"
                "\n"
                "@tool\n"
                "def f(user):\n"
                "    authenticate(user)\n"
                "    subprocess.run(user, shell=True)\n"
                "\n"
                "def authenticate(user):\n"
                "    if not user:\n"
                "        raise PermissionError('not authed')\n"
            ),
        })
        result = scan_path(root, repository_analysis=True, cache=None)
        self.assertEqual(
            result.analysis_errors, [],
            f"Scan should not error: {result.analysis_errors}",
        )
        reasons = _all_reasons(result)
        self.assertTrue(reasons, "No findings or capabilities produced.")
        # The CRITICAL hostile invariant: AUTHENTICATION MUST be labelled
        # "does NOT authorize this action".
        ok = [
            r for r in reasons
            if "AUTHENTICATION" in r and "does NOT authorize" in r
        ]
        self.assertTrue(
            ok,
            "AUTHENTICATION guard was not explicitly labelled as NOT "
            "authorizing the action. Reasons observed:\n  "
            + "\n  ".join(repr(r) for r in reasons),
        )

    # ------------------------------------------------------------------
    # 3. AUTHORIZATION + BOUND — matching parameters prove the
    #    authority call plumbing binds to the sink's parameters.
    # ------------------------------------------------------------------
    def test_authorization_guard_evidence_in_finding(self) -> None:
        """``def f(cust): authorize_refund(cust); refund(cust)`` — the
        finding's evidence contains "AUTHORIZATION" AND "BOUND" (the
        authority parameter 'cust' traces to the sink's parameter 'cust').
        """
        root = _write_repo({
            "main.py": (
                "from langchain.tools import tool\n"
                "\n"
                "@tool\n"
                "def f(cust):\n"
                "    authorize_refund(cust)\n"
                "    refund(cust)\n"
                "\n"
                "def authorize_refund(cust):\n"
                "    if not cust:\n"
                "        raise PermissionError('not authorized')\n"
            ),
        })
        result = scan_path(root, repository_analysis=True, cache=None)
        self.assertEqual(
            result.analysis_errors, [],
            f"Scan should not error: {result.analysis_errors}",
        )
        reasons = _all_reasons(result)
        self.assertTrue(reasons, "No findings or capabilities produced.")
        # AUTHORIZATION kind AND BOUND binding — both substrings present.
        ok = [
            r for r in reasons
            if "AUTHORIZATION" in r and "BOUND" in r
        ]
        self.assertTrue(
            ok,
            "AUTHORIZATION + BOUND evidence not surfaced. "
            "Reasons observed:\n  "
            + "\n  ".join(repr(r) for r in reasons),
        )

    # ------------------------------------------------------------------
    # 4. Wrong-action binding — ``authorize_read`` authority CANNOT
    #    bind to a ``refund`` sink, even when parameters match. The
    #    action-label soundness gate fires FIRST inside
    #    compare_authority_to_sink; the evidence must say "UNBOUND"
    #    AND "differs from sink action".
    # ------------------------------------------------------------------
    def test_wrong_action_binding_evidence_in_finding(self) -> None:
        """``def f(cust): authorize_read(cust); refund(cust, amt)`` —
        the finding's evidence contains "UNBOUND" AND
        "differs from sink action" (the authority is for a different
        action than the sink performs).
        """
        root = _write_repo({
            "main.py": (
                "from langchain.tools import tool\n"
                "\n"
                "@tool\n"
                "def f(cust, amt):\n"
                "    authorize_read(cust)\n"
                "    refund(cust, amt)\n"
                "\n"
                "def authorize_read(cust):\n"
                "    if not cust:\n"
                "        raise PermissionError('not authorized')\n"
            ),
        })
        result = scan_path(root, repository_analysis=True, cache=None)
        self.assertEqual(
            result.analysis_errors, [],
            f"Scan should not error: {result.analysis_errors}",
        )
        reasons = _all_reasons(result)
        self.assertTrue(reasons, "No findings or capabilities produced.")
        # Wrong-action binding: UNBOUND AND "differs from sink action".
        ok = [
            r for r in reasons
            if "UNBOUND" in r and "differs from sink action" in r
        ]
        self.assertTrue(
            ok,
            "Wrong-action binding UNBOUND evidence not surfaced. "
            "Reasons observed:\n  "
            + "\n  ".join(repr(r) for r in reasons),
        )

    # ------------------------------------------------------------------
    # 5. Substrate wiring DOES NOT suppress findings — the scan WITH
    #    substrate wiring produces a SUPERSET of findings vs scan
    #    WITHOUT (no findings are removed). The substrate modules only
    #    ADD evidence; they never remove findings.
    # ------------------------------------------------------------------
    def test_substrate_wiring_does_not_suppress_findings(self) -> None:
        """The substrate wiring must NEVER suppress or downgrade an
        existing finding. Every (file, line, rule_id) tuple present in
        ``scan_path(repository_analysis=False)`` MUST also be present
        in ``scan_path(repository_analysis=True)``.
        """
        # Use the Objective-2 transitive-reach scenario so the with-repo
        # scan has at least one finding (a transitively-reachable sink
        # the per-file scan missed).
        root = _write_repo({
            "agent.py": (
                "from langchain.tools import tool\n"
                "import subprocess\n"
                "\n"
                "@tool\n"
                "def agent_action(x):\n"
                "    layer_one(x)\n"
                "\n"
                "def layer_one(x):\n"
                "    layer_two(x)\n"
                "\n"
                "def layer_two(x):\n"
                "    subprocess.run(x, shell=True)\n"
            ),
        })
        result_without = scan_path(
            root, repository_analysis=False, cache=None,
        )
        result_with = scan_path(
            root, repository_analysis=True, cache=None,
        )
        # Both scans must complete without analysis errors.
        self.assertEqual(
            result_without.analysis_errors, [],
            f"Without-repo scan errored: {result_without.analysis_errors}",
        )
        self.assertEqual(
            result_with.analysis_errors, [],
            f"With-repo scan errored: {result_with.analysis_errors}",
        )
        without_keys = {
            (f.file, f.line, f.rule_id) for f in result_without.findings
        }
        with_keys = {
            (f.file, f.line, f.rule_id) for f in result_with.findings
        }
        missing = without_keys - with_keys
        self.assertEqual(
            missing, set(),
            f"Substrate wiring suppressed existing findings: {missing}",
        )

    # ------------------------------------------------------------------
    # 6. Dynamic dispatch — ``fn = getattr(x, 'guard'); fn()`` — the
    #    substrate modules cannot resolve the dispatch. The scan MUST
    #    complete without crashing; the finding's evidence may or may
    #    not include substrate info (the dispatch is UNRESOLVED), but
    #    the scan completes.
    # ------------------------------------------------------------------
    def test_substrate_wiring_does_not_crash_on_dynamic_dispatch(self) -> None:
        """``def f(): fn = getattr(x, 'guard'); fn(); subprocess.run('ls',
        shell=True)`` — the scan must NOT crash on the dynamic
        dispatch. The substrate pass is best-effort; any failure MUST
        be silently skipped (the repo layer must remain non-fatal).
        """
        root = _write_repo({
            "main.py": (
                "from langchain.tools import tool\n"
                "import subprocess\n"
                "\n"
                "@tool\n"
                "def f():\n"
                "    fn = getattr(x, 'guard')\n"
                "    fn()\n"
                "    subprocess.run('ls', shell=True)\n"
            ),
        })
        result = scan_path(root, repository_analysis=True, cache=None)
        # CRITICAL: scan completes without analysis errors.
        self.assertEqual(
            result.analysis_errors, [],
            f"Scan crashed on dynamic dispatch: {result.analysis_errors}",
        )
        # The subprocess sink must still be reported (per-file scan
        # flags it; substrate wiring does not suppress).
        self.assertTrue(
            any("subprocess" in (f.call_text or "") for f in result.findings),
            f"subprocess.run finding not present after dynamic-dispatch "
            f"scan. Findings: {result.findings}",
        )


if __name__ == "__main__":
    unittest.main()
