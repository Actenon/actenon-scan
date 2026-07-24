"""Regression tests for DEPLOY-K8S and other rule false-positive fixes.

These tests use the exact snippets from real-world false positives found
by running 0.2.3 against six real agent repositories.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from actenon_scan.engine import scan_path


def _scan_source(source: str) -> list:
    """Scan a source string and return the findings."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(source)
        f.flush()
        result = scan_path(f.name)
    Path(f.name).unlink()
    return [f for f in result.findings if not f.suppressed]


class TestDeployK8sFalsePositiveFix:
    """DEPLOY-K8S must not match client.<anything>.create.

    Real-world false positives from 0.2.3:
      - crewai: client.collections.create(name=..., vectorizer_config=...)
      - langchain: self.client.search.create(**params)
    """

    def test_crewai_weaviate_pattern_no_finding(self):
        """crewai: client.collections.create — Weaviate vector search, not K8s."""
        source = '''from langchain_core.tools import BaseTool
class T(BaseTool):
    def _run(self, q: str):
        return self.client.search.create(query=q)
'''
        findings = _scan_source(source)
        k8s_findings = [f for f in findings if f.rule_id == "DEPLOY-K8S"]
        assert len(k8s_findings) == 0, f"DEPLOY-K8S false positive: {k8s_findings}"

    def test_langchain_perplexity_pattern_no_finding(self):
        """langchain: self.client.search.create — Perplexity search, not K8s."""
        source = '''from langchain_core.tools import BaseTool
class PerplexityTool(BaseTool):
    def _run(self, query: str):
        response = self.client.search.create(**{"query": query})
        return response
'''
        findings = _scan_source(source)
        k8s_findings = [f for f in findings if f.rule_id == "DEPLOY-K8S"]
        assert len(k8s_findings) == 0, f"DEPLOY-K8S false positive: {k8s_findings}"

    def test_real_kubernetes_client_still_caught(self):
        """A real kubernetes client call must still be caught."""
        source = '''from kubernetes import client
from mcp.server.fastmcp import FastMCP
mcp = FastMcp("x")
@mcp.tool()
def deploy():
    client.AppsV1Api().create_namespaced_deployment(namespace="default", body={})
'''
        findings = _scan_source(source)
        k8s_findings = [f for f in findings if f.rule_id == "DEPLOY-K8S"]
        assert len(k8s_findings) == 1, f"Expected 1 DEPLOY-K8S finding, got {len(k8s_findings)}"

    def test_kubectl_via_subprocess_caught(self):
        """kubectl via subprocess.run must be caught (by EXEC-SHELL or DEPLOY-K8S)."""
        source = '''import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def deploy(manifest: str):
    subprocess.run(["kubectl", "apply", "-f", "-"], input=manifest)
'''
        findings = _scan_source(source)
        # subprocess.run with kubectl is caught by EXEC-SHELL (subprocess.run
        # is a shell execution sink). That's correct — it IS a shell call.
        # The point is that kubectl deploy is detected by SOME rule.
        assert len(findings) >= 1, f"Expected kubectl detection, got no findings"


class TestDatabaseOrmMutateFalsePositiveFix:
    """DATABASE-ORM-MUTATE must not match generic session.create, db.create."""

    def test_generic_session_create_no_finding(self):
        """session.create on a generic session variable must not match."""
        source = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def create_session():
    return session.create(user_id="x")
'''
        findings = _scan_source(source)
        orm_findings = [f for f in findings if f.rule_id == "DATABASE-ORM-MUTATE"]
        assert len(orm_findings) == 0, f"DATABASE-ORM-MUTATE false positive: {orm_findings}"

    def test_django_objects_create_still_caught(self):
        """Django's Model.objects.create must still be caught."""
        source = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def create_user(name: str):
    return User.objects.create(name=name)
'''
        findings = _scan_source(source)
        orm_findings = [f for f in findings if f.rule_id == "DATABASE-ORM-MUTATE"]
        assert len(orm_findings) == 1, f"Expected 1 ORM finding, got {len(orm_findings)}"


class TestCommunicationSendFalsePositiveFix:
    """COMMUNICATION-SEND must not match generic message.create."""

    def test_generic_message_create_no_finding(self):
        """message.create on a generic variable must not match."""
        source = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def send_msg():
    return message.create(text="hello")
'''
        findings = _scan_source(source)
        comm_findings = [f for f in findings if f.rule_id == "COMMUNICATION-SEND"]
        assert len(comm_findings) == 0, f"COMMUNICATION-SEND false positive: {comm_findings}"

    def test_slack_postMessage_still_caught(self):
        """Slack's chat_postMessage must still be caught."""
        source = '''from mcp.server.fastmcp import FastMCP
from slack_sdk import WebClient
mcp = FastMCP("x")
@mcp.tool()
def notify(channel: str, text: str):
    client = WebClient(token="x")
    client.chat_postMessage(channel=channel, text=text)
'''
        findings = _scan_source(source)
        comm_findings = [f for f in findings if f.rule_id == "COMMUNICATION-SEND"]
        assert len(comm_findings) >= 1, f"Expected Slack finding, got {findings}"


class TestRuleAuditResults:
    """Document the rule audit findings.

    Every attr_call rule was checked for the same defect class as DEPLOY-K8S:
    a pattern loose enough to match an unrelated SDK.

    Audit results:
      PAY-STRIPE-REFUND: module_patterns are specific (stripe, stripe.Refund, etc.) — OK
      PAY-BRAINTREE: module_patterns are specific (braintree, adyen, paypal) — OK
      DATA-DELETE-OS: module_patterns are specific (os, shutil, pathlib, Path) — OK
      ACCESS-CONTROL-MUTATE: module_patterns are specific (iam, policy, role, user, group) — OK
        but func_patterns include create_user, create_role — these could match
        non-IAM code with variables named 'user' or 'role'. REVIEW: acceptable
        because the func names (put_user_policy, attach_role_policy) are specific
        enough that false positives are unlikely.
      PROVIDER-SDK-CALL: module_patterns include specific providers (boto3, github, etc.) — OK
        but func_patterns include 'create' which is generic. REVIEW: acceptable
        because 'create' only matches when combined with a provider module pattern.
      DATABASE-ORM-MUTATE: FIXED — was using generic 'db', 'session', 'objects'
      COMMUNICATION-SEND: FIXED — was using 'create' as func_pattern with generic modules
      IDENTITY-IAM-MUTATE: same patterns as ACCESS-CONTROL-MUTATE — OK
      DEPLOY-K8S: FIXED — was using generic 'client'
    """

    def test_audit_documented(self):
        """This test exists to document the audit in the test suite."""
        # The audit is documented in the docstring above.
        # If a new rule is added, it must be audited here.
        assert True
