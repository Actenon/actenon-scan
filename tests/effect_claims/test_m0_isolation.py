"""M0: introducing the claim layer changes nothing that exists.

Covers required M0 test 10: existing findings are unchanged by merely
introducing the M0 types. Also pins the M0 boundary: no existing module
imports the claim layer, the claim layer depends on nothing but the standard
library and two existing enums, no constructor needs a finding or a rule, and
no provider-specific knowledge is present.
"""

from __future__ import annotations

import ast
import inspect
import json
import re
import subprocess
import sys
import typing
from pathlib import Path

import pytest

import actenon_scan.effects as effects

REPO = Path(__file__).resolve().parents[2]
PACKAGE = REPO / "actenon_scan"
EFFECTS = PACKAGE / "effects"
FIXTURE = REPO / "tests" / "fixtures" / "vulnerable"
ALLOWED_EXISTING_IMPORTS = {"actenon_scan.repository.symbol_index", "actenon_scan.repository.taint"}
# M1 adds one explicit integration consumer. All legacy modules and the
# frozen effects package retain their original isolation guarantees.
M1_CONSUMERS = {PACKAGE / "claim_genesis.py"}


def module_name(path: Path) -> str:
    parts = path.relative_to(REPO).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    package = module_name(path) if path.name == "__init__.py" else module_name(path).rpartition(".")[0]
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                anchor = package.split(".")
                anchor = anchor[: len(anchor) - (node.level - 1)]
                base = ".".join(anchor + ([base] if base else []))
            found.add(base)
            found.update(f"{base}.{alias.name}" for alias in node.names)
    return found


def test_10_no_existing_module_imports_the_claim_layer():
    offenders = []
    for path in PACKAGE.rglob("*.py"):
        if EFFECTS in path.parents or path in M1_CONSUMERS:
            continue
        if any(m == "actenon_scan.effects" or m.startswith("actenon_scan.effects.") for m in imported_modules(path)):
            offenders.append(str(path.relative_to(REPO)))
    assert offenders == []


def test_10_no_existing_module_mentions_the_claim_layer_dynamically():
    pattern = re.compile(r"actenon_scan\.effects|['\"]effects['\"]")
    offenders = [str(p.relative_to(REPO)) for p in PACKAGE.rglob("*.py")
                 if EFFECTS not in p.parents and p not in M1_CONSUMERS
                 and pattern.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


def test_10_claim_layer_depends_only_on_stdlib_and_two_existing_enums():
    stdlib = sys.stdlib_module_names | {"__future__"}
    for path in EFFECTS.glob("*.py"):
        for m in imported_modules(path):
            top = m.split(".")[0]
            if top in stdlib:
                continue
            assert top == "actenon_scan", f"{path.name} imports third-party {m}"
            if m == "actenon_scan.effects" or m.startswith("actenon_scan.effects."):
                continue
            owner = next((a for a in ALLOWED_EXISTING_IMPORTS if m == a or m.startswith(a + ".")), None)
            assert owner is not None, f"{path.name} imports existing module {m}"


def run_scan(import_effects_first: bool) -> dict:
    script = (
        "import json, sys\n"
        + ("import actenon_scan.effects\n" if import_effects_first else "")
        + "from actenon_scan.engine import scan_path\n"
        "from actenon_scan.report.json_out import format_json\n"
        f"out = format_json(scan_path({str(FIXTURE)!r}))\n"
        "loaded = 'actenon_scan.effects' in sys.modules\n"
        "print(json.dumps({'report': out, 'effects_loaded': loaded}))\n"
    )
    proc = subprocess.run([sys.executable, "-c", script], cwd=REPO, capture_output=True, text=True, timeout=300,
                          check=True)
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def scans():
    return run_scan(False), run_scan(True)


def test_10_findings_are_identical_with_and_without_the_claim_layer(scans):
    without, with_effects = scans
    assert with_effects["effects_loaded"] is True
    assert with_effects["report"] == without["report"]


def test_10_the_fixture_actually_produces_findings(scans):
    report = json.loads(scans[0]["report"])
    findings = report["findings"]
    assert findings, "the invariance check is vacuous without findings"
    rules = {f["rule_id"] for f in findings}
    assert {"EXEC-SHELL", "FILE-WRITE"} <= rules
    assert all("severity" in f for f in findings)


def test_10_a_normal_scan_never_loads_the_claim_layer(scans):
    assert scans[0]["effects_loaded"] is False


# ========================================= no finding, rule or provider bias


def public_types():
    return [obj for name, obj in vars(effects).items()
            if not name.startswith("_") and inspect.isclass(obj) and obj.__module__.startswith("actenon_scan.effects")]


def test_no_constructor_accepts_or_requires_a_finding():
    for cls in public_types():
        if not hasattr(cls, "__dataclass_fields__"):
            continue
        hints = typing.get_type_hints(cls, globalns=vars(sys.modules[cls.__module__]))
        for name in cls.__dataclass_fields__:
            text = f"{name} {hints.get(name, '')}".lower()
            assert "finding" not in text, f"{cls.__name__}.{name}"
            assert "sinkfinding" not in text.replace("_", ""), f"{cls.__name__}.{name}"


def test_no_constructor_requires_a_rule():
    for cls in public_types():
        if not hasattr(cls, "__dataclass_fields__"):
            continue
        for name, param in inspect.signature(cls).parameters.items():
            if "rule" in name.lower():
                assert param.default is not inspect.Parameter.empty, f"{cls.__name__}.{name} is required"


def test_claim_layer_imports_no_finding_or_rule_types():
    for path in EFFECTS.glob("*.py"):
        for m in imported_modules(path):
            assert not m.startswith(("actenon_scan.engine", "actenon_scan.detectors", "actenon_scan.rules",
                                     "actenon_scan.capability", "actenon_scan.report")), f"{path.name}: {m}"


PROVIDER_TERMS = (
    "stripe", "boto", "botocore", "aws", "dynamodb", "s3", "sqs", "sns", "lambda_", "azure", "gcp", "google",
    "firebase", "supabase", "cloudflare", "twilio", "sendgrid", "mailgun", "slack", "discord", "openai",
    "anthropic", "postgres", "psycopg", "mysql", "sqlalchemy", "mongodb", "pymongo", "redis", "kafka",
    "salesforce", "shopify", "paypal", "octokit", "pygithub", "github", "gitlab", "vercel", "netlify",
    "heroku", "kubernetes", "terraform",
)
FROZEN_VOCABULARY_ALLOWLIST = {"github_rest_mutation", "GITHUB_REST_MUTATION"}


def test_no_provider_specific_knowledge_in_the_claim_layer():
    hits = []
    for path in EFFECTS.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in FROZEN_VOCABULARY_ALLOWLIST:
            text = text.replace(token, "")
        for term in PROVIDER_TERMS:
            if re.search(rf"(?<![a-z]){re.escape(term)}(?![a-z])", text, re.IGNORECASE):
                hits.append(f"{path.name}: {term}")
    assert hits == []


def test_no_resource_boundary_field_was_introduced():
    for path in EFFECTS.glob("*.py"):
        assert "resource_boundary" not in path.read_text(encoding="utf-8"), path.name


def test_package_is_registered_for_distribution():
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert '"actenon_scan.effects"' in text
