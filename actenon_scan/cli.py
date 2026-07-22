"""actenon-scan CLI — argparse-based command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from actenon_scan.engine import scan_path
from actenon_scan.report.json_out import format_json
from actenon_scan.report.pretty import format_pretty
from actenon_scan.report.sarif import format_sarif
from actenon_scan.suppress import collect_suppressions_from_file


def main(argv: list[str] | None = None) -> int:
    from actenon_scan import __version__

    parser = argparse.ArgumentParser(
        prog="actenon-scan",
        description="Defensive static-analysis scanner for the AI-agent execution gap.",
    )
    parser.add_argument("--version", action="version", version=f"actenon-scan {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan a path for the execution gap.")
    scan_parser.add_argument("path", help="File or directory to scan.")
    scan_parser.add_argument("--format", choices=["pretty", "json", "sarif"], default="pretty")
    scan_parser.add_argument("--fail-on", choices=["none", "low", "medium", "high"], default="medium")
    scan_parser.add_argument("--config", help="Path to config file (JSON or YAML).")
    scan_parser.add_argument("--baseline", help="Path to baseline.json for known-findings suppression.")
    scan_parser.add_argument("--include", action="append", default=None, help="Glob pattern to include (repeatable).")
    scan_parser.add_argument("--exclude", action="append", default=None, help="Glob pattern to exclude (repeatable).")
    scan_parser.add_argument("--output", "-o", default=None, help="Write output to file instead of stdout.")

    # rules
    _rules_parser = subparsers.add_parser("rules", help="List active rules.")

    # init
    init_parser = subparsers.add_parser("init", help="Write a default config file.")
    init_parser.add_argument("--format", choices=["json", "yaml", "yml"], default="json")

    # adopt (adoption guidance)
    adopt_parser = subparsers.add_parser(
        "adopt",
        help="Show adoption guidance for scan findings.",
    )
    adopt_parser.add_argument(
        "path", help="File or directory to scan for adoption guidance.",
    )
    adopt_parser.add_argument(
        "--config", help="Path to config file (JSON or YAML).",
    )
    adopt_parser.add_argument(
        "--baseline", help="Path to baseline.json for known-findings suppression.",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "rules":
        return _cmd_rules(args)
    elif args.command == "init":
        return _cmd_init(args)
    elif args.command == "adopt":
        return _cmd_adopt(args)
    else:
        parser.print_help()
        return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        return 2

    # Load baseline
    baseline = None
    if args.baseline:
        from actenon_scan.baseline import load_baseline
        baseline = load_baseline(args.baseline)

    # Collect suppressions
    suppressions: set[tuple[str, str]] = set()
    if target.is_file():
        suppressions = collect_suppressions_from_file(target)
    else:
        for filepath in target.rglob("*.py"):
            suppressions.update(collect_suppressions_from_file(filepath))

    result = scan_path(
        target,
        config=args.config,
        include_globs=args.include,
        exclude_globs=args.exclude,
        suppressions=suppressions,
        baseline_findings=baseline,
    )

    # Format output
    if args.format == "json":
        output = format_json(result)
    elif args.format == "sarif":
        output = format_sarif(result)
    else:
        output = format_pretty(result)

    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output, end="")

    # Exit code
    if args.fail_on == "none":
        return 0
    if result.has_findings_at_or_above(args.fail_on):
        return 1
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    from actenon_scan.rules.loader import load_default_rules
    rules = load_default_rules()
    print(f"actenon-scan rules (version {rules.version})")
    print(f"  {len(rules.sinks)} sink rule(s), {len(rules.guard_patterns)} guard pattern(s)")
    print("")
    for sink in rules.sinks:
        print(f"  [{sink.severity.upper():6s}] {sink.id:30s} {sink.category}")
        print(f"           {sink.description}")
    print("")
    print("  Guard patterns:")
    for g in rules.guard_patterns:
        print(f"    - {g}")
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    config = {
        "version": "1",
        "sinks": [],
        "guards": [
            {"patterns": ["my_custom_authorize", "my_org_verify_permission"]}
        ],
        "reachability": {
            "tool_decorators": [],
            "tool_wrappers": [],
            "tool_base_classes": [],
            "tool_methods": [],
            "agent_frameworks": []
        }
    }
    if args.format == "json":
        path = "actenon-scan.json"
        content = json.dumps(config, indent=2) + "\n"
    else:
        path = "actenon-scan.yml"
        lines = ["# actenon-scan configuration", ""]
        lines.append("# Add your custom guard patterns here:")
        lines.append("guards:")
        lines.append("  - patterns:")
        lines.append("      - my_custom_authorize")
        lines.append("      - my_org_verify_permission")
        lines.append("")
        lines.append("# Add your custom sink rules here:")
        lines.append("# sinks:")
        lines.append("#   - id: CUSTOM-SINK")
        lines.append("#     category: custom")
        lines.append("#     severity: high")
        lines.append("#     description: Custom sink")
        lines.append("#     match:")
        lines.append("#       type: name_call")
        lines.append("#       func_patterns: [\"my_dangerous_function\"]")
        content = "\n".join(lines) + "\n"

    Path(path).write_text(content)
    print(f"Wrote default config to {path}")
    return 0


def _cmd_adopt(args: argparse.Namespace) -> int:
    """Show adoption guidance for scan findings.

    Demonstrates the adoption journey:
      scan finding
      -> local brokered protection
      -> Cloud management
      -> resource-owned verification

    This command is fully usable WITHOUT Cloud login — it just shows
    guidance text based on the scan findings.
    """
    target = Path(args.path)
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        return 2

    baseline = None
    if args.baseline:
        from actenon_scan.baseline import load_baseline
        baseline = load_baseline(args.baseline)

    suppressions = set()
    from actenon_scan.suppress import collect_suppressions_from_file

    files_to_scan = [target] if target.is_file() else list(target.rglob("*.py"))
    for f in files_to_scan:
        if f.suffix == ".py":
            suppressions.update(collect_suppressions_from_file(f))

    result = scan_path(
        target,
        config=args.config,
        suppressions=suppressions,
        baseline_findings=baseline,
    )

    if result.finding_count == 0:
        print("No findings. Your codebase has no detected execution-gap vulnerabilities.")
        print("If you have custom guards, make sure they're registered with scan --config.")
        return 0

    print(f"Found {result.finding_count} unguarded consequential action(s).")
    print("=" * 60)
    print()
    print("Adoption journey for each finding:")
    print()

    for f in result.findings:
        if f.suppressed:
            continue
        print(f"  Finding: {f.rule_id} ({f.category}, {f.severity})")
        print(f"  File:    {f.file}:{f.line}")
        print(f"  Call:    {f.call_text}")
        print()
        print("  Remediation routes (NOT Actenon-only):")
        print("    1. Add an existing internal guard (if one exists)")
        print("       -> Register it: actenon-scan init, add to guards section")
        print("    2. Use a policy engine (OPA, Casbin, custom)")
        print("       -> Register the policy-check function with scan --config")
        print("    3. Use Actenon Kernel (proof verification at the edge)")
        print("       -> pip install actenon-kernel")
        print("       -> verify_pccb() before the sink call")
        print("    4. Use brokered Actenon protection (local):")
        print("       -> pip install actenon-permit")
        print("       -> Actenon.local() + register_adapter_tool()")
        print("       -> The broker resolves the credential; agent never sees it")
        print("    5. Use Cloud-managed Actenon:")
        print("       -> Deploy actenon-cloud")
        print("       -> Cloud issues grants, manages credentials, runs the broker")
        print("       -> Evidence bundle with 9 independent layers")
        print("    6. Use resource-owned verification:")
        print("       -> Resource boundary independently verifies the proof")
        print("       -> Resource issues a signed receipt")
        print("       -> Cloud verifies the receipt (never trusts submission alone)")
        print("    7. Redesign the boundary:")
        print("       -> If the action should not be agent-reachable, remove the path")
        print()
        print("  Note: Cloud is OPTIONAL. Local brokered protection (route 4)")
        print("  works without any Cloud login or deployment.")
        print()
        print("-" * 60)

    print()
    print("Next steps:")
    print("  1. Review each finding and choose a remediation route.")
    print("  2. If using custom guards, register them: actenon-scan init")
    print("  3. Re-scan after remediation: actenon-scan scan <path>")
    print("  4. Create a baseline for accepted findings: actenon-scan baseline <path>")
    return 1 if result.has_findings_at_or_above("medium") else 0
