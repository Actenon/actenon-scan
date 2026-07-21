"""actenon-scan CLI — argparse-based command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from actenon_scan.engine import ScanResult, SEVERITY_ORDER, scan_path
from actenon_scan.report.json_out import format_json
from actenon_scan.report.pretty import format_pretty
from actenon_scan.report.sarif import format_sarif
from actenon_scan.suppress import collect_suppressions_from_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="actenon-scan",
        description="Defensive static-analysis scanner for the AI-agent execution gap.",
    )
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
    rules_parser = subparsers.add_parser("rules", help="List active rules.")

    # init
    init_parser = subparsers.add_parser("init", help="Write a default config file.")
    init_parser.add_argument("--format", choices=["json", "yaml", "yml"], default="json")

    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "rules":
        return _cmd_rules(args)
    elif args.command == "init":
        return _cmd_init(args)
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
        import fnmatch
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
