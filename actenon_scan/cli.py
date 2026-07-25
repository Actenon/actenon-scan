"""actenon-scan CLI — argparse-based command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from actenon_scan.engine import scan_path, scan_path_parallel
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
    scan_parser.add_argument(
        "--fail-on-unsupported",
        action="store_true",
        default=False,
        help="Exit non-zero if any unsupported source files were found (e.g. .ts without [typescript] extra). "
        "Default off — unsupported files alone do not fail the build.",
    )
    scan_parser.add_argument("--output", "-o", default=None, help="Write output to file instead of stdout.")
    scan_parser.add_argument(
        "--jobs",
        type=int,
        default=None,
        metavar="N",
        help="Scan with N parallel processes (default: os.cpu_count(); 1 disables). "
             "Findings are identical to a serial scan.",
    )
    scan_parser.add_argument(
        "--changed-only",
        default=None,
        metavar="GIT_REF",
        help="Only scan files changed since GIT_REF (e.g., HEAD~1, main, origin/main). Requires git.",
    )
    scan_parser.add_argument(
        "--guard",
        action="append",
        default=None,
        help="Register a guard pattern by name (repeatable). No config file needed.",
    )

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

    # --guard: register guard patterns without a config file
    config_path = args.config
    if args.guard and not config_path:
    # Write a temporary config with the guard patterns
        import tempfile, json
        tmp_config = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False,
            prefix="actenon-scan-guards-",
        )
        json.dump({"guard_patterns": args.guard}, tmp_config)
        tmp_config.close()
        config_path = tmp_config.name

    explicit_files = None
    # --changed-only: filter to files changed since git ref
    include_globs = args.include
    if args.changed_only:
        changed_files = _get_changed_files(args.changed_only, target)
        if changed_files:
            # Pass the exact paths through rather than converting to include
            # globs: globbing still walked the entire tree before filtering,
            # which is the fixed cost --changed-only exists to avoid.
            base = target if target.is_dir() else target.parent
            explicit_files = [
                (base / cf) if not Path(cf).is_absolute() else Path(cf)
                for cf in changed_files
            ]

    try:
        # An explicit --jobs N is always honoured. Otherwise auto_jobs decides,
        # and it returns 1 unless parallelism has been measured to pay for
        # itself on this shape of machine and repo. Parallel-by-default was
        # ~10% SLOWER than serial on 2-4 core CI runners.
        if args.jobs is not None:
            jobs = args.jobs
        else:
            jobs = None  # resolved below, once the file count is known
        # --changed-only already scans a handful of files; process startup
        # would cost more than it saves, so it stays serial.
        if jobs is None and explicit_files is None:
            from actenon_scan.engine import _collect_files, auto_jobs
            jobs = auto_jobs(len(_collect_files(target, include_globs, args.exclude)))
        elif jobs is None:
            jobs = 1

        if jobs > 1 and explicit_files is None:
            result = scan_path_parallel(
                target,
                jobs=jobs,
                config=config_path,
                include_globs=include_globs,
                exclude_globs=args.exclude,
                suppressions=suppressions,
                baseline_findings=baseline,
            )
        else:
            result = scan_path(
                target,
                config=config_path,
                include_globs=include_globs,
                exclude_globs=args.exclude,
                explicit_files=explicit_files,
                suppressions=suppressions,
                baseline_findings=baseline,
            )
    except Exception as e:
        # Catch ConfigError and other config-loading errors gracefully.
        # Never crash with a raw traceback on a config mistake.
        from actenon_scan.rules.loader import ConfigError
        if isinstance(e, ConfigError):
            print(f"actenon-scan: {e}", file=sys.stderr)
            return 2
        raise

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
    # Unsupported files alone do NOT fail the build (default). Use
    # --fail-on-unsupported to opt in.
    if args.fail_on_unsupported and result.unsupported_files:
        return 1
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
    """Write a starter .actenon-scan.json config.

    If the current directory contains Python files with guard-shaped
    function names not in the default vocabulary, they are pre-populated
    as suggestions.
    """
    # Scan for unrecognised guard-shaped names in the current directory
    suggested_guards: list[str] = []
    try:
        from actenon_scan.engine import scan_path, _find_declarative_guarded_classes
        from actenon_scan.rules.loader import load_default_rules
        import ast as _ast
        from pathlib import Path as _Path

        rules = load_default_rules()
        known_guards = set(rules.guard_patterns)
        guard_shape_words = {"authorize", "check", "verify", "guard", "gate",
                             "permission", "auth", "policy", "enforce", "allow",
                             "approve", "confirm", "validate", "require"}

        for pyfile in _Path(".").rglob("*.py"):
            if "__pycache__" in pyfile.parts or pyfile.name.startswith("test_"):
                continue
            try:
                source = pyfile.read_text(encoding="utf-8")
                tree = _ast.parse(source, filename=str(pyfile))
            except Exception:
                continue
            for node in _ast.walk(tree):
                if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                    name_lower = node.name.lower()
                    # Check if it looks guard-shaped but is not in known_guards
                    if any(word in name_lower for word in guard_shape_words):
                        if node.name not in known_guards and node.name not in suggested_guards:
                            suggested_guards.append(node.name)
            if len(suggested_guards) >= 20:
                break
    except Exception:
        pass  # Don't fail --init if scanning fails

    config = {
        "version": "1",
        "guard_patterns": suggested_guards if suggested_guards else [],
    }

    if args.format == "json":
        path = ".actenon-scan.json"
        content = json.dumps(config, indent=2) + "\n"
    else:
        path = ".actenon-scan.yml"
        lines = ["# actenon-scan configuration", ""]
        if suggested_guards:
            lines.append("# Suggested guard patterns found in your codebase:")
            lines.append("guard_patterns:")
            for g in suggested_guards:
                lines.append(f'  - "{g}"')
        else:
            lines.append("# Add your custom guard patterns here:")
            lines.append('guard_patterns: []')
        lines.append("")
        content = "\n".join(lines) + "\n"

    Path(path).write_text(content)
    print(f"Wrote config to {path}")
    if suggested_guards:
        print(f"Found {len(suggested_guards)} suggested guard(s): {', '.join(suggested_guards[:5])}{'...' if len(suggested_guards) > 5 else ''}")
    else:
        print("No unrecognised guard-shaped names found. Add patterns manually if needed.")
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


def _get_changed_files(git_ref: str, target: Path) -> list[str]:
    """Get files changed since a git ref, relative to target."""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--relative", git_ref],
            capture_output=True, text=True, cwd=str(target),
            timeout=10,
        )
        if result.returncode != 0:
            print(f"Warning: git diff failed: {result.stderr}", file=sys.stderr)
            return None
        # Filter to .py files only
        changed = [f.strip() for f in result.stdout.splitlines() if f.strip().endswith(".py")]
        return changed if changed else None
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Warning: --changed-only requires git: {e}", file=sys.stderr)
        return None
