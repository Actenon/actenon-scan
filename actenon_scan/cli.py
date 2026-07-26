"""actenon-scan CLI — argparse-based command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from actenon_scan.engine import scan_path, scan_path_parallel
from actenon_scan.report.json_out import format_json
from actenon_scan.report.pretty import format_pretty, format_list
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
    scan_parser.add_argument(
        "--format",
        choices=["pretty", "list", "json", "sarif", "html", "markdown"],
        default="pretty",
        help="Output format. 'pretty' = blast-radius summary (default). "
             "'list' = linter-style list. 'json'/'sarif' = machine-readable. "
             "'html'/'markdown' = shareable reports.",
    )
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
    scan_parser.add_argument(
        "--no-cache",
        action="store_true",
        default=False,
        help="Disable the content-hash cache. Every file is scanned fresh.",
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

    # brief (Work Order 1, Part 6): one-page execution-boundary report.
    brief_parser = subparsers.add_parser(
        "brief",
        help="Generate a one-page execution-boundary brief for a finding.",
    )
    brief_parser.add_argument(
        "location",
        help="File:line location of the finding (e.g., path/to/file.py:42).",
    )
    brief_parser.add_argument(
        "--rule",
        default=None,
        help="Rule ID to disambiguate when multiple rules fire at the same line.",
    )
    brief_parser.add_argument(
        "--format",
        choices=["text", "markdown"],
        default="text",
        help="Output format: text (email) or markdown (issue/PR). Default: text.",
    )

    # explain (Work Order 2, Part 2): execution-path explanation.
    explain_parser = subparsers.add_parser(
        "explain",
        help="Show the analysed execution path for a finding.",
    )
    explain_parser.add_argument(
        "location",
        help="File:line location of the finding (e.g., path/to/file.py:42).",
    )
    explain_parser.add_argument(
        "--rule",
        default=None,
        help="Rule ID to disambiguate when multiple rules fire at the same line.",
    )

    # fix (Work Order 2, Part 3): generate remediation diffs.
    fix_parser = subparsers.add_parser(
        "fix",
        help="Generate a remediation diff for a finding.",
    )
    fix_parser.add_argument(
        "location",
        help="File:line location of the finding, or '.' for fix-all.",
    )
    fix_parser.add_argument(
        "--rule",
        default=None,
        help="Rule ID to disambiguate when multiple rules fire at the same line.",
    )
    fix_parser.add_argument(
        "--mode",
        choices=["guard", "approval", "actenon"],
        default=None,
        help="Remediation mode. If omitted, auto-selects the best available.",
    )
    fix_parser.add_argument(
        "--apply",
        action="store_true",
        default=False,
        help="Apply the patch to the file. Without this flag, prints a diff only.",
    )
    fix_parser.add_argument(
        "--fix-all",
        action="store_true",
        default=False,
        help="With 'fix .', generate one diff covering every eligible finding.",
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
    elif args.command == "brief":
        return _cmd_brief(args)
    elif args.command == "explain":
        return _cmd_explain(args)
    elif args.command == "fix":
        return _cmd_fix(args)
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
    # Work Order 4, Part 1.1+1.4: auto-detect .actenon-scan.json at the
    # scan target root (or the repo root above it), AND read exclude
    # patterns from ANY config file — whether auto-detected or explicit.
    # Search order: explicit --config > target/.actenon-scan.json >
    # target.parent/.actenon-scan.json
    auto_exclude: list[str] | None = None
    if not config_path:
        auto_config = target / ".actenon-scan.json" if target.is_dir() else target.parent / ".actenon-scan.json"
        if auto_config.exists():
            config_path = str(auto_config)
    # Read exclude patterns from whatever config file we're using.
    # This fixes the bug where --config .actenon-scan.json did NOT apply
    # the exclude key (it was only read in the auto-detection path).
    if config_path:
        import json as _json
        try:
            with open(config_path) as f:
                cfg = _json.load(f)
            if isinstance(cfg, dict) and "exclude" in cfg:
                auto_exclude = cfg["exclude"]
        except (OSError, _json.JSONDecodeError):
            pass
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
    # Merge auto-detected excludes with explicit --exclude flags
    exclude_globs = list(args.exclude) if args.exclude else []
    if auto_exclude:
        exclude_globs.extend(auto_exclude)
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
            jobs = auto_jobs(len(_collect_files(target, include_globs, exclude_globs)))
        elif jobs is None:
            jobs = 1

        import time as _time
        _t0 = _time.perf_counter()

        # ── Content-hash cache (Work Order 2, Part 4.4) ──
        cache = None
        if not args.no_cache:
            from actenon_scan.cache import FileCache, get_default_cache_dir
            cache_dir = get_default_cache_dir(target)
            cache = FileCache(cache_dir)

        # ── Progressive output (Work Order 2, Part 4.1) ──
        # Stream findings to stderr as they are discovered, but ONLY for
        # interactive terminal output (pretty format, stdout is a TTY).
        # Machine formats (json/sarif/html/markdown) use stable
        # non-progressive output.
        on_finding = None
        if (args.format == "pretty"
                and not args.output
                and sys.stderr.isatty()):
            def _progressive(finding) -> None:
                from actenon_scan.report.blast_radius import consequence_label, _extract_method_name
                print(
                    f"  [{finding.severity.upper()}] {consequence_label(finding.category):14s} "
                    f"{finding.file}:{finding.line}  {_extract_method_name(finding.call_text)}()",
                    file=sys.stderr,
                )
            on_finding = _progressive

        if jobs > 1 and explicit_files is None:
            result = scan_path_parallel(
                target,
                jobs=jobs,
                config=config_path,
                include_globs=include_globs,
                exclude_globs=exclude_globs,
                suppressions=suppressions,
                baseline_findings=baseline,
            )
        else:
            result = scan_path(
                target,
                config=config_path,
                include_globs=include_globs,
                exclude_globs=exclude_globs,
                explicit_files=explicit_files,
                suppressions=suppressions,
                baseline_findings=baseline,
                cache=cache,
                on_finding=on_finding,
            )
        result._elapsed = _time.perf_counter() - _t0
    except Exception as e:
        # Catch ConfigError and other config-loading errors gracefully.
        # Never crash with a raw traceback on a config mistake.
        from actenon_scan.rules.loader import ConfigError
        if isinstance(e, ConfigError):
            print(f"actenon-scan: {e}", file=sys.stderr)
            return 2
        raise

    # Format output
    _elapsed = getattr(result, "_elapsed", None)

    if args.format == "json":
        output = format_json(result)
    elif args.format == "sarif":
        output = format_sarif(result)
    elif args.format == "list":
        output = format_list(result)
    elif args.format == "html":
        from actenon_scan.report.html_out import format_html
        output = format_html(result, elapsed=_elapsed)
    elif args.format == "markdown":
        from actenon_scan.report.markdown_out import format_markdown
        output = format_markdown(result, elapsed=_elapsed)
    else:
        # Default: blast-radius summary
        output = format_pretty(result, elapsed=_elapsed)

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


def _cmd_brief(args: argparse.Namespace) -> int:
    """Generate a one-page execution-boundary brief for a finding.

    Work Order 1, Part 6: the brief is a reusable, typed report for
    responsible outreach. It consumes reusable internal objects (not
    duplicated analysis) and supports text (email) + markdown (issue/PR)
    output formats.

    Safety (Part 6.6 + RULE 9 + RULE 10): the brief never includes
    attack prompts, prompt-injection strings, exploitation payloads, or
    credential values. A safety filter redacts credential-looking
    patterns and asserts no forbidden pattern remains.
    """
    # Parse the file:line location.
    if ":" not in args.location:
        print(
            f"Error: location must be in the form path/to/file.py:LINE",
            file=sys.stderr,
        )
        return 2
    file_str, _, line_str = args.location.rpartition(":")
    try:
        line = int(line_str)
    except ValueError:
        print(f"Error: line number must be an integer, got: {line_str}", file=sys.stderr)
        return 2

    file_path = Path(file_str)
    if not file_path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2

    from actenon_scan.brief import build_brief, format_brief_text, format_brief_markdown

    brief = build_brief(str(file_path), line, rule_id=args.rule)
    if brief is None:
        print(
            f"No finding at {file_path}:{line}"
            + (f" with rule {args.rule}" if args.rule else "")
            + ". Run `actenon-scan scan` first to confirm the finding exists.",
            file=sys.stderr,
        )
        return 1

    if args.format == "markdown":
        print(format_brief_markdown(brief))
    else:
        print(format_brief_text(brief))
    return 0


def _parse_location(location: str) -> tuple[Path, int] | int:
    """Parse a file:line location. Returns (path, line) or an exit code."""
    if ":" not in location:
        print(
            f"Error: location must be in the form path/to/file.py:LINE",
            file=sys.stderr,
        )
        return 2
    file_str, _, line_str = location.rpartition(":")
    try:
        line = int(line_str)
    except ValueError:
        print(f"Error: line number must be an integer, got: {line_str}", file=sys.stderr)
        return 2
    file_path = Path(file_str)
    if not file_path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2
    return (file_path, line)


def _cmd_explain(args: argparse.Namespace) -> int:
    """Show the analysed execution path for a finding (Part 2)."""
    parsed = _parse_location(args.location)
    if isinstance(parsed, int):
        return parsed
    file_path, line = parsed

    from actenon_scan.brief import build_brief
    from actenon_scan.explain import format_explain

    brief = build_brief(str(file_path), line, rule_id=args.rule)
    if brief is None:
        print(
            f"No finding at {file_path}:{line}"
            + (f" with rule {args.rule}" if args.rule else "")
            + ".",
            file=sys.stderr,
        )
        return 1
    print(format_explain(brief))
    return 0


def _cmd_fix(args: argparse.Namespace) -> int:
    """Generate a remediation diff for a finding (Part 3)."""
    if args.location == ".":
        # Fix-all mode.
        from actenon_scan.fix import generate_fix_all
        results = generate_fix_all(".", mode=args.mode, apply=args.apply)
        if not results:
            print("No eligible findings to fix.")
            return 0
        for r in results:
            if r.diff:
                print(r.diff)
            elif r.note:
                print(f"# {r.note}")
        print(f"\n{len(results)} finding(s) processed. Mode: {results[0].mode if results else 'n/a'}.")
        if not args.apply:
            print("Use --apply to write changes to files.")
        return 0

    parsed = _parse_location(args.location)
    if isinstance(parsed, int):
        return parsed
    file_path, line = parsed

    from actenon_scan.fix import generate_fix

    fix = generate_fix(
        str(file_path), line,
        mode=args.mode, rule_id=args.rule, apply=args.apply,
    )
    if fix is None:
        print(
            f"No finding at {file_path}:{line}"
            + (f" with rule {args.rule}" if args.rule else "")
            + ".",
            file=sys.stderr,
        )
        return 1

    if fix.diff:
        print(fix.diff)
        if fix.applied:
            print(f"# Applied {fix.mode} fix to {file_path}")
        else:
            print(f"# Mode: {fix.mode}. Use --apply to write this change.")
    else:
        print(f"# Automatic remediation was not generated.")
        print(f"# {fix.note}")
        print("# Available approaches:")
        print("# 1. repository-native guard")
        print("# 2. framework-native approval")
        print("# 3. Actenon proof verification")
        print("# Use --mode guard|approval|actenon to force a mode.")
    return 0
