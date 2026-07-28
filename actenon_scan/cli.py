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
    # nargs='+' so the pre-commit hook (which passes one file per changed
    # file as positional args) does not crash with "unrecognized arguments".
    # When a single path is given (the normal case) behaviour is unchanged.
    scan_parser.add_argument(
        "path",
        nargs="+",
        help="File or directory to scan. Multiple paths may be given "
             "(e.g. for pre-commit, which passes each changed file).",
    )
    scan_parser.add_argument(
        "--format",
        choices=["pretty", "list", "json", "sarif", "html", "markdown"],
        default="pretty",
        help="Output format. 'pretty' = blast-radius summary (default). "
             "'list' = linter-style list. 'json'/'sarif' = machine-readable. "
             "'html'/'markdown' = shareable reports.",
    )
    # CLI default --fail-on is "medium". This is the near-universal convention
    # for SAST/linter tools (semgrep, bandit, eslint, shellcheck all do it):
    # a non-zero exit on findings means "findings present", not "crashed".
    # The CLI has no other machine-readable signal — its exit code IS the
    # status. A scanner that finds 8 unguarded consequential actions and
    # returns 0 passes CI silently, which is the false-assurance failure
    # this tool exists to close.
    #
    # The action.yml default is intentionally "none" — the Action has its own
    # reporting surface (sticky PR comment + SARIF upload to the Security tab),
    # so findings stay visible even when the check is green. A soft default
    # there is defensible for teams adopting the tool against an untriaged
    # baseline. The CLI has no such surface. The two intentionally differ;
    # do not "fix" them back into alignment.
    scan_parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high"],
        default="medium",
        help="Exit non-zero when findings meet this severity. Default: medium "
             "(findings at or above medium severity fail the build). Set to "
             "'high' to only fail on high-severity findings; 'none' to never "
             "fail (use with --baseline for triaged repos); 'low' is the strictest.",
    )
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
    scan_parser.add_argument(
        "--cache-dir",
        default=None,
        help="Override the cache directory. Default: "
             "${XDG_CACHE_HOME:-~/.cache}/actenon-scan/<target-hash>. "
             "Can also be set via the ACTENON_SCAN_CACHE_DIR env var. "
             "Use this in CI to keep the cache on a persistent volume "
             "across runs, or to avoid polluting the workspace.",
    )

    # rules
    _rules_parser = subparsers.add_parser("rules", help="List active rules.")

    # init
    init_parser = subparsers.add_parser("init", help="Write a default config file.")
    init_parser.add_argument("--format", choices=["json", "yaml", "yml"], default="json")
    # P1-2 fix: init previously overwrote the existing .actenon-scan.json
    # silently, destroying exclude/sinks/reachability keys. Now it merges
    # suggested guards into the existing config and refuses to overwrite
    # without --force.
    init_parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Overwrite the existing config instead of merging. DANGEROUS: "
             "loses exclude/sinks/reachability keys. Default: merge.",
    )

    # baseline: generate a known-findings baseline from the current scan.
    # The `--baseline` flag on `scan` consumes these files; this subcommand
    # produces them. Previously, `_cmd_adopt` told users to run
    # `actenon-scan baseline <path>` but no such subcommand existed.
    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Generate a baseline.json from the current scan, for known-findings suppression.",
    )
    baseline_parser.add_argument(
        "path",
        help="File or directory to scan and lock in as the known-findings baseline.",
    )
    baseline_parser.add_argument(
        "--output", "-o",
        default="baseline.json",
        help="Output file path. Default: baseline.json in the current directory.",
    )
    baseline_parser.add_argument(
        "--config", help="Path to config file (JSON or YAML).",
    )

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
        nargs="?",
        default=None,
        help="File:line location of the finding (e.g., path/to/file.py:42). "
             "Omit when using --all.",
    )
    brief_parser.add_argument(
        "--all",
        dest="all_findings",
        action="store_true",
        default=False,
        help="Generate a brief for every finding in the scan. Requires a path "
             "argument (e.g. `actenon-scan brief --all .`).",
    )
    brief_parser.add_argument(
        "--path",
        default=".",
        help="Path to scan when using --all. Default: current directory.",
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
    brief_parser.add_argument(
        "--output", "-o", default=None,
        help="Write output to file instead of stdout (useful with --all).",
    )

    # explain (Work Order 2, Part 2): execution-path explanation.
    explain_parser = subparsers.add_parser(
        "explain",
        help="Show the analysed execution path for a finding.",
    )
    explain_parser.add_argument(
        "location",
        nargs="?",
        default=None,
        help="File:line location of the finding (e.g., path/to/file.py:42). "
             "Omit when using --all.",
    )
    explain_parser.add_argument(
        "--all",
        dest="all_findings",
        action="store_true",
        default=False,
        help="Explain every finding in the scan. Requires a path argument "
             "(e.g. `actenon-scan explain --all .`).",
    )
    explain_parser.add_argument(
        "--path",
        default=".",
        help="Path to scan when using --all. Default: current directory.",
    )
    explain_parser.add_argument(
        "--rule",
        default=None,
        help="Rule ID to disambiguate when multiple rules fire at the same line.",
    )
    explain_parser.add_argument(
        "--output", "-o", default=None,
        help="Write output to file instead of stdout (useful with --all).",
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

    # install
    install_parser = subparsers.add_parser(
        "install",
        help="Install actenon-scan into a project (GitHub Actions, pre-commit).",
    )
    install_sub = install_parser.add_subparsers(dest="install_target")

    # install github
    github_parser = install_sub.add_parser(
        "github",
        help="Generate a GitHub Actions workflow for actenon-scan.",
    )
    github_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print the proposed workflow without writing to disk.",
    )
    github_parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Overwrite an existing workflow file. A backup is saved.",
    )
    github_parser.add_argument(
        "--blocking",
        action="store_true",
        default=False,
        help="Configure the workflow to block merging on findings (fail-on: high). "
             "Default: non-blocking (fail-on: none).",
    )
    github_parser.add_argument(
        "--baseline",
        default=None,
        help="Path to a baseline.json for known-findings suppression.",
    )
    github_parser.add_argument(
        "--config",
        default=None,
        help="Path to an actenon-scan config file (JSON or YAML).",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "rules":
        return _cmd_rules(args)
    elif args.command == "init":
        return _cmd_init(args)
    elif args.command == "baseline":
        return _cmd_baseline(args)
    elif args.command == "adopt":
        return _cmd_adopt(args)
    elif args.command == "brief":
        return _cmd_brief(args)
    elif args.command == "explain":
        return _cmd_explain(args)
    elif args.command == "fix":
        return _cmd_fix(args)
    elif args.command == "install":
        return _cmd_install(args)
    else:
        parser.print_help()
        return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    # Normalize to a single `target` plus optional `explicit_files` for the
    # multi-path case (pre-commit passes one path per changed file).
    paths = [Path(p) for p in args.path]
    # Validate every path up-front — fail fast with a clear message rather
    # than silently scanning a subset.
    for p in paths:
        if not p.exists():
            print(f"Error: path not found: {p}", file=sys.stderr)
            return 2

    if len(paths) == 1:
        target = paths[0]
        multi_explicit_files: list[Path] | None = None
    else:
        # Multiple paths: pick the common ancestor directory as `target`
        # and pass the individual files as `explicit_files`. This keeps the
        # engine's single-target contract intact while letting pre-commit
        # (and any caller) pass N files in one invocation.
        # If any path is a directory, fall back to the first directory (the
        # other paths are then redundant — they are inside it).
        dir_paths = [p for p in paths if p.is_dir()]
        if dir_paths:
            target = dir_paths[0]
            multi_explicit_files = None
        else:
            # All file paths. Common ancestor must be a directory.
            common = Path(os.path.commonpath([p.resolve() for p in paths]))
            if common.is_file():
                common = common.parent
            target = common
            multi_explicit_files = [p.resolve() for p in paths]

    # Load baseline
    baseline = None
    if args.baseline:
        from actenon_scan.baseline import load_baseline
        baseline = load_baseline(args.baseline)

    # Collect suppressions
    # NOTE: pass `target` so suppressions are keyed the SAME way the engine
    # keys findings (path relative to target). Without this, suppressions
    # silently become no-ops whenever the scan target is an absolute path
    # (the universal case in CI — `scan .` resolves to the absolute
    # workspace path).
    suppressions: set[tuple[str, str]] = set()
    if target.is_file():
        suppressions = collect_suppressions_from_file(target, target)
    else:
        for filepath in target.rglob("*.py"):
            suppressions.update(collect_suppressions_from_file(filepath, target))

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

    explicit_files = multi_explicit_files
    # --changed-only: filter to files changed since git ref
    include_globs = args.include
    # Merge auto-detected excludes with explicit --exclude flags
    exclude_globs = list(args.exclude) if args.exclude else []
    if auto_exclude:
        exclude_globs.extend(auto_exclude)
    if args.changed_only:
        changed_files = _get_changed_files(args.changed_only, target)
        if not changed_files:
            # P1-5 fix: previously, an empty git diff silently fell through
            # to a full scan (because explicit_files stayed None and the
            # scan_path call below walks the whole tree). A user running
            # `--changed-only HEAD` on a clean working tree (the common CI
            # case) would get a full scan and N findings they didn't
            # expect. Now we print a warning and exit 0 with no findings.
            print(
                f"--changed-only {args.changed_only}: no scannable files changed. "
                f"Nothing to scan.",
                file=sys.stderr,
            )
            # Print an empty result so callers piping output get something.
            from actenon_scan.report.pretty import format_pretty as _fp
            from actenon_scan.engine import ScanResult as _SR
            print(_fp(_SR()), end="")
            return 0
        # Pass the exact paths through rather than converting to include
        # globs: globbing still walked the entire tree before filtering,
        # which is the fixed cost --changed-only exists to avoid.
        base = target if target.is_dir() else target.parent
        changed_paths = [
            (base / cf) if not Path(cf).is_absolute() else Path(cf)
            for cf in changed_files
        ]
        # If the user also passed explicit paths on the CLI, intersect
        # with the changed-files set so we don't scan files that weren't
        # changed. (This is rare but the semantics should be intuitive.)
        if explicit_files:
            explicit_set = {p.resolve() for p in explicit_files}
            explicit_files = [p for p in changed_paths if p.resolve() in explicit_set]
        else:
            explicit_files = changed_paths
        # Apply exclude patterns to the changed-files list.
        # Without this, --changed-only bypasses the exclude config and
        # reports findings from test fixtures that were touched in the PR.
        if exclude_globs:
            from fnmatch import fnmatch
            filtered = []
            for f in explicit_files:
                rel = str(f.relative_to(base)) if base in f.parents or f == base else str(f)
                excluded = False
                for pattern in exclude_globs:
                    # Handle ** patterns by also checking prefix matches
                    clean_pattern = pattern.replace("**/", "").replace("/**", "")
                    if fnmatch(rel, pattern) or fnmatch(str(f), pattern) or clean_pattern in rel:
                        excluded = True
                        break
                if not excluded:
                    filtered.append(f)
            explicit_files = filtered
            # If excludes filtered out everything, warn and exit 0.
            if not explicit_files:
                print(
                    f"--changed-only {args.changed_only}: all changed files were "
                    f"excluded by config. Nothing to scan.",
                    file=sys.stderr,
                )
                from actenon_scan.report.pretty import format_pretty as _fp2
                from actenon_scan.engine import ScanResult as _SR2
                print(_fp2(_SR2()), end="")
                return 0

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
            # --cache-dir flag wins; otherwise env var (handled in
            # get_default_cache_dir); otherwise XDG default.
            if args.cache_dir:
                cache_dir = args.cache_dir
            else:
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
                cache=cache,
                on_finding=on_finding,
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

    P1-2 fix: previously this command SILENTLY OVERWROTE an existing
    .actenon-scan.json, destroying exclude/sinks/reachability keys. Now
    it MERGES suggested guards into the existing config (deduped) and
    refuses to overwrite without --force.
    """
    # Determine the config file path.
    if args.format == "json":
        path = ".actenon-scan.json"
    else:
        path = ".actenon-scan.yml"

    # Read the existing config if present (for merge).
    existing_config: dict = {}
    existing_path = Path(path)
    if existing_path.exists() and not args.force:
        try:
            if args.format == "json":
                existing_config = json.loads(existing_path.read_text())
            else:
                import yaml as _yaml
                existing_config = _yaml.safe_load(existing_path.read_text()) or {}
            if not isinstance(existing_config, dict):
                existing_config = {}
        except (OSError, json.JSONDecodeError, Exception):
            # If we can't parse the existing config, fall through to the
            # overwrite path with a warning.
            print(
                f"Warning: could not parse existing {path}; will overwrite. "
                f"Use --force to suppress this warning.",
                file=sys.stderr,
            )
            existing_config = {}

    # Scan for unrecognised guard-shaped names in the current directory.
    suggested_guards: list[str] = []
    try:
        from actenon_scan.engine import scan_path, _find_declarative_guarded_classes
        from actenon_scan.rules.loader import load_default_rules
        import ast as _ast
        from pathlib import Path as _Path

        rules = load_default_rules()
        known_guards = set(rules.guard_patterns)
        # Include guards already in the existing config so we don't re-suggest them.
        known_guards.update(existing_config.get("guard_patterns", []))
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
                    if any(word in name_lower for word in guard_shape_words):
                        if node.name not in known_guards and node.name not in suggested_guards:
                            suggested_guards.append(node.name)
            if len(suggested_guards) >= 20:
                break
    except Exception:
        pass  # Don't fail --init if scanning fails

    # Build the new config. MERGE with existing instead of overwriting.
    if args.force:
        # --force: write a fresh config with only the suggested guards.
        config = {
            "version": "1",
            "guard_patterns": suggested_guards if suggested_guards else [],
        }
        action_verb = "Overwrote"
    else:
        # Merge: start with existing config, add suggested guards (deduped).
        config = dict(existing_config)  # shallow copy preserves exclude/sinks/reachability
        config.setdefault("version", "1")
        existing_guards = list(config.get("guard_patterns", []))
        merged_guards = list(existing_guards)
        for g in suggested_guards:
            if g not in merged_guards:
                merged_guards.append(g)
        config["guard_patterns"] = merged_guards
        action_verb = "Merged into" if existing_config else "Wrote"

    if args.format == "json":
        content = json.dumps(config, indent=2) + "\n"
    else:
        import yaml as _yaml
        lines = ["# actenon-scan configuration", ""]
        if config.get("guard_patterns"):
            lines.append("# Guard patterns (custom + suggested):")
            lines.append("guard_patterns:")
            for g in config["guard_patterns"]:
                lines.append(f'  - "{g}"')
        else:
            lines.append("# Add your custom guard patterns here:")
            lines.append('guard_patterns: []')
        # Preserve exclude/sinks/reachability if present.
        for key in ("exclude", "sinks", "reachability"):
            if key in config:
                lines.append("")
                lines.append(f"{key}:")
                lines.append(_yaml.dump(config[key], default_flow_style=False).rstrip())
        lines.append("")
        content = "\n".join(lines) + "\n"

    Path(path).write_text(content)
    print(f"{action_verb} config at {path}")
    if suggested_guards:
        print(f"Found {len(suggested_guards)} suggested guard(s): {', '.join(suggested_guards[:5])}{'...' if len(suggested_guards) > 5 else ''}")
    else:
        print("No unrecognised guard-shaped names found. Add patterns manually if needed.")
    if existing_config and not args.force:
        preserved_keys = [k for k in ("exclude", "sinks", "reachability") if k in existing_config]
        if preserved_keys:
            print(f"Preserved existing keys: {', '.join(preserved_keys)}")
    return 0


def _cmd_baseline(args: argparse.Namespace) -> int:
    """Generate a baseline.json from the current scan.

    The `--baseline` flag on `scan` consumes these files to suppress
    known findings. This subcommand produces them — previously, users
    had to hand-craft the JSON.
    """
    target = Path(args.path)
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        return 2

    # Run the scan.
    from actenon_scan.engine import scan_path
    result = scan_path(target, config=args.config)

    # Convert findings to the baseline format. The baseline is matched on
    # (file, snippet_hash) — see baseline.py:load_baseline.
    baseline_findings = []
    for f in result.findings:
        if f.suppressed:
            continue
        baseline_findings.append({
            "file": f.file,
            "line": f.line,
            "rule_id": f.rule_id,
            "snippet_hash": f.snippet_hash,
            "category": f.category,
            "severity": f.severity,
        })

    # Write the baseline file.
    from actenon_scan.baseline import write_baseline
    write_baseline(baseline_findings, args.output)

    print(f"Wrote {len(baseline_findings)} finding(s) to {args.output}")
    print(f"Next: actenon-scan scan {target} --baseline {args.output}")
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
            suppressions.update(collect_suppressions_from_file(f, target))

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
    """Get files changed since a git ref, relative to target.

    Returns .py, .ts, .tsx, .js, .jsx, .mjs, .cjs, and .go files. The
    previous implementation only returned .py files, which meant the
    GitHub Action's --changed-only flag silently skipped changed .ts/.go
    files in a PR — directly contradicting the README's "Parses Python,
    TypeScript, and Go" promise.
    """
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
        # All scannable extensions — MUST stay in sync with the engine's
        # _collect_files and the TS/Go detector suffix lists.
        scannable_exts = (
            ".py",
            ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
            ".go",
        )
        changed = [
            f.strip() for f in result.stdout.splitlines()
            if f.strip().endswith(scannable_exts)
        ]
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

    With ``--all``, generates a brief for every finding in the scan.
    Useful for security leads reviewing 50+ findings in one document.
    """
    from actenon_scan.brief import build_brief, format_brief_text, format_brief_markdown

    # --all mode: scan the path and brief every finding.
    if getattr(args, "all_findings", False):
        target = Path(args.path)
        if not target.exists():
            print(f"Error: path not found: {target}", file=sys.stderr)
            return 2
        from actenon_scan.engine import scan_path
        result = scan_path(target)
        findings = [f for f in result.findings if not f.suppressed]
        if not findings:
            print(f"No findings in {target} — nothing to brief.")
            return 0

        # Resolve target to an absolute path so we can locate finding files
        # regardless of the user's cwd (same fix as _cmd_explain --all).
        target_abs = target.resolve()
        out_lines: list[str] = []
        for i, f in enumerate(findings):
            fpath = target_abs / f.file if not os.path.isabs(f.file) else Path(f.file)
            brief = build_brief(str(fpath), f.line, rule_id=f.rule_id)
            if brief is None:
                continue
            if args.format == "markdown":
                out_lines.append(format_brief_markdown(brief))
            else:
                out_lines.append(format_brief_text(brief))
            if i < len(findings) - 1:
                out_lines.append("\n---\n")  # separator between briefs

        output = "\n".join(out_lines)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"Wrote {len(findings)} brief(s) to {args.output}")
        else:
            print(output)
        return 0

    # Single-finding mode.
    if not args.location:
        print("Error: location is required (or use --all with --path).", file=sys.stderr)
        return 2
    parsed = _parse_location(args.location)
    if isinstance(parsed, int):
        return parsed
    file_path, line = parsed

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
        output = format_brief_markdown(brief)
    else:
        output = format_brief_text(brief)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


def _parse_location(location: str) -> tuple[Path, int] | int:
    """Parse a file:line location. Returns (path, line) or an exit code.

    Validates:
    - location contains a colon
    - the line part is an integer
    - the line is >= 1 (a 0 or negative line is malformed — previously
      `explain app.py:-1` would run a full scan and return "No finding
      at app.py:-1." which was both wasteful and misleading)
    - the file exists
    """
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
    if line < 1:
        print(
            f"Error: line number must be >= 1, got: {line}. "
            f"Use a 1-indexed line number from `actenon-scan scan` output.",
            file=sys.stderr,
        )
        return 2
    file_path = Path(file_str)
    if not file_path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2
    return (file_path, line)


def _cmd_explain(args: argparse.Namespace) -> int:
    """Show the analysed execution path for a finding (Part 2).

    With ``--all``, explains every finding in the scan.
    """
    from actenon_scan.brief import build_brief
    from actenon_scan.explain import format_explain

    # --all mode: scan the path and explain every finding.
    if getattr(args, "all_findings", False):
        target = Path(args.path)
        if not target.exists():
            print(f"Error: path not found: {target}", file=sys.stderr)
            return 2
        from actenon_scan.engine import scan_path
        result = scan_path(target)
        findings = [f for f in result.findings if not f.suppressed]
        if not findings:
            print(f"No findings in {target} — nothing to explain.")
            return 0

        # Resolve target to an absolute path so we can locate finding files
        # regardless of the user's cwd. The engine returns f.file as a path
        # RELATIVE TO TARGET, so we join with target to get an absolute path
        # that build_brief can read.
        target_abs = target.resolve()
        out_lines: list[str] = []
        for i, f in enumerate(findings):
            # f.file is relative to target; resolve it.
            fpath = target_abs / f.file if not os.path.isabs(f.file) else Path(f.file)
            brief = build_brief(str(fpath), f.line, rule_id=f.rule_id)
            if brief is None:
                continue
            out_lines.append(format_explain(brief))
            if i < len(findings) - 1:
                out_lines.append("\n---\n")

        output = "\n".join(out_lines)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"Wrote {len(findings)} explanation(s) to {args.output}")
        else:
            print(output)
        return 0

    # Single-finding mode.
    if not args.location:
        print("Error: location is required (or use --all with --path).", file=sys.stderr)
        return 2
    parsed = _parse_location(args.location)
    if isinstance(parsed, int):
        return parsed
    file_path, line = parsed

    brief = build_brief(str(file_path), line, rule_id=args.rule)
    if brief is None:
        print(
            f"No finding at {file_path}:{line}"
            + (f" with rule {args.rule}" if args.rule else "")
            + ".",
            file=sys.stderr,
        )
        return 1
    output = format_explain(brief)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)
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


def _cmd_install(args: argparse.Namespace) -> int:
    """Install actenon-scan into a project."""
    if getattr(args, "install_target", None) == "github":
        return _cmd_install_github(args)
    else:
        print("Usage: actenon-scan install github [options]")
        print("Run 'actenon-scan install github --help' for details.")
        return 2


def _cmd_install_github(args: argparse.Namespace) -> int:
    """Generate a GitHub Actions workflow for actenon-scan.

    Creates .github/workflows/actenon-scan.yml with:
      - PR-triggered scanning of changed files
      - Sticky PR comment (updated in place)
      - SARIF upload to Security tab
      - Non-blocking by default (--blocking enables fail-on: high)
      - Uses @v1 stable tag
      - Secure minimum permissions
      - No secrets required
    """
    # 1. Detect Git repository
    cwd = Path.cwd()
    repo_root = _find_git_root(cwd)
    if repo_root is None:
        print("Error: not inside a Git repository. Run from a repository root.",
              file=sys.stderr)
        return 2

    # 2. Determine workflow path
    workflow_dir = repo_root / ".github" / "workflows"
    workflow_path = workflow_dir / "actenon-scan.yml"

    # 3. Check for existing file
    if workflow_path.exists() and not args.force:
        print(f"Error: {workflow_path} already exists.", file=sys.stderr)
        print(f"  Use --force to overwrite (a backup will be saved).", file=sys.stderr)
        return 1

    # 4. Generate workflow YAML
    fail_on = "high" if args.blocking else "none"
    baseline_line = f"          baseline: ${{{{ '{args.baseline}' }}}}\n" if args.baseline else ""
    config_line = f"          config: ${{{{ '{args.config}' }}}}\n" if args.config else ""

    workflow_yaml = f"""# actenon-scan — finds where agent-controlled input reaches
# consequential actions without an authority check.
# Generated by: actenon-scan install github
# This workflow is non-blocking by default. To block on HIGH findings,
# delete this file and re-run with --blocking.
name: actenon-scan
on:
  pull_request:
    paths:
      - '**/*.py'
      - '**/*.ts'
      - '**/*.tsx'
      - '**/*.js'
      - '**/*.jsx'
      - '**/*.go'
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'
permissions:
  pull-requests: write
  security-events: write
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # required for --changed-only to diff against the base branch
      - uses: Actenon/actenon-scan@v1
        with:
          fail-on: {fail_on}
{baseline_line}{config_line}"""

    # Clean up trailing empty lines from optional baseline/config
    workflow_yaml = workflow_yaml.rstrip() + "\n"

    # 5. Dry-run: print without writing
    if args.dry_run:
        print(workflow_yaml)
        print(f"\n# Would write to: {workflow_path}", file=sys.stderr)
        return 0

    # 6. Backup existing file if --force
    if workflow_path.exists() and args.force:
        import shutil
        backup_path = workflow_path.with_suffix(".yml.bak")
        shutil.copy2(workflow_path, backup_path)
        print(f"Backed up existing workflow to {backup_path}")

    # 7. Create directory and write (atomic)
    workflow_dir.mkdir(parents=True, exist_ok=True)
    import tempfile
    fd, tmp_path = tempfile.mkstemp(
        dir=str(workflow_dir), suffix=".tmp", prefix=".actenon-scan-"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(workflow_yaml)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, workflow_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    # 8. Print summary
    blocking_desc = "blocks on HIGH findings" if args.blocking else "does not block merging"
    print(f"Created {workflow_path.relative_to(repo_root)}")
    print("Behaviour:")
    print("  ✓ scans pull-request changes (Python, TypeScript, Go)")
    print("  ✓ updates one PR comment (sticky, no duplicates)")
    print("  ✓ uploads SARIF to Security tab")
    print(f"  ✓ {blocking_desc}")
    if args.baseline:
        print(f"  ✓ uses baseline: {args.baseline}")
    if args.config:
        print(f"  ✓ uses config: {args.config}")
    print("Run locally:")
    print("  uvx actenon-scan scan .")
    print("Next steps:")
    print("  - Commit the workflow file")
    print("  - Open a PR to see the scan in action")
    if not args.baseline:
        print("  - Run 'actenon-scan baseline .' to create a baseline for existing findings")
    return 0


def _find_git_root(start: Path) -> Path | None:
    """Walk up from `start` to find the nearest .git directory."""
    current = start.resolve()
    while True:
        if (current / ".git").exists():
            return current
        if current.parent == current:
            return None
        current = current.parent
