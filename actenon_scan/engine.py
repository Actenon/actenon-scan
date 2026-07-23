"""Scan engine — orchestrates AST parsing, sink detection, reachability, and guard checks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from actenon_scan.detectors.guards import is_guarded
from actenon_scan.detectors.reachability import detect_reachability
from actenon_scan.detectors.sinks import detect_sinks
from actenon_scan.rules.loader import Ruleset, load_rules


@dataclass
class Finding:
    file: str
    line: int
    col: int
    rule_id: str
    category: str
    severity: str
    confidence: str
    description: str
    call_text: str
    remediation: str
    suppressed: bool = False
    suppression_reason: str = ""
    snippet_hash: str = ""
    tier: str = "production"

    @property
    def effective_severity(self) -> str:
        """Downgrade severity one notch if confidence is MEDIUM."""
        if self.confidence == "medium":
            return _downgrade_severity(self.severity)
        return self.severity


def _downgrade_severity(severity: str) -> str:
    mapping = {"high": "medium", "medium": "low", "low": "low"}
    return mapping.get(severity, severity)


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    rules_used: Ruleset | None = None
    # Per-file analysis errors caught by the defensive wrapper in scan_path.
    # Each tuple is (relative_path, error_message). One malformed file should
    # never zero out a whole repo — see the v0.2.2 crash where a single
    # AttributeError in _find_declarative_guarded_classes killed 7 of 14 repos.
    analysis_errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len([f for f in self.findings if not f.suppressed])

    def has_findings_at_or_above(self, threshold: str) -> bool:
        threshold_level = SEVERITY_ORDER.get(threshold, 0)
        for f in self.findings:
            if f.suppressed:
                continue
            if SEVERITY_ORDER.get(f.effective_severity, 0) >= threshold_level:
                return True
        return False


def _assign_tier(filepath: str) -> str:
    """Assign a tier to a finding based on its file path.

    Returns "example" if the file is in a demo/examples/cookbook/samples/docs
    directory, "production" otherwise.
    """
    example_patterns = (
        "/examples/", "/example/",
        "/cookbook/", "/recipes/",
        "/samples/", "/sample/",
        "/docs/", "/doc/", "/documentation/",
        "/tutorials/", "/tutorial/",
        "/benchmarks/", "/benchmark/",
        "/demo/", "/demos/",
    )
    # Normalize path separators
    normalized = "/" + filepath.replace("\\", "/").lstrip("/")
    for pattern in example_patterns:
        if pattern in normalized:
            return "example"
    # Also check if the path STARTS with one of these (root-level)
    root_patterns = (
        "examples/", "example/", "cookbook/", "recipes/",
        "samples/", "sample/", "docs/", "doc/",
        "tutorials/", "tutorial/", "benchmarks/", "benchmark/",
        "demo/", "demos/",
    )
    for pattern in root_patterns:
        if normalized.lstrip("/").startswith(pattern):
            return "example"
    return "production"


def _build_parent_map_for_engine(tree: ast.AST) -> dict[int, ast.AST]:
    """Build a map from node id() to parent node."""
    parent_map: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[id(child)] = parent
    return parent_map


def _find_declarative_guarded_classes(
    tree: ast.Module, reachability_cfg: dict
) -> set[str]:
    """Find class names that carry a declarative authorization guard.

    A class is guarded when any of:
    - It assigns a listed class_attributes name at class body level to a truthy
      literal (requires_auth = True)
    - It carries a listed decorator on the class
    - It is instantiated with a listed constructor_params keyword argument

    Inheritance: if a class subclasses a guarded class (in the same file), it
    inherits the guard.
    """
    decl_cfg = reachability_cfg.get("declarative_guards", {})
    class_attrs = set(decl_cfg.get("class_attributes", []))
    decorators = set(decl_cfg.get("decorators", []))
    constructor_params = set(decl_cfg.get("constructor_params", []))

    guarded_classes: set[str] = set()

    # Pass 1: detect direct guards on class definitions
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        # Check class attributes (requires_auth = True)
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id in class_attrs:
                        # Check if value is truthy
                        if isinstance(stmt.value, ast.Constant) and stmt.value.value:
                            guarded_classes.add(node.name)
                        elif isinstance(stmt.value, ast.Name) and stmt.value.id == "True":
                            guarded_classes.add(node.name)

            # Check annotated assignments (requires_auth: bool = True)
            if isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name) and stmt.target.id in class_attrs:
                    if stmt.value and isinstance(stmt.value, ast.Constant) and stmt.value.value:
                        guarded_classes.add(node.name)

        # Check class decorators
        for decorator in node.decorator_list:
            decorator_name = _get_decorator_name_for_guards(decorator)
            if decorator_name in decorators:
                guarded_classes.add(node.name)

    # Pass 2: detect constructor params (AuthPlugin(permissions=[...]))
    # A guarded class is one instantiated with a declared constructor_params
    # kwarg (e.g. Tool(dependencies=[Depends(auth)])). The callee may be a
    # bare Name (Tool(...)), an Attribute (module.Tool(...)), or a chained
    # Call (Foo()(...)) — use _callee_name to handle all shapes safely.
    # NOTE: ast.Name exposes `.id`, NOT `.name` (only ClassDef/FunctionDef
    # have `.name`). Using `.name` on a Name crashes with AttributeError —
    # this was the v0.2.2 release-blocking bug.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg in constructor_params:
                name = _callee_name(node.func)
                if name:
                    guarded_classes.add(name)

    # Pass 3: inheritance — subclasses of guarded classes inherit the guard
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for base in node.bases:
                base_name = _get_base_name_for_guards(base)
                if base_name in guarded_classes and node.name not in guarded_classes:
                    guarded_classes.add(node.name)
                    changed = True

    return guarded_classes


def _callee_name(func: ast.expr) -> str | None:
    """Return the callable name for a Call's `func` node.

    Handles all common call shapes so the constructor_params guard pass
    doesn't crash on plain constructor calls:
      Tool(...)              -> ast.Name       -> 'Tool'
      pkg.Tool(...)          -> ast.Attribute  -> 'Tool'
      Foo()(...)             -> ast.Call       -> recurse on .func
      (lambda: x)()          -> ast.Lambda     -> None
    """
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Call):
        return _callee_name(func.func)
    return None


def _get_decorator_name_for_guards(node: ast.expr) -> str:
    """Get the name of a decorator."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _get_decorator_name_for_guards(node.func)
    return ""


def _get_base_name_for_guards(node: ast.expr) -> str:
    """Get the name of a base class."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _is_in_declarative_guarded_class(
    tree: ast.Module,
    sink_line: int,
    guarded_classes: set[str],
    parent_map: dict[int, ast.AST],
) -> str | None:
    """Check if the sink at sink_line is inside a method of a guarded class,
    or inside a function with a declarative guard decorator.

    Returns the guard reason (e.g., "requires_auth") if suppressed, None otherwise.
    """
    if not guarded_classes:
        # Even if no guarded classes, check for function-level declarative guards
        pass

    # Find the node at sink_line
    sink_node = None
    for node in ast.walk(tree):
        if hasattr(node, "lineno") and node.lineno == sink_line:
            if isinstance(node, ast.Call):
                sink_node = node
                break

    if sink_node is None:
        return None

    # Walk up the parent chain
    current = parent_map.get(id(sink_node))
    while current is not None:
        # Check if we're in a function with a declarative guard decorator
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decl_cfg = parent_map  # not ideal but we need access to the config
            # Check function decorators against the declarative_guards.decorators list
            # We need to get the config — but we don't have it here directly.
            # Instead, check if any decorator name matches common guard patterns.
            for decorator in current.decorator_list:
                decorator_name = _get_decorator_name_for_guards(decorator)
                # Check against a broad set of guard decorator names
                if decorator_name in (
                    "requires_auth", "require_auth", "requires_permission",
                    "require_permission", "authenticated", "login_required",
                    "permission_required", "requires_approval", "requires_confirmation",
                    "human_in_the_loop", "authorize", "authorized"
                ):
                    return f"decorator:{decorator_name}"

        # Check if we're in a guarded class
        if isinstance(current, ast.ClassDef):
            if current.name in guarded_classes:
                for stmt in current.body:
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                return target.id
                return "declarative_guard"
            for base in current.bases:
                base_name = _get_base_name_for_guards(base)
                if base_name in guarded_classes:
                    return f"inherited:{base_name}"
        current = parent_map.get(id(current))

    return None


def _detect_self_package(target: Path) -> str | None:
    """Auto-detect the package name of the repo being scanned.

    Looks for pyproject.toml at the target root and extracts the package name.
    This is used for self-scan suppression: when scanning a framework's own
    repo (e.g., crewAI), the agent_framework_import signal is suppressed for
    that package so internal functions don't get false-positive reachability.
    """
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return None

    # Look for pyproject.toml at the target root (or parent dirs)
    search_dir = target if target.is_dir() else target.parent
    for _ in range(3):  # check up to 3 levels up
        pyproject = search_dir / "pyproject.toml"
        if pyproject.exists():
            try:
                with open(pyproject, "rb") as f:
                    data = tomllib.load(f)
                name = data.get("project", {}).get("name", "")
                if name:
                    # Normalize: "actenon-scan" → "actenon_scan"
                    return name.replace("-", "_")
            except Exception:
                pass
            break
        if search_dir.parent == search_dir:
            break
        search_dir = search_dir.parent
    return None


def scan_path(
    target: str | Path,
    *,
    config: str | Path | None = None,
    include_globs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    suppressions: set[tuple[str, str]] | None = None,
    baseline_findings: dict[str, set[str]] | None = None,
    self_package: str | None = None,
) -> ScanResult:
    """Scan a file or directory for the execution gap.

    Args:
        self_package: The package name of the repo being scanned (e.g., "crewai"
            when scanning the crewAI repo). When set, the agent_framework_import
            reachability signal is suppressed for that package, preventing
            self-scan noise (every file in a framework's own repo imports the
            framework). Auto-detected from pyproject.toml if not provided.
    """
    rules = load_rules(config)
    target = Path(target)
    files = _collect_files(target, include_globs, exclude_globs)
    findings: list[Finding] = []
    analysis_errors: list[tuple[str, str]] = []

    # Auto-detect self_package from pyproject.toml if not provided
    if self_package is None:
        self_package = _detect_self_package(target)

    for filepath in files:
        rel = str(filepath.relative_to(target) if target.is_dir() else filepath.name)
        try:
            source = filepath.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(filepath))
        except (SyntaxError, UnicodeDecodeError):
            continue

        # Defensive per-file wrapper: a single malformed AST node, an
        # unexpected ast shape, or a bug in any detector must NOT zero out
        # the rest of the repo. Record the error and move on. This is the
        # lesson from v0.2.2 where one AttributeError in
        # _find_declarative_guarded_classes crashed 7 of 14 scanned repos.
        try:
            sink_findings = detect_sinks(tree, str(filepath), rules.sinks)
            # Detect declarative guards (class attributes, decorators, constructor params)
            declarative_guarded_classes = _find_declarative_guarded_classes(tree, rules.reachability)
            parent_map = _build_parent_map_for_engine(tree)

            for sf in sink_findings:
                reach = detect_reachability(tree, sf.line, rules.reachability, self_package=self_package)
                if reach.confidence == "none":
                    continue  # not agent-reachable — skip

                guarded = is_guarded(tree, sf.line, rules.guard_patterns)
                if guarded:
                    continue  # guarded by inline guard call — no finding

                # Check declarative guards (class-level authorization)
                declarative_suppressed = _is_in_declarative_guarded_class(
                    tree, sf.line, declarative_guarded_classes, parent_map
                )

                severity = sf.severity
                if reach.confidence == "medium":
                    severity = _downgrade_severity(severity)

                snippet_hash = _compute_snippet_hash(source, sf.line)

                finding = Finding(
                    file=rel,
                    line=sf.line,
                    col=sf.col,
                    rule_id=sf.rule_id,
                    category=sf.category,
                    severity=severity,
                    confidence=reach.confidence,
                    description=sf.description,
                    call_text=sf.call_text,
                    remediation=_remediation_hint(sf.category),
                    snippet_hash=snippet_hash,
                    tier=_assign_tier(rel),
                )

                # Apply declarative guard suppression
                if declarative_suppressed:
                    finding.suppressed = True
                    finding.suppression_reason = f"declarative_guard:{declarative_suppressed}"

                # Check inline suppression
                if suppressions and (rel, sf.rule_id) in suppressions:
                    finding.suppressed = True
                    finding.suppression_reason = "inline_suppression"

                # Check baseline
                if baseline_findings:
                    file_baselines = baseline_findings.get(rel, set())
                    if snippet_hash in file_baselines:
                        finding.suppressed = True

                findings.append(finding)
        except Exception as exc:
            # Record and continue — never let one file kill the repo scan.
            analysis_errors.append((rel, f"{type(exc).__name__}: {exc}"))
            continue

    return ScanResult(
        findings=findings,
        files_scanned=len(files),
        rules_used=rules,
        analysis_errors=analysis_errors,
    )


def _collect_files(
    target: Path,
    include_globs: list[str] | None,
    exclude_globs: list[str] | None,
) -> list[Path]:
    """Collect .py files to scan, respecting include/exclude globs.

    When no --include globs are specified, ALL .py files in the target
    directory are scanned. Test files are skipped by default (test_*.py,
    *_test.py, files in tests/ or test/ directories) to reduce noise —
    use --include to override or --exclude to add patterns.
    """

    if target.is_file():
        return [target] if target.suffix == ".py" else []

    # Collect all .py files recursively
    all_py_files = list(target.rglob("*.py"))

    # If no include globs specified, scan all .py files (minus excludes)
    if not include_globs:
        include_globs = ["**/*.py"]

    # Default excludes: virtual envs, build dirs, and dependency dirs.
    # These always cause false positives (vendored code, installed packages,
    # build artifacts) and should never be scanned unless the user explicitly
    # includes them.
    #
    # NOTE: examples/, cookbook/, samples/, docs/ are NOT excluded — they are
    # tiered as "example" findings instead. See _assign_tier().
    default_dir_excludes = [
        ".git/**", ".hg/**", ".svn/**",
        ".venv/**", "venv/**", "env/**", ".env/**",
        ".actenon-env/**", ".scan-env/**", ".scan-venv/**", ".tox/**",
        ".cache/**", ".pytest_cache/**",
        "node_modules/**", "bower_components/**",
        "__pycache__/**", "*.pyc",
        "build/**", "dist/**", "target/**",
        ".eggs/**", "*.egg-info/**",
        ".mypy_cache/**", ".ruff_cache/**",
        ".coverage/**", "htmlcov/**",
        # Actenon's own shipped test fixtures (defensive — the wheel also
        # excludes them now, but this catches source-checkout scans).
        "**/tests/fixtures/**",
    ]

    # Detect virtual environments by marker file (pyvenv.cfg). Any directory
    # containing pyvenv.cfg is a venv, regardless of its name. This catches
    # arbitrarily-named venvs like .scan-venv, my-env, etc.
    venv_dirs: set[str] = set()
    for cfg in target.rglob("pyvenv.cfg"):
        # The venv root is the directory containing pyvenv.cfg
        venv_root = cfg.parent
        try:
            rel = venv_root.relative_to(target)
            venv_dirs.add(str(rel))
        except ValueError:
            pass
    for venv_dir in venv_dirs:
        default_dir_excludes.append(f"{venv_dir}/**")

    # Default excludes: test files (unless user explicitly includes them)
    # We exclude test_*.py and *_test.py files at ANY depth in the tree,
    # plus conftest.py. We do NOT exclude tests/ directories themselves
    # (they may contain agent tool fixtures that aren't named test_*.py).
    default_test_excludes = [
        "**/test_*.py",
        "**/*_test.py",
        "**/conftest.py",
    ]
    exclude = list(exclude_globs or [])

    # Always exclude venv/build/dependency dirs (user can't override via
    # --include; if they really want to scan a venv, they should point
    # scan_path directly at it).
    exclude.extend(default_dir_excludes)

    # Only add default test excludes if the user didn't explicitly include test files
    if not any("test" in g.lower() for g in (include_globs or [])):
        exclude.extend(default_test_excludes)

    files = []
    for filepath in all_py_files:
        rel = filepath.relative_to(target)
        rel_str = str(rel)

        # Check excludes
        excluded = False
        for pattern in exclude:
            if _glob_match(rel_str, pattern):
                excluded = True
                break
        if excluded:
            continue

        # Check includes — if any include matches, the file is included
        included = False
        for pattern in include_globs:
            if _glob_match(rel_str, pattern):
                included = True
                break
        if included:
            files.append(filepath)

    return files


def _glob_match(rel_path: str, pattern: str) -> bool:
    """Match a relative path against a glob pattern.

    Handles ** patterns (recursive) that fnmatch doesn't support natively.
    Also handles directory-prefix excludes like `.venv/**` (match anything
    under .venv/) and `**/tests/fixtures/**` (match anywhere in the tree).
    """
    import fnmatch as _fnmatch

    # Normalize: **/*.py matches everything ending in .py
    if pattern == "**/*.py":
        return rel_path.endswith(".py")

    # Handle **/filename patterns — match the filename anywhere in the tree
    # e.g. **/test_*.py matches lib/tests/rag/test_csv_loader.py
    if pattern.startswith("**/") and not pattern.endswith("/**"):
        # Strip the **/ prefix and use fnmatch on the basename + full path
        file_pattern = pattern[3:]
        # Match against the full path (fnmatch * crosses /)
        if _fnmatch.fnmatch(rel_path, f"*/{file_pattern}") or _fnmatch.fnmatch(rel_path, file_pattern):
            return True
        # Also match against just the basename for deep paths
        basename = rel_path.split("/")[-1]
        if _fnmatch.fnmatch(basename, file_pattern):
            return True
        return False

    # Handle **/dir/** and **/dir/subdir/** patterns — match anywhere in the
    # tree under the named directory. Must be checked BEFORE the dir/** branch
    # because both end with /**.
    if pattern.startswith("**/") and pattern.endswith("/**"):
        middle = pattern[3:-3]  # strip **/ and /**
        parts = rel_path.split("/")
        # middle may be a multi-segment path like "tests/fixtures"
        middle_parts = middle.split("/")
        # Check if middle_parts appears as a contiguous subsequence in parts
        for i in range(len(parts) - len(middle_parts) + 1):
            if parts[i : i + len(middle_parts)] == middle_parts:
                return True
        return False

    # Handle dir/** patterns — match anything under that directory
    if pattern.endswith("/**"):
        prefix = pattern[:-3]  # strip the /**
        # Match if the path is inside the prefix directory
        parts = rel_path.split("/")
        for i, part in enumerate(parts[:-1]):  # don't match the last part (filename)
            if "/".join(parts[: i + 1]) == prefix:
                return True
        # Also match if the prefix itself appears as a path segment anywhere
        if prefix in rel_path.split("/"):
            return True
        return False

    # Convert ** to a wildcard that fnmatch can handle
    normalized_pattern = pattern.replace("**/", "")
    return _fnmatch.fnmatch(rel_path, normalized_pattern) or _fnmatch.fnmatch(rel_path, pattern)


def _compute_snippet_hash(source: str, line: int) -> str:
    """Compute a normalized hash of the code snippet for baseline matching.

    This is resilient to line-number drift — it hashes the line content
    + surrounding context, not the line number.
    """
    import hashlib
    lines = source.splitlines()
    # Use the target line + 1 line of context above (if available)
    start = max(0, line - 2)
    end = min(len(lines), line)
    snippet = "\n".join(lines[start:end])
    # Normalize whitespace
    normalized = re.sub(r"\s+", " ", snippet.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _remediation_hint(category: str) -> str:
    """Provide remediation guidance with MULTIPLE routes (not Actenon-only).

    Each finding offers several remediation routes:
      1. Add an existing internal guard (if one exists but isn't recognised)
      2. Register the guard with Scan (so it's recognised in future scans)
      3. Use Actenon Kernel (proof verification at the edge)
      4. Use brokered Actenon protection (Permit + broker + adapter)
      5. Redesign the boundary (if the action shouldn't be reachable)
    """
    hints = {
        "payments": (
            "Guard this payment call before execution. Options: "
            "(1) add an existing internal authorization check, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel proof verification, "
            "(4) use brokered Actenon protection (Permit + adapter), "
            "(5) redesign the boundary if this action should not be agent-reachable."
        ),
        "data_destruction": (
            "Guard this destructive call before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
        "deployment": (
            "Guard this deployment call before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
        "access_control": (
            "Guard this access-control mutation before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
        "communication": (
            "Guard this send-on-behalf call before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
        "provider_sdk": (
            "Guard this provider SDK call before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection (adapter wraps the SDK), "
            "(5) redesign the boundary."
        ),
        "database_mutation": (
            "Guard this database mutation before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
        "identity_change": (
            "Guard this identity/IAM mutation before execution. Options: "
            "(1) add an existing internal guard, "
            "(2) register it with scan --config, "
            "(3) use Actenon Kernel, "
            "(4) use brokered Actenon protection, "
            "(5) redesign the boundary."
        ),
    }
    return hints.get(category, (
        "Guard this action before execution. Options: "
        "(1) add an existing internal guard, "
        "(2) register it with scan --config, "
        "(3) use Actenon Kernel, "
        "(4) use brokered Actenon protection, "
        "(5) redesign the boundary."
    ))
