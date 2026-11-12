"""Agent-first onboarding, doctor diagnostics, skill management, and pre-commit setup.

Designed for zero-friction adoption by both humans and coding agents:
  - ``actenon-scan setup``   : install SKILL.md + auto-link into detected agent harnesses + run readiness checks
  - ``actenon-scan doctor``  : verify language extras, git, config, CI/pre-commit hooks, and agent skill links
  - ``actenon-scan skill``   : status | install | link | uninstall for the embedded SKILL.md
  - ``actenon-scan install pre-commit`` : wire pre-commit hooks cleanly into .pre-commit-config.yaml

Zero runtime dependencies (100% Python stdlib). Never makes network calls, never uploads code,
and never overwrites or removes foreign files not owned by actenon-scan.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from actenon_scan import __version__
from actenon_scan.skill import SKILL_MARKER, SKILL_NAME, get_skill_markdown

MANIFEST_FILENAME = ".install-manifest.json"

# (harness_id, display_name, config_root_rel_to_home, skills_dir_rel_to_home)
KNOWN_AGENT_HARNESSES: tuple[tuple[str, str, str, str], ...] = (
    ("claude-code", "Claude Code", ".claude", ".claude/skills"),
    ("cursor", "Cursor", ".cursor", ".cursor/skills"),
    ("codex", "Codex", ".codex", ".codex/skills"),
    ("gemini-cli", "Gemini CLI", ".gemini", ".gemini/skills"),
    ("antigravity", "Antigravity", ".gemini/antigravity", ".gemini/antigravity/skills"),
    ("copilot", "GitHub Copilot", ".copilot", ".copilot/skills"),
    ("windsurf", "Windsurf", ".codeium/windsurf", ".codeium/windsurf/skills"),
    ("openclaw", "OpenClaw", ".openclaw", ".openclaw/skills"),
    ("hermes", "Hermes", ".hermes", ".hermes/skills"),
)

_PRUNED_WALK_DIRS = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "node_modules", "vendor", "bower_components", "__pycache__",
    "build", "dist", "target", ".eggs", ".mypy_cache", ".ruff_cache",
    ".tox", ".cache", ".pytest_cache",
})


def _resolve_home(home_dir: Path | None = None) -> Path:
    if home_dir is not None:
        return Path(home_dir).expanduser().resolve()
    override = os.environ.get("ACTENON_SCAN_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path.home().resolve()


def _canonical_skill_dir(home: Path) -> Path:
    return home / ".agents" / "skills" / SKILL_NAME


def _mkdir_secure(path: Path, stop_at: Path) -> None:
    """Create directories up to ``path`` with 0o700 permissions on newly created dirs, refusing symlinks."""
    if stop_at.is_symlink():
        raise RuntimeError(f"Refusing to traverse symlinked home directory: {stop_at}")
    if not stop_at.exists():
        stop_at.mkdir(mode=0o700, parents=True, exist_ok=True)
    rel_parts: list[Path] = []
    cur = path
    while cur != stop_at and cur.parent != cur:
        rel_parts.append(cur)
        cur = cur.parent
    for target in reversed(rel_parts):
        if target.is_symlink():
            raise RuntimeError(f"Refusing to traverse symlinked skill directory: {target}")
        if not target.exists():
            target.mkdir(mode=0o700, parents=False, exist_ok=True)
            try:
                os.chmod(target, 0o700)
            except OSError:
                pass


def _write_file_secure(path: Path, content: str) -> None:
    """Atomically write ``path`` with 0o600 permissions, refusing symlink targets."""
    if path.is_symlink():
        raise RuntimeError(f"Refusing to overwrite symlink file: {path}")
    parent = path.parent
    fd, tmp_name = tempfile.mkstemp(dir=str(parent), prefix=".actenon-skill-", suffix=".tmp")
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _read_manifest(canonical_dir: Path) -> dict[str, Any]:
    mpath = canonical_dir / MANIFEST_FILENAME
    if not mpath.exists() or mpath.is_symlink():
        return {}
    try:
        data = json.loads(mpath.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _is_owned_skill_target(target_dir: Path, canonical_dir: Path, recorded_links: set[str]) -> bool:
    """Return True if ``target_dir`` was installed/linked by actenon-scan."""
    if target_dir.is_symlink():
        try:
            resolved = target_dir.resolve()
            if resolved == canonical_dir.resolve():
                return True
        except OSError:
            pass
        return str(target_dir) in recorded_links
    if target_dir.is_dir():
        skill_md = target_dir / "SKILL.md"
        if skill_md.is_file() and not skill_md.is_symlink():
            try:
                txt = skill_md.read_text(encoding="utf-8", errors="replace")
                if SKILL_MARKER in txt:
                    return True
            except OSError:
                pass
    return False


@dataclass
class LinkOutcome:
    harness: str
    path: str
    status: str  # linked | already_linked | updated | skipped_foreign | would_link | removed
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "harness": self.harness,
            "path": self.path,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass
class SkillReport:
    action: str
    canonical_dir: str
    installed: bool
    dry_run: bool = False
    sha256: str = ""
    links: list[LinkOutcome] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "canonical_dir": self.canonical_dir,
            "installed": self.installed,
            "dry_run": self.dry_run,
            "sha256": self.sha256,
            "links": [lnk.to_dict() for lnk in self.links],
            "errors": list(self.errors),
        }


def install_and_link_skill(
    *,
    home_dir: Path | None = None,
    extra_link_dirs: list[Path] | None = None,
    link_harnesses: bool = True,
    dry_run: bool = False,
) -> SkillReport:
    """Install SKILL.md to ~/.agents/skills/actenon-scan and optionally link into agent harnesses."""
    home = _resolve_home(home_dir)
    canonical_dir = _canonical_skill_dir(home)
    skill_md_content = get_skill_markdown()
    digest = hashlib.sha256(skill_md_content.encode("utf-8")).hexdigest()
    report = SkillReport(
        action="install",
        canonical_dir=str(canonical_dir),
        installed=False,
        dry_run=dry_run,
        sha256=digest,
    )

    prev_manifest = _read_manifest(canonical_dir)
    recorded_links: set[str] = set(prev_manifest.get("linked_paths", []))

    # Validate canonical directory is not foreign before touching it.
    if canonical_dir.is_symlink():
        report.errors.append(
            f"Refusing to install: {canonical_dir} is a symlink."
        )
        return report
    if canonical_dir.exists() and not _is_owned_skill_target(canonical_dir, canonical_dir, recorded_links):
        skill_file = canonical_dir / "SKILL.md"
        if skill_file.exists():
            report.errors.append(
                f"Refusing to overwrite foreign skill at {canonical_dir} (missing actenon-scan marker)."
            )
            return report

    if not dry_run:
        try:
            _mkdir_secure(canonical_dir, home)
            _write_file_secure(canonical_dir / "SKILL.md", skill_md_content)
            report.installed = True
        except Exception as exc:
            report.errors.append(f"Failed to write canonical skill: {exc}")
            return report
    else:
        report.installed = (canonical_dir / "SKILL.md").exists()

    # Collect target skill parent directories to link into.
    targets: list[tuple[str, Path]] = []
    if link_harnesses:
        for _hid, display_name, cfg_rel, skills_rel in KNOWN_AGENT_HARNESSES:
            cfg_root = home / cfg_rel
            if cfg_root.exists() and not cfg_root.is_symlink():
                targets.append((display_name, home / skills_rel / SKILL_NAME))

    for custom_dir in extra_link_dirs or ():
        cpath = Path(custom_dir).expanduser().resolve()
        target = cpath if cpath.name == SKILL_NAME else (cpath / SKILL_NAME)
        targets.append(("Custom", target))

    seen_targets: set[Path] = set()
    for harness_name, link_target in targets:
        if link_target == canonical_dir or link_target in seen_targets:
            continue
        seen_targets.add(link_target)

        if link_target.exists() or link_target.is_symlink():
            if not _is_owned_skill_target(link_target, canonical_dir, recorded_links):
                report.links.append(
                    LinkOutcome(
                        harness=harness_name,
                        path=str(link_target),
                        status="skipped_foreign",
                        detail="Existing skill not managed by actenon-scan; left untouched.",
                    )
                )
                continue
            if link_target.is_symlink():
                try:
                    if link_target.resolve() == canonical_dir.resolve():
                        recorded_links.add(str(link_target))
                        report.links.append(
                            LinkOutcome(
                                harness=harness_name,
                                path=str(link_target),
                                status="already_linked",
                            )
                        )
                        continue
                except OSError:
                    pass
            if dry_run:
                report.links.append(
                    LinkOutcome(harness=harness_name, path=str(link_target), status="would_link")
                )
                continue
            try:
                if link_target.is_symlink() or link_target.is_file():
                    link_target.unlink()
                elif link_target.is_dir():
                    _write_file_secure(link_target / "SKILL.md", skill_md_content)
                    recorded_links.add(str(link_target))
                    report.links.append(
                        LinkOutcome(harness=harness_name, path=str(link_target), status="updated")
                    )
                    continue
            except OSError as exc:
                report.errors.append(f"Could not update {link_target}: {exc}")
                continue

        if dry_run:
            report.links.append(
                LinkOutcome(harness=harness_name, path=str(link_target), status="would_link")
            )
            continue

        try:
            link_target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                link_target.symlink_to(canonical_dir, target_is_directory=True)
                detail = f"-> {canonical_dir}"
            except OSError:
                # Windows without developer-mode symlink privilege: copy owned directory.
                link_target.mkdir(mode=0o700, parents=True, exist_ok=True)
                _write_file_secure(link_target / "SKILL.md", skill_md_content)
                detail = "copied (symlink unavailable)"
            recorded_links.add(str(link_target))
            report.links.append(
                LinkOutcome(
                    harness=harness_name,
                    path=str(link_target),
                    status="linked",
                    detail=detail,
                )
            )
        except OSError as exc:
            report.errors.append(f"Could not link {link_target}: {exc}")

    if not dry_run:
        manifest = {
            "installed_by": "actenon-scan",
            "version": __version__,
            "sha256": digest,
            "linked_paths": sorted(recorded_links),
        }
        try:
            _write_file_secure(
                canonical_dir / MANIFEST_FILENAME,
                json.dumps(manifest, indent=2) + "\n",
            )
        except Exception as exc:
            report.errors.append(f"Could not write skill manifest: {exc}")

    return report


def skill_status(*, home_dir: Path | None = None) -> SkillReport:
    """Inspect canonical SKILL.md installation and harness links without modifying disk."""
    home = _resolve_home(home_dir)
    canonical_dir = _canonical_skill_dir(home)
    skill_file = canonical_dir / "SKILL.md"
    installed = skill_file.is_file() and not skill_file.is_symlink()
    sha = ""
    if installed:
        try:
            sha = hashlib.sha256(skill_file.read_bytes()).hexdigest()
        except OSError:
            sha = ""
    manifest = _read_manifest(canonical_dir)
    recorded_links = set(manifest.get("linked_paths", []))
    report = SkillReport(
        action="status",
        canonical_dir=str(canonical_dir),
        installed=installed,
        sha256=sha,
    )
    for _hid, display_name, cfg_rel, skills_rel in KNOWN_AGENT_HARNESSES:
        cfg_root = home / cfg_rel
        link_target = home / skills_rel / SKILL_NAME
        if not cfg_root.exists() and not link_target.exists() and not link_target.is_symlink():
            continue
        if link_target.exists() or link_target.is_symlink():
            if _is_owned_skill_target(link_target, canonical_dir, recorded_links):
                report.links.append(
                    LinkOutcome(harness=display_name, path=str(link_target), status="linked")
                )
            else:
                report.links.append(
                    LinkOutcome(
                        harness=display_name,
                        path=str(link_target),
                        status="skipped_foreign",
                        detail="Foreign skill present",
                    )
                )
        else:
            report.links.append(
                LinkOutcome(
                    harness=display_name,
                    path=str(link_target),
                    status="not_linked",
                    detail="Harness detected; run 'actenon-scan setup' to link",
                )
            )
    return report


def uninstall_skill(*, home_dir: Path | None = None, dry_run: bool = False) -> SkillReport:
    """Remove actenon-scan's managed SKILL.md and owned harness links without touching foreign files."""
    home = _resolve_home(home_dir)
    canonical_dir = _canonical_skill_dir(home)
    manifest = _read_manifest(canonical_dir)
    recorded_links = set(manifest.get("linked_paths", []))
    report = SkillReport(
        action="uninstall",
        canonical_dir=str(canonical_dir),
        installed=(canonical_dir / "SKILL.md").exists(),
        dry_run=dry_run,
    )

    candidate_links: list[tuple[str, Path]] = []
    for _hid, display_name, _cfg_rel, skills_rel in KNOWN_AGENT_HARNESSES:
        candidate_links.append((display_name, home / skills_rel / SKILL_NAME))
    for recorded in sorted(recorded_links):
        rpath = Path(recorded)
        if all(rpath != existing for _, existing in candidate_links):
            candidate_links.append(("Custom", rpath))

    for harness_name, link_target in candidate_links:
        if not link_target.exists() and not link_target.is_symlink():
            continue
        if not _is_owned_skill_target(link_target, canonical_dir, recorded_links):
            report.links.append(
                LinkOutcome(
                    harness=harness_name,
                    path=str(link_target),
                    status="skipped_foreign",
                    detail="Foreign file/directory left untouched",
                )
            )
            continue
        if dry_run:
            report.links.append(
                LinkOutcome(harness=harness_name, path=str(link_target), status="would_remove")
            )
            continue
        try:
            if link_target.is_symlink() or link_target.is_file():
                link_target.unlink()
            elif link_target.is_dir():
                shutil.rmtree(link_target)
            report.links.append(
                LinkOutcome(harness=harness_name, path=str(link_target), status="removed")
            )
        except OSError as exc:
            report.errors.append(f"Could not remove {link_target}: {exc}")

    if canonical_dir.exists() or canonical_dir.is_symlink():
        if _is_owned_skill_target(canonical_dir, canonical_dir, recorded_links):
            if not dry_run:
                try:
                    if canonical_dir.is_symlink() or canonical_dir.is_file():
                        canonical_dir.unlink()
                    else:
                        shutil.rmtree(canonical_dir)
                    report.installed = False
                except OSError as exc:
                    report.errors.append(f"Could not remove {canonical_dir}: {exc}")
        else:
            report.errors.append(
                f"Skipped {canonical_dir}: does not contain actenon-scan ownership marker."
            )

    return report


def _count_workspace_languages(root: Path, max_files: int = 4000) -> dict[str, int]:
    counts = {"python": 0, "typescript": 0, "go": 0}
    if not root.is_dir():
        return counts
    seen = 0
    ts_exts = {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _PRUNED_WALK_DIRS]
        for fname in filenames:
            seen += 1
            if seen > max_files:
                return counts
            ext = os.path.splitext(fname)[1].lower()
            if ext == ".py":
                counts["python"] += 1
            elif ext in ts_exts:
                counts["typescript"] += 1
            elif ext == ".go":
                counts["go"] += 1
    return counts


def collect_doctor_report(
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> dict[str, Any]:
    """Build structured environment & workspace readiness diagnostics."""
    work_dir = (Path(cwd) if cwd is not None else Path.cwd()).resolve()
    from actenon_scan.detectors.typescript import is_typescript_extra_available
    from actenon_scan.detectors.go import is_go_extra_available

    ts_ok = is_typescript_extra_available()
    go_ok = is_go_extra_available()
    try:
        import yaml as _yaml  # noqa: F401
        yaml_ok = True
    except ImportError:
        yaml_ok = False

    git_bin = shutil.which("git")
    git_ok = git_bin is not None
    in_git_repo = False
    if git_ok:
        try:
            # actenon-scan: ignore[EXEC-SHELL] — constant-argv read-only git worktree probe (shell=False)
            proc = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(work_dir),
                capture_output=True,
                text=True,
                timeout=3,
            )
            in_git_repo = proc.returncode == 0
        except Exception:
            in_git_repo = False

    lang_counts = _count_workspace_languages(work_dir)
    config_found: str | None = None
    for cfg_name in (
        ".actenon-scan.json",
        "actenon-scan.json",
        ".actenon-scan.yml",
        ".actenon-scan.yaml",
        "actenon-scan.yml",
        "actenon-scan.yaml",
    ):
        if (work_dir / cfg_name).is_file():
            config_found = cfg_name
            break

    gh_workflow = (work_dir / ".github" / "workflows" / "actenon-scan.yml").is_file()
    pre_commit_cfg = (work_dir / ".pre-commit-config.yaml").is_file()
    pre_commit_wired = False
    if pre_commit_cfg:
        try:
            pre_commit_wired = "actenon-scan" in (work_dir / ".pre-commit-config.yaml").read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            pre_commit_wired = False

    skill_rep = skill_status(home_dir=home_dir)

    warnings: list[str] = []
    recommendations: list[str] = []
    if lang_counts["typescript"] > 0 and not ts_ok:
        warnings.append(
            f"Workspace contains {lang_counts['typescript']} TypeScript/JS file(s), "
            f"but [typescript] parser extra is not installed (they will be reported as unsupported)."
        )
        recommendations.append('pip install "actenon-scan[all]"')
    if lang_counts["go"] > 0 and not go_ok:
        warnings.append(
            f"Workspace contains {lang_counts['go']} Go file(s), "
            f"but [go] parser extra is not installed (they will be reported as unsupported)."
        )
        if 'pip install "actenon-scan[all]"' not in recommendations:
            recommendations.append('pip install "actenon-scan[all]"')
    if config_found and config_found.endswith((".yml", ".yaml")) and not yaml_ok:
        warnings.append(
            f"Found YAML config {config_found}, but [yaml] extra (PyYAML) is not installed."
        )
        if 'pip install "actenon-scan[all]"' not in recommendations:
            recommendations.append('pip install "actenon-scan[yaml]"')
    if not skill_rep.installed:
        recommendations.append("actenon-scan setup")

    return {
        "version": __version__,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "cwd": str(work_dir),
        "parsers": {
            "python": True,
            "typescript": ts_ok,
            "go": go_ok,
            "yaml_config": yaml_ok,
        },
        "git": {
            "installed": git_ok,
            "inside_work_tree": in_git_repo,
        },
        "workspace": {
            "file_counts": lang_counts,
            "config_file": config_found,
            "github_workflow": gh_workflow,
            "pre_commit_hook": pre_commit_wired,
        },
        "skill": skill_rep.to_dict(),
        "ready_for_workspace": len(warnings) == 0,
        "warnings": warnings,
        "recommendations": recommendations,
    }


def format_doctor_text(report: dict[str, Any]) -> str:
    parsers = report["parsers"]
    ws = report["workspace"]
    counts = ws["file_counts"]
    skill = report["skill"]
    linked = [lnk for lnk in skill["links"] if lnk["status"] in ("linked", "already_linked", "updated")]

    lines = [
        f"actenon-scan doctor (v{report['version']}, Python {report['python']})",
        "",
        "Language & Config Support:",
        "  [ok] Python AST + repository call-graph engine (built-in, 0 runtime deps)",
        (
            "  [ok] TypeScript / JavaScript (tree-sitter-typescript installed)"
            if parsers["typescript"]
            else '  [..] TypeScript / JavaScript optional extra not installed (pip install "actenon-scan[all]")'
        ),
        (
            "  [ok] Go (tree-sitter-go installed)"
            if parsers["go"]
            else '  [..] Go optional extra not installed (pip install "actenon-scan[all]")'
        ),
        (
            "  [ok] YAML config (PyYAML installed; JSON always built-in)"
            if parsers["yaml_config"]
            else "  [..] YAML config optional extra not installed (JSON .actenon-scan.json works built-in)"
        ),
        "",
        f"Workspace ({report['cwd']}):",
        f"  Detected files: {counts['python']} Python, {counts['typescript']} TypeScript/JS, {counts['go']} Go",
        f"  Git --changed-only: {'ready' if report['git']['inside_work_tree'] else ('git installed (not a git repo)' if report['git']['installed'] else 'git not found')}",
        f"  Config file: {ws['config_file'] or 'none (using defaults)'}",
        f"  GitHub Action: {'configured (.github/workflows/actenon-scan.yml)' if ws['github_workflow'] else 'not configured (run: actenon-scan install github)'}",
        f"  Pre-commit hook: {'configured (.pre-commit-config.yaml)' if ws['pre_commit_hook'] else 'not configured (run: actenon-scan install pre-commit)'}",
        "",
        "Agent Skill Integration:",
        (
            f"  [ok] Canonical skill installed: {skill['canonical_dir']}/SKILL.md"
            if skill["installed"]
            else f"  [..] Canonical skill not installed yet (run: actenon-scan setup)"
        ),
    ]
    if linked:
        names = ", ".join(f"{lnk['harness']}" for lnk in linked)
        lines.append(f"  [ok] Linked into agent harnesses: {names}")
    elif skill["links"]:
        unlinked = [lnk["harness"] for lnk in skill["links"] if lnk["status"] == "not_linked"]
        if unlinked:
            lines.append(f"  [..] Detected unlinked harnesses: {', '.join(unlinked)} (run: actenon-scan setup)")

    if report["warnings"]:
        lines.append("")
        lines.append("Warnings:")
        for w in report["warnings"]:
            lines.append(f"  ! {w}")

    lines.append("")
    lines.append("Next:")
    for rec in report["recommendations"]:
        lines.append(f"  {rec}")
    lines.append("  actenon-scan .")
    return "\n".join(lines)


def install_pre_commit(
    *,
    cwd: Path | None = None,
    dry_run: bool = False,
    force: bool = False,
    blocking: bool = False,
) -> tuple[int, str]:
    """Create or append actenon-scan hooks in .pre-commit-config.yaml."""
    work_dir = (Path(cwd) if cwd is not None else Path.cwd()).resolve()
    # Walk upward for .git root if inside one; otherwise write in work_dir.
    repo_root = work_dir
    cur = work_dir
    while True:
        if (cur / ".git").exists():
            repo_root = cur
            break
        if cur.parent == cur:
            break
        cur = cur.parent

    cfg_path = repo_root / ".pre-commit-config.yaml"
    lang_counts = _count_workspace_languages(repo_root)
    fail_arg = "high" if blocking else "none"

    hook_lines = [
        "  - repo: https://github.com/Actenon/actenon-scan",
        f"    rev: v{__version__}",
        "    hooks:",
        "      - id: actenon-scan",
        f'        args: ["--fail-on", "{fail_arg}", "--no-cache"]',
    ]
    if lang_counts["typescript"] > 0:
        hook_lines.extend([
            "      - id: actenon-scan-typescript",
            f'        args: ["--fail-on", "{fail_arg}", "--no-cache"]',
        ])
    if lang_counts["go"] > 0:
        hook_lines.extend([
            "      - id: actenon-scan-go",
            f'        args: ["--fail-on", "{fail_arg}", "--no-cache"]',
        ])
    repo_block = "\n".join(hook_lines) + "\n"

    if cfg_path.exists():
        existing = cfg_path.read_text(encoding="utf-8", errors="replace")
        if "actenon-scan" in existing and not force:
            return (
                0,
                f"{cfg_path} already configures actenon-scan (use --force to replace).",
            )
        if force and "actenon-scan" in existing:
            new_content = "repos:\n" + repo_block
        elif "repos:" in existing:
            sep = "" if existing.endswith("\n") else "\n"
            new_content = existing + sep + repo_block
        else:
            sep = "\n" if existing and not existing.endswith("\n") else ""
            new_content = existing + sep + "repos:\n" + repo_block
    else:
        new_content = "repos:\n" + repo_block

    if dry_run:
        return (0, new_content.rstrip())

    _write_file_secure_public(cfg_path, new_content)
    msg = (
        f"Configured {cfg_path.name} with actenon-scan pre-commit hook(s).\n"
        f"Activate locally with:\n"
        f"  pre-commit install"
    )
    return (0, msg)


def install_workspace_mcp(
    *,
    cwd: Path | None = None,
    dry_run: bool = False,
    force: bool = False,
) -> tuple[int, str]:
    """Register ``actenon-scan mcp-server`` in workspace ``.mcp.json`` non-destructively."""
    work_dir = (Path(cwd) if cwd is not None else Path.cwd()).resolve()
    mcp_path = work_dir / ".mcp.json"
    existing_data: dict[str, Any] = {}
    if mcp_path.exists():
        try:
            loaded = json.loads(mcp_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                existing_data = loaded
            else:
                return (2, f"Error: {mcp_path} root must be a JSON object.")
        except (OSError, json.JSONDecodeError) as exc:
            return (2, f"Error: could not parse existing {mcp_path}: {exc}")

    servers = existing_data.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
        existing_data["mcpServers"] = servers

    if "actenon-scan" in servers and not force:
        return (0, f"{mcp_path.name} already registers actenon-scan (use --force to update).")

    servers["actenon-scan"] = {
        "command": "actenon-scan",
        "args": ["mcp-server"],
    }
    rendered = json.dumps(existing_data, indent=2) + "\n"
    if dry_run:
        return (0, rendered.rstrip())

    _write_file_secure_public(mcp_path, rendered)
    return (0, f"Registered native MCP server `actenon-scan` in {mcp_path.name}.")


def _write_file_secure_public(path: Path, content: str) -> None:
    """Atomically write a project config file (respecting standard repo file mode 0o644)."""
    if path.is_symlink():
        raise RuntimeError(f"Refusing to overwrite symlink file: {path}")
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".actenon-pc-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
