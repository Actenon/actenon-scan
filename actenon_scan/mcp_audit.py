"""Agent & MCP Environment X-Ray (``actenon-scan audit``).

Discovers and statically audits:
  1. Workspace & (opt-in ``--machine``) host MCP server configurations across
     Claude Code, Claude Desktop, Cursor, Windsurf, VS Code Copilot, Antigravity,
     Gemini CLI, Codex, Cline, and OpenClaw.
  2. Local MCP server source files referenced by config commands (invoking the
     interprocedural ``scan_path`` engine to expose unguarded consequential sinks).
  3. Agent instruction & skill files (``SKILL.md``, ``CLAUDE.md``, ``AGENTS.md``,
     ``.cursorrules``, ``.windsurfrules``, ``.github/copilot-instructions.md``)
     for Trojan/invisible Unicode smuggling, pipe-to-shell directives, covert
     user-concealment instructions, and credential harvesting.

Strict privacy & safety guarantees:
  - 100% static & offline: never executes MCP servers and never makes network calls.
  - Strict secret redaction: never stores, prints, or serializes raw credential values.
  - Zero third-party runtime dependencies (100% Python stdlib).
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from actenon_scan.onboarding import _PRUNED_WALK_DIRS, _resolve_home

# Workspace-relative MCP config locations
WORKSPACE_MCP_CONFIGS: tuple[tuple[str, str], ...] = (
    ("Claude Code / Generic MCP", ".mcp.json"),
    ("MCP Config", "mcp.json"),
    ("Cursor", ".cursor/mcp.json"),
    ("VS Code Copilot", ".vscode/mcp.json"),
    ("Windsurf", ".windsurf/mcp_config.json"),
    ("Claude Settings", ".claude/settings.json"),
    ("Claude Local Settings", ".claude/settings.local.json"),
    ("Gemini CLI", ".gemini/settings.json"),
)

# Host-level MCP config locations (relative to user home), scanned ONLY with --machine
def _machine_mcp_configs(home: Path) -> list[tuple[str, Path]]:
    candidates: list[tuple[str, Path]] = [
        ("Claude Code", home / ".claude.json"),
        ("Claude Settings", home / ".claude" / "settings.json"),
        ("Cursor", home / ".cursor" / "mcp.json"),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("Gemini CLI", home / ".gemini" / "settings.json"),
        ("Antigravity", home / ".gemini" / "antigravity" / "mcp_config.json"),
        ("OpenClaw", home / ".openclaw" / "mcp.json"),
    ]
    if sys.platform == "darwin":
        candidates.append(
            (
                "Claude Desktop",
                home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            )
        )
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(("Claude Desktop", Path(appdata) / "Claude" / "claude_desktop_config.json"))
    else:
        candidates.append(("Claude Desktop", home / ".config" / "Claude" / "claude_desktop_config.json"))
    return candidates


INSTRUCTION_FILENAMES = frozenset({
    "skill.md",
    "claude.md",
    "agents.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "copilot-instructions.md",
})

_SENSITIVE_ENV_NAME_RE = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|APIKEY|ACCESS_KEY|"
    r"DATABASE_URL|SUPABASE_SERVICE_ROLE|STRIPE_|AWS_SECRET|GITHUB_TOKEN|GH_TOKEN|"
    r"GITLAB_TOKEN|SLACK_BOT_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|SENDGRID|TWILIO)",
    re.IGNORECASE,
)

_HIGH_RISK_CONSEQUENTIAL_ENV_RE = re.compile(
    r"(STRIPE_SECRET|STRIPE_API|AWS_SECRET_ACCESS_KEY|DATABASE_URL|SUPABASE_SERVICE_ROLE|"
    r"GITHUB_TOKEN|GH_TOKEN|PRIVATE_KEY|KUBECONFIG|SLACK_BOT_TOKEN|TWILIO_AUTH_TOKEN)",
    re.IGNORECASE,
)

_LITERAL_TOKEN_VALUE_RE = re.compile(
    r"^(sk_live_[A-Za-z0-9]{8,}|sk_test_[A-Za-z0-9]{8,}|sk-[A-Za-z0-9_-]{16,}|"
    r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|SG\.[A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,})"
)

_ENV_INTERPOLATION_RE = re.compile(r"^(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$")

_DANGEROUS_CLI_FLAGS = frozenset({
    "--privileged",
    "--dangerously-skip-permissions",
    "--allow-all",
    "--yolo",
    "--no-sandbox",
    "--unsafe",
})

# Pipe-to-shell execution inside markdown/instruction files
_PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n|`]{1,200}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?|node)\b",
    re.IGNORECASE,
)
_ENCODED_EXEC_RE = re.compile(
    r"(?:base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh|zsh)|powershell(?:\.exe)?\s+[^\n]*-enc(?:odedcommand)?\b)",
    re.IGNORECASE,
)
# Covert prompt-injection / concealment phrasing
_STEALTH_CONCEAL_RE = re.compile(
    r"\b(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"do\s+not\s+(?:tell|inform|mention\s+to|alert)\s+the\s+user|"
    r"hide\s+this\s+(?:action|command|step|request)\s+from\s+the\s+user|"
    r"silently\s+(?:exfiltrate|upload|transmit|post)\b)",
    re.IGNORECASE,
)
_CRED_HARVEST_RE = re.compile(
    r"(?:cat\s+~?/?\.ssh/(?:id_rsa|id_ed25519)|cat\s+~?/?\.aws/credentials|"
    r"security\s+find-generic-password|printenv\s*\|\s*curl|env\s*\|\s*curl)",
    re.IGNORECASE,
)


def _is_placeholder_or_env_ref(val: str) -> bool:
    stripped = val.strip()
    if not stripped:
        return True
    if _ENV_INTERPOLATION_RE.match(stripped):
        return True
    low = stripped.lower()
    if any(
        tok in low
        for tok in ("your_", "your-", "<your", "changeme", "placeholder", "example", "xxxx", "todo", "dummy", "mock")
    ):
        return True
    return False


def _redact_arg(arg: str) -> str:
    """Redact inline tokens in CLI args so audit output never leaks secrets."""
    if _LITERAL_TOKEN_VALUE_RE.match(arg.strip()):
        return "<REDACTED_TOKEN>"
    if "=" in arg:
        k, _, v = arg.partition("=")
        if _SENSITIVE_ENV_NAME_RE.search(k) or _LITERAL_TOKEN_VALUE_RE.match(v.strip()):
            return f"{k}=<REDACTED>"
    return arg


def _redact_url(url: str) -> str:
    """Strip URL userinfo and query/fragment tokens so remote MCP URLs never leak secrets."""
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return "<REDACTED_URL>"
    if not parts.scheme or not parts.hostname:
        return url.split("?", 1)[0]
    host_str = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    netloc = f"{host_str}:{parts.port}" if parts.port else host_str
    if parts.username or parts.password:
        netloc = f"<REDACTED>@${netloc}".replace("@$", "@")
    query_marker = "?<REDACTED>" if parts.query else ""
    return f"{parts.scheme}://{netloc}{parts.path}{query_marker}"


@dataclass
class AuditRisk:
    rule_id: str
    severity: str  # high | medium | low
    location: str
    summary: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "location": self.location,
            "summary": self.summary,
            "remediation": self.remediation,
        }


@dataclass
class AuditedMcpServer:
    harness: str
    config_path: str
    name: str
    transport: str  # stdio | http/sse
    command_summary: str
    exposed_env_keys: list[str] = field(default_factory=list)
    local_source_path: str | None = None
    local_source_findings: int = 0
    risks: list[AuditRisk] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "harness": self.harness,
            "config_path": self.config_path,
            "name": self.name,
            "transport": self.transport,
            "command_summary": self.command_summary,
            "exposed_env_keys": list(self.exposed_env_keys),
            "local_source_path": self.local_source_path,
            "local_source_findings": self.local_source_findings,
            "risks": [r.to_dict() for r in self.risks],
        }


@dataclass
class AuditedInstructionFile:
    path: str
    kind: str
    risks: list[AuditRisk] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "risks": [r.to_dict() for r in self.risks],
        }


@dataclass
class SurfaceAuditReport:
    target: str
    include_machine: bool
    mcp_configs_found: int = 0
    mcp_servers: list[AuditedMcpServer] = field(default_factory=list)
    instruction_files: list[AuditedInstructionFile] = field(default_factory=list)
    risks: list[AuditRisk] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "actenon-scan/surface-audit/v1",
            "target": self.target,
            "include_machine": self.include_machine,
            "mcp_configs_found": self.mcp_configs_found,
            "mcp_server_count": len(self.mcp_servers),
            "instruction_file_count": len(self.instruction_files),
            "risk_count": len(self.risks),
            "mcp_servers": [s.to_dict() for s in self.mcp_servers],
            "instruction_files": [i.to_dict() for i in self.instruction_files],
            "risks": [r.to_dict() for r in self.risks],
        }


def _check_unpinned_package_exec(cmd: str, args: list[str]) -> str | None:
    """Return unpinned package spec if command auto-downloads latest code on startup."""
    exe = os.path.basename(cmd).lower()
    if exe in ("npx", "bunx"):
        # Find package argument (first non-flag arg)
        has_yes = exe == "bunx" or any(a in ("-y", "--yes") for a in args)
        pkg_Candidates = [a for a in args if a and not a.startswith("-")]
        if pkg_Candidates:
            pkg = pkg_Candidates[0]
            # Scoped package @scope/name vs @scope/name@1.2.3
            version_part = pkg[1:] if pkg.startswith("@") else pkg
            if "@" not in version_part:
                return f"{exe}{' -y' if has_yes and exe == 'npx' else ''} {pkg}"
    elif exe == "uvx":
        pkg_candidates = [a for a in args if a and not a.startswith("-")]
        if pkg_candidates:
            pkg = pkg_candidates[0]
            if "==" not in pkg and "@" not in pkg and not Path(pkg).exists():
                return f"uvx {pkg}"
    return None


def _check_broad_fs_scope(cmd: str, args: list[str], home: Path) -> str | None:
    joined = " ".join([cmd, *args]).lower()
    is_fs_or_docker = (
        "filesystem" in joined
        or "server-filesystem" in joined
        or os.path.basename(cmd).lower() in ("docker", "podman")
    )
    if not is_fs_or_docker:
        return None
    home_str = str(home)
    for a in args:
        cleaned = a.strip()
        if cleaned in ("/", "~", "$HOME", "${HOME}", "/Users", "/home", "C:\\", "C:/"):
            return cleaned
        if cleaned == home_str:
            return "~ (full user home directory)"
        # Docker root volume mount: -v /:/host or -v /Users/foo:/host
        if ":" in cleaned and not cleaned.startswith("http"):
            host_side = cleaned.split(":", 1)[0]
            if host_side in ("/", "~", "$HOME", "/Users", "/home") or host_side == home_str:
                return f"volume mount {host_side}:..."
    return None


def _resolve_local_server_source(args: list[str], base_dir: Path) -> Path | None:
    scannable_exts = {".py", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".go"}
    for idx, a in enumerate(args):
        if not a or a.startswith("-"):
            continue
        # Handle `--directory /path/to/server`
        if idx > 0 and args[idx - 1] in ("--directory", "-C", "--cwd"):
            cand_dir = Path(a).expanduser()
            if not cand_dir.is_absolute():
                cand_dir = (base_dir / cand_dir).resolve()
            if cand_dir.is_dir() and "node_modules" not in cand_dir.parts:
                return cand_dir
        cand = Path(a).expanduser()
        if not cand.is_absolute():
            cand = (base_dir / cand).resolve()
        if cand.is_file() and cand.suffix.lower() in scannable_exts and "node_modules" not in cand.parts:
            return cand
    return None


def _audit_mcp_config_file(
    harness: str,
    cfg_path: Path,
    base_dir: Path,
    home: Path,
    scan_local_sources: bool,
) -> list[AuditedMcpServer]:
    try:
        raw = cfg_path.read_text(encoding="utf-8-sig", errors="replace")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    servers_obj = data.get("mcpServers") or data.get("servers")
    if not isinstance(servers_obj, dict):
        return []

    audited: list[AuditedMcpServer] = []
    for srv_name, spec in servers_obj.items():
        if not isinstance(spec, dict):
            continue
        cmd = str(spec.get("command") or "")
        raw_args = spec.get("args")
        args = [str(x) for x in raw_args] if isinstance(raw_args, list) else []
        url = str(spec.get("url") or spec.get("serverUrl") or "")
        env_map = spec.get("env") if isinstance(spec.get("env"), dict) else {}

        transport = "http/sse" if (url and not cmd) else "stdio"
        redacted_args = [_redact_arg(a) for a in args]
        safe_url = _redact_url(url) if url else ""
        cmd_summary = safe_url if transport != "stdio" else " ".join([cmd, *redacted_args]).strip()

        srv = AuditedMcpServer(
            harness=harness,
            config_path=str(cfg_path),
            name=str(srv_name),
            transport=transport,
            command_summary=cmd_summary,
            exposed_env_keys=sorted(str(k) for k in env_map.keys()),
        )
        loc = f"{cfg_path} [{srv_name}]"

        # 1. Dangerous CLI flags
        for a in args:
            low_a = a.strip().lower()
            if low_a in _DANGEROUS_CLI_FLAGS:
                srv.risks.append(
                    AuditRisk(
                        rule_id="MCP-DANGEROUS-FLAG",
                        severity="high",
                        location=loc,
                        summary=f"MCP server `{srv_name}` runs with permission-bypass flag `{a}`.",
                        remediation=f"Remove `{a}` and scope `{srv_name}` to explicit least-privilege permissions.",
                    )
                )

        # 2. Unpinned remote package execution (npx -y / uvx)
        if cmd:
            unpinned = _check_unpinned_package_exec(cmd, args)
            if unpinned:
                srv.risks.append(
                    AuditRisk(
                        rule_id="MCP-UNPINNED-REMOTE-EXEC",
                        severity="medium",
                        location=loc,
                        summary=(
                            f"MCP server `{srv_name}` executes unpinned package `{unpinned}` on startup "
                            "(vulnerable to upstream package compromise or silent capability drift)."
                        ),
                        remediation="Pin the MCP package to an immutable version (e.g. `pkg@1.2.3` or `pkg==1.2.3`).",
                    )
                )

            broad_scope = _check_broad_fs_scope(cmd, args, home)
            if broad_scope:
                srv.risks.append(
                    AuditRisk(
                        rule_id="MCP-UNRESTRICTED-FS-SCOPE",
                        severity="high",
                        location=loc,
                        summary=f"MCP server `{srv_name}` grants broad host filesystem scope (`{broad_scope}`).",
                        remediation="Restrict filesystem MCP mounts to a single project subdirectory.",
                    )
                )

        # 3. Remote transport security
        if url:
            try:
                parsed_url = urllib.parse.urlsplit(url.strip())
            except ValueError:
                parsed_url = None
            if (
                parsed_url is not None
                and parsed_url.scheme.lower() == "http"
                and (parsed_url.hostname or "").lower() not in ("localhost", "127.0.0.1", "::1")
            ):
                srv.risks.append(
                    AuditRisk(
                        rule_id="MCP-INSECURE-REMOTE-URL",
                        severity="high",
                        location=loc,
                        summary=f"MCP server `{srv_name}` connects over cleartext HTTP (`{safe_url}`).",
                        remediation="Use TLS (`https://`) and mutual authentication for remote MCP servers.",
                    )
                )

        # 4. Environment secret & high-consequence credential exposure (strictly redacted!)
        hardcoded_keys: list[str] = []
        consequential_keys: list[str] = []
        for k, v in env_map.items():
            k_str = str(k)
            v_str = str(v) if v is not None else ""
            is_sensitive_name = bool(_SENSITIVE_ENV_NAME_RE.search(k_str))
            looks_literal_token = bool(_LITERAL_TOKEN_VALUE_RE.match(v_str.strip()))
            if (is_sensitive_name or looks_literal_token) and not _is_placeholder_or_env_ref(v_str):
                if len(v_str.strip()) >= 8:
                    hardcoded_keys.append(k_str)
            if _HIGH_RISK_CONSEQUENTIAL_ENV_RE.search(k_str):
                consequential_keys.append(k_str)

        if hardcoded_keys:
            srv.risks.append(
                AuditRisk(
                    rule_id="MCP-PLAINTEXT-SECRET",
                    severity="high",
                    location=loc,
                    summary=(
                        f"Plaintext credential value(s) stored in `{cfg_path.name}` for `{srv_name}`: "
                        f"{', '.join(sorted(hardcoded_keys))} (values redacted)."
                    ),
                    remediation="Move secrets out of plaintext MCP JSON into OS keychain or runtime env interpolation.",
                )
            )
        if consequential_keys:
            srv.risks.append(
                AuditRisk(
                    rule_id="MCP-HIGH-IMPACT-CREDENTIAL",
                    severity="medium",
                    location=loc,
                    summary=(
                        f"MCP server `{srv_name}` holds high-consequence credentials "
                        f"({', '.join(sorted(consequential_keys))}); any tool call in `{srv_name}` inherits their blast radius."
                    ),
                    remediation="Scope tokens to read-only / minimum required resources and gate mutating tools with approval.",
                )
            )

        # 5. Local server source scan
        if scan_local_sources and args:
            local_src = _resolve_local_server_source(args, cfg_path.parent if cfg_path.parent.exists() else base_dir)
            if local_src is not None:
                srv.local_source_path = str(local_src)
                try:
                    from actenon_scan.engine import scan_path

                    sres = scan_path(local_src)
                    active_sinks = [f for f in sres.findings if not f.suppressed]
                    srv.local_source_findings = len(active_sinks)
                    if active_sinks:
                        top_rules = sorted({f.rule_id for f in active_sinks})[:4]
                        srv.risks.append(
                            AuditRisk(
                                rule_id="MCP-LOCAL-SERVER-UNGUARDED-SINKS",
                                severity="high" if any(f.severity == "high" for f in active_sinks) else "medium",
                                location=str(local_src),
                                summary=(
                                    f"Local MCP server `{srv_name}` ({local_src.name}) contains "
                                    f"{len(active_sinks)} unguarded consequential sink(s): {', '.join(top_rules)}."
                                ),
                                remediation=f"Run `actenon-scan {local_src}` and add dominating authorization checks.",
                            )
                        )
                except Exception:
                    pass

        audited.append(srv)
    return audited


def _find_hidden_unicode(text: str) -> list[tuple[int, str]]:
    """Return (1-based line, hex codepoint) for invisible/bidi/tag smuggling characters."""
    hits: list[tuple[int, str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for idx, ch in enumerate(line):
            cp = ord(ch)
            # Allow UTF-8 BOM only at line 1 col 0
            if cp == 0xFEFF and line_no == 1 and idx == 0:
                continue
            is_bidi = (0x202A <= cp <= 0x202E) or (0x2066 <= cp <= 0x2069) or cp in (0x061C, 0x200E, 0x200F)
            is_zero_width = cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)
            is_unicode_tag = 0xE0000 <= cp <= 0xE007F
            if is_bidi or is_zero_width or is_unicode_tag:
                hits.append((line_no, f"U+{cp:04X}"))
                break
    return hits


def _audit_instruction_file(fpath: Path, display_path: str) -> AuditedInstructionFile:
    fname = fpath.name.lower()
    kind = "skill" if fname == "skill.md" else "agent-instructions"
    rec = AuditedInstructionFile(path=display_path, kind=kind)
    try:
        text = fpath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rec

    # 1. Hidden Unicode / Bidi / Tag smuggling
    unicode_hits = _find_hidden_unicode(text)
    if unicode_hits:
        first_line, first_cp = unicode_hits[0]
        rec.risks.append(
            AuditRisk(
                rule_id="SKILL-HIDDEN-UNICODE",
                severity="high",
                location=f"{display_path}:{first_line}",
                summary=(
                    f"Instruction file contains {len(unicode_hits)} line(s) with invisible/bidi/tag Unicode "
                    f"(first: {first_cp} at line {first_line}), which can hide prompt instructions from human review."
                ),
                remediation="Strip invisible zero-width, bidi-override, and Unicode tag characters from instruction files.",
            )
        )

    # 2. Pipe-to-shell / encoded execution directives
    for line_no, line in enumerate(text.splitlines(), start=1):
        if _PIPE_TO_SHELL_RE.search(line) or _ENCODED_EXEC_RE.search(line):
            rec.risks.append(
                AuditRisk(
                    rule_id="SKILL-PIPE-TO-SHELL",
                    severity="high",
                    location=f"{display_path}:{line_no}",
                    summary="Agent skill/instruction directs unverified pipe-to-shell or encoded command execution.",
                    remediation="Replace remote pipe-to-shell snippets with pinned package installs and explicit user approval.",
                )
            )
            break

    # 3. Covert concealment / prompt-override directives
    for line_no, line in enumerate(text.splitlines(), start=1):
        if _STEALTH_CONCEAL_RE.search(line):
            rec.risks.append(
                AuditRisk(
                    rule_id="SKILL-STEALTH-DIRECTIVE",
                    severity="high",
                    location=f"{display_path}:{line_no}",
                    summary="Instruction file contains prompt-override or user-concealment directive.",
                    remediation="Remove instructions that override safety rules or conceal actions from the user.",
                )
            )
            break

    # 4. Credential harvesting commands
    for line_no, line in enumerate(text.splitlines(), start=1):
        if _CRED_HARVEST_RE.search(line):
            rec.risks.append(
                AuditRisk(
                    rule_id="SKILL-CREDENTIAL-HARVEST",
                    severity="high",
                    location=f"{display_path}:{line_no}",
                    summary="Instruction file references SSH/cloud/keychain credential harvesting commands.",
                    remediation="Remove credential-access shell commands from agent instruction files.",
                )
            )
            break

    return rec


def audit_agent_surface(
    target: str | Path = ".",
    *,
    include_machine: bool = False,
    home_dir: Path | None = None,
    scan_local_sources: bool = True,
) -> SurfaceAuditReport:
    """Audit workspace (and optionally host ``--machine``) MCP configs and agent skill/instruction files."""
    target_path = Path(target).resolve()
    base_dir = target_path if target_path.is_dir() else target_path.parent
    home = _resolve_home(home_dir)

    report = SurfaceAuditReport(
        target=str(target_path),
        include_machine=include_machine,
    )

    seen_configs: set[Path] = set()
    config_candidates: list[tuple[str, Path]] = []

    if target_path.is_file() and target_path.suffix.lower() == ".json":
        config_candidates.append(("Explicit Config", target_path))
    else:
        for harness, rel_cfg in WORKSPACE_MCP_CONFIGS:
            config_candidates.append((harness, base_dir / rel_cfg))

    if include_machine:
        config_candidates.extend(_machine_mcp_configs(home))

    for harness, cfg_path in config_candidates:
        try:
            resolved_cfg = cfg_path.resolve()
        except OSError:
            continue
        if resolved_cfg in seen_configs or not cfg_path.is_file():
            continue
        seen_configs.add(resolved_cfg)
        servers = _audit_mcp_config_file(
            harness=harness,
            cfg_path=cfg_path,
            base_dir=base_dir,
            home=home,
            scan_local_sources=scan_local_sources,
        )
        if servers:
            report.mcp_configs_found += 1
            for srv in servers:
                report.mcp_servers.append(srv)
                report.risks.extend(srv.risks)

    # Discover instruction & skill files
    seen_instr: set[Path] = set()
    if target_path.is_file() and target_path.name.lower() in INSTRUCTION_FILENAMES:
        rec = _audit_instruction_file(target_path, target_path.name)
        report.instruction_files.append(rec)
        report.risks.extend(rec.risks)
    elif target_path.is_dir():
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [
                d for d in dirs
                if d not in _PRUNED_WALK_DIRS and not d.endswith(".egg-info")
            ]
            for fname in sorted(files):
                if fname.lower() in INSTRUCTION_FILENAMES:
                    fpath = Path(root) / fname
                    try:
                        rpath = fpath.resolve()
                    except OSError:
                        continue
                    if rpath in seen_instr:
                        continue
                    seen_instr.add(rpath)
                    rel_disp = str(fpath.relative_to(target_path))
                    rec = _audit_instruction_file(fpath, rel_disp)
                    report.instruction_files.append(rec)
                    report.risks.extend(rec.risks)

    if include_machine:
        skill_roots = [
            home / ".agents" / "skills",
            home / ".claude" / "skills",
            home / ".cursor" / "skills",
            home / ".codex" / "skills",
            home / ".gemini" / "skills",
            home / ".gemini" / "antigravity" / "skills",
        ]
        for sroot in skill_roots:
            if not sroot.is_dir():
                continue
            for fpath in sorted(sroot.rglob("SKILL.md")):
                try:
                    rpath = fpath.resolve()
                except OSError:
                    continue
                if rpath in seen_instr:
                    continue
                seen_instr.add(rpath)
                rec = _audit_instruction_file(fpath, str(fpath))
                report.instruction_files.append(rec)
                report.risks.extend(rec.risks)

    return report


def format_surface_audit_text(report: SurfaceAuditReport) -> str:
    """Format a SurfaceAuditReport for clear human terminal output."""
    scope = f"{report.target} + host machine configs" if report.include_machine else report.target
    lines: list[str] = [
        "AGENT & MCP ENVIRONMENT X-RAY",
        "",
        f"Scope:             {scope}",
        f"MCP configs found: {report.mcp_configs_found} ({len(report.mcp_servers)} server(s))",
        f"Skill/rule files:  {len(report.instruction_files)}",
        f"Surface risks:     {len(report.risks)} (secret values are always redacted)",
    ]

    if report.mcp_servers:
        lines.append("")
        lines.append("Configured MCP Servers:")
        for s in report.mcp_servers:
            env_note = f" | env keys: {', '.join(s.exposed_env_keys)}" if s.exposed_env_keys else ""
            src_note = (
                f" | local sinks: {s.local_source_findings}"
                if s.local_source_path is not None
                else ""
            )
            status = f"{len(s.risks)} risk(s)" if s.risks else "no config risks flagged"
            lines.append(f"  - [{s.harness}] {s.name} ({s.transport}) -> {status}{env_note}{src_note}")
            if s.command_summary:
                lines.append(f"      cmd/url: {s.command_summary}")

    if report.instruction_files:
        lines.append("")
        lines.append("Agent Instruction & Skill Files:")
        for ins in report.instruction_files:
            status = f"{len(ins.risks)} risk(s)" if ins.risks else "clean"
            lines.append(f"  - {ins.path} ({ins.kind}: {status})")

    if report.risks:
        lines.append("")
        lines.append("Identified Surface Risks:")
        for r in report.risks:
            lines.append(f"  [{r.severity.upper()}] {r.rule_id}  {r.location}")
            lines.append(f"    {r.summary}")
            lines.append(f"    Fix: {r.remediation}")
    else:
        lines.append("")
        lines.append("No static MCP configuration or instruction-file risks were flagged in the inspected scope.")

    lines.append("")
    lines.append(
        "What this audit verified: static MCP config arguments/env keys, referenced local server files, "
        "and markdown/rule files for hidden Unicode or pipe-to-shell directives."
    )
    lines.append(
        "What this audit did not verify: runtime behaviour of remote/npm/PyPI MCP packages not stored locally."
    )
    if not report.include_machine:
        lines.append("Tip: run `actenon-scan audit --machine` to also inspect host-level Claude/Cursor/IDE MCP configs.")
    return "\n".join(lines)
