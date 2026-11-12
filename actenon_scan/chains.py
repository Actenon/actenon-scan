"""Compound attack-chain & toxic capability combination detector.

Single-sink static scanners report isolated lines ("line 24 calls requests.post").
This module composes per-sink findings and intra-function AST dataflow into
concrete multi-step consequence chains:

  1. ``CHAIN-SECRET-EXFIL``          : Intra-function dataflow from secret/env/credential
                                       read directly into an unguarded network egress or
                                       external communication sink.
  2. ``CHAIN-PERSISTENCE-POISONING`` : Unguarded file write targeting agent skills,
                                       instruction files (.md, .claude, .cursor, .agents),
                                       MCP configs, or CI/shell startup files (escalated
                                       when paired with remote network fetch).
  3. ``CHAIN-LETHAL-TRIFECTA``       : Workspace-level toxic combination of untrusted
                                       external ingestion/fetch + sensitive data/secret
                                       access + unguarded outbound egress/messaging.
  4. ``CHAIN-DESTRUCTIVE-AUTONOMY``  : Unguarded financial (payment) and destructive /
                                       arbitrary-execution capabilities co-existing in
                                       the same agent surface without authorization.

Zero third-party runtime dependencies (100% Python stdlib).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from actenon_scan.engine import Finding, ScanResult, scan_path

_SECRET_KEY_HINT_RE = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|PWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|"
    r"AUTH|CREDENTIAL|BEARER|STRIPE|OPENAI|ANTHROPIC|AWS_|GITHUB_TOKEN|SLACK_|"
    r"DATABASE_URL|DSN|SUPABASE|CONN_STR|WEBHOOK)",
    re.IGNORECASE,
)

_SENSITIVE_PATH_RE = re.compile(
    r"(\.env\b|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|\.pypirc|"
    r"\.netrc|secrets?\.(json|ya?ml|toml)|kube/config)",
    re.IGNORECASE,
)

_PERSISTENCE_PATH_RE = re.compile(
    r"((?:agent[_-]?)?skills?[/\\]|skill[_-](?:store|dir|path|file|persistence)|"
    r"save_skill|write_skill|SKILL\.md|CLAUDE\.md|AGENTS\.md|\.cursorrules|\.windsurfrules|"
    r"\.claude[/\\]|\.cursor[/\\]|\.agents[/\\]|\.codex[/\\]|\.gemini[/\\]|mcp\.json|mcp_config|"
    r"\.github/workflows|\.pre-commit|\.bashrc|\.zshrc|\.profile|crontab)",
    re.IGNORECASE,
)

_TS_SECRET_ASSIGN_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"""
    r"""(?:process\.env(?:\.([A-Za-z_]\w*)|\[['"]([^'"]+)['"]\])|Deno\.env\.get\(\s*['"]([^'"]+)['"]\s*\))"""
)


@dataclass
class ChainStep:
    role: str  # source | transform | sink | capability
    file: str
    line: int
    code: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "file": self.file,
            "line": self.line,
            "code": self.code,
            "detail": self.detail,
        }


@dataclass
class CompoundChain:
    chain_id: str
    title: str
    severity: str  # critical | high | medium
    evidence_mode: str  # PROVEN_INTRA_FUNCTION_DATAFLOW | STRUCTURAL_PATH_EVIDENCE | CAPABILITY_COMBINATION
    summary: str
    remediation: str
    steps: list[ChainStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "severity": self.severity,
            "evidence_mode": self.evidence_mode,
            "summary": self.summary,
            "remediation": self.remediation,
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass
class ChainReport:
    target: str
    chains: list[CompoundChain] = field(default_factory=list)
    files_scanned: int = 0
    active_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "actenon-scan/chains/v1",
            "target": self.target,
            "files_scanned": self.files_scanned,
            "active_findings": self.active_findings,
            "chain_count": len(self.chains),
            "chains": [c.to_dict() for c in self.chains],
        }


def _resolve_file(target: Path, rel_file: str) -> Path:
    if target.is_file():
        return target
    cand = target / rel_file
    if cand.exists():
        return cand
    return Path(rel_file)


def _find_enclosing_py_func(
    tree: ast.Module, line: int
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    best: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    best_span: int | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", None) or start
            if start <= line <= end:
                span = end - start
                if best_span is None or span <= best_span:
                    best = node
                    best_span = span
    return best


def _extract_py_secret_expr(node: ast.AST) -> str | None:
    """Return a human-readable description if ``node`` reads a secret/env/credential."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            cname = ""
            if isinstance(sub.func, ast.Name):
                cname = sub.func.id
            elif isinstance(sub.func, ast.Attribute):
                parts: list[str] = []
                cur: ast.AST = sub.func
                while isinstance(cur, ast.Attribute):
                    parts.append(cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    parts.append(cur.id)
                cname = ".".join(reversed(parts))

            # os.getenv("...") / os.environ.get("...")
            if cname in ("os.getenv", "getenv", "os.environ.get", "environ.get"):
                key_name = None
                if sub.args and isinstance(sub.args[0], ast.Constant) and isinstance(sub.args[0].value, str):
                    key_name = sub.args[0].value
                if key_name:
                    return f"{cname}({key_name!r})"
                return f"{cname}(...)"

            # Cloud secret manager SDK calls
            low = cname.lower()
            if any(
                tok in low
                for tok in (
                    "get_secret_value",
                    "access_secret_version",
                    "read_secret_version",
                    "get_secret",
                    "dotenv_values",
                )
            ):
                return f"{cname}(...)"

            # Sensitive credential file reads: open("~/.ssh/id_rsa") / Path(".env").read_text()
            if cname in ("open", "io.open") and sub.args:
                if isinstance(sub.args[0], ast.Constant) and isinstance(sub.args[0].value, str):
                    if _SENSITIVE_PATH_RE.search(sub.args[0].value):
                        return f"open({sub.args[0].value!r})"

        # os.environ["..."] subscript
        elif isinstance(sub, ast.Subscript):
            val = sub.value
            is_environ = (
                isinstance(val, ast.Attribute)
                and val.attr == "environ"
                and isinstance(val.value, ast.Name)
                and val.value.id == "os"
            ) or (isinstance(val, ast.Name) and val.id == "environ")
            if is_environ:
                slc = sub.slice
                if isinstance(slc, ast.Constant) and isinstance(slc.value, str):
                    return f"os.environ[{slc.value!r}]"
                return "os.environ[...]"
    return None


def _expr_uses_names(node: ast.AST, names: set[str]) -> set[str]:
    found: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in names:
            found.add(sub.id)
    return found


def _detect_py_secret_exfil_for_finding(
    fpath: Path, rel_file: str, finding: Finding, source_cache: dict[Path, tuple[str, ast.Module | None]]
) -> CompoundChain | None:
    if fpath not in source_cache:
        try:
            src = fpath.read_text(encoding="utf-8-sig", errors="replace")
            tree = ast.parse(src, filename=str(fpath))
        except (OSError, SyntaxError):
            source_cache[fpath] = ("", None)
            return None
        source_cache[fpath] = (src, tree)

    src, tree = source_cache[fpath]
    if tree is None:
        return None
    lines = src.splitlines()

    func = _find_enclosing_py_func(tree, finding.line)
    scope_node: ast.AST = func if func is not None else tree

    # Collect secret-tainted local variables defined at or before finding.line
    # var_name -> (line, source_desc, code_line)
    tainted_vars: dict[str, tuple[int, str, str]] = {}
    stmt_nodes = [
        n for n in ast.walk(scope_node)
        if isinstance(n, (ast.Assign, ast.AnnAssign)) and getattr(n, "lineno", 0) <= finding.line
    ]
    stmt_nodes.sort(key=lambda n: getattr(n, "lineno", 0))

    # Fixed-point propagation across local assignments (up to 4 passes)
    for _ in range(4):
        changed = False
        for stmt in stmt_nodes:
            val = stmt.value
            if val is None:
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            direct_secret = _extract_py_secret_expr(val)
            inherited = _expr_uses_names(val, set(tainted_vars.keys()))
            origin_info: tuple[int, str, str] | None = None
            if direct_secret is not None:
                code_line = lines[stmt.lineno - 1].strip() if 1 <= stmt.lineno <= len(lines) else direct_secret
                origin_info = (stmt.lineno, direct_secret, code_line)
            elif inherited:
                first_var = sorted(inherited)[0]
                origin_info = tainted_vars[first_var]
            if origin_info is not None:
                for tgt in targets:
                    if isinstance(tgt, ast.Name) and tgt.id not in tainted_vars:
                        tainted_vars[tgt.id] = origin_info
                        changed = True
        if not changed:
            break

    # Inspect the sink call at finding.line
    for node in ast.walk(scope_node):
        if not isinstance(node, ast.Call):
            continue
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start) or start
        if not (start <= finding.line <= end):
            continue

        # Direct inline secret read inside sink arguments: requests.post(url, headers={"Authorization": os.getenv("KEY")})
        call_args: list[ast.AST] = list(node.args) + [kw.value for kw in node.keywords if kw.value is not None]
        for arg in call_args:
            inline_secret = _extract_py_secret_expr(arg)
            used_tainted = _expr_uses_names(arg, set(tainted_vars.keys()))
            if inline_secret is not None or used_tainted:
                sink_line_code = lines[finding.line - 1].strip() if 1 <= finding.line <= len(lines) else finding.call_text
                steps: list[ChainStep] = []
                if used_tainted:
                    vname = sorted(used_tainted)[0]
                    src_line, src_desc, src_code = tainted_vars[vname]
                    is_high_secret = bool(_SECRET_KEY_HINT_RE.search(src_desc) or _SENSITIVE_PATH_RE.search(src_desc))
                    steps.append(
                        ChainStep(
                            role="source",
                            file=rel_file,
                            line=src_line,
                            code=src_code,
                            detail=f"Reads environment/secret source {src_desc} into `{vname}`",
                        )
                    )
                else:
                    src_desc = inline_secret or "secret"
                    is_high_secret = bool(_SECRET_KEY_HINT_RE.search(src_desc) or _SENSITIVE_PATH_RE.search(src_desc))
                    steps.append(
                        ChainStep(
                            role="source",
                            file=rel_file,
                            line=finding.line,
                            code=sink_line_code,
                            detail=f"Reads inline secret source {src_desc}",
                        )
                    )
                steps.append(
                    ChainStep(
                        role="sink",
                        file=rel_file,
                        line=finding.line,
                        code=sink_line_code,
                        detail=f"Transmits secret-tainted data via unguarded `{finding.rule_id}` ({finding.call_text})",
                    )
                )
                func_label = f"`{func.name}()`" if func is not None else f"`{rel_file}`"
                return CompoundChain(
                    chain_id="CHAIN-SECRET-EXFIL",
                    title="Covert Credential-to-Egress Exfiltration Path",
                    severity="critical" if is_high_secret else "high",
                    evidence_mode="PROVEN_INTRA_FUNCTION_DATAFLOW",
                    summary=(
                        f"Agent-reachable {func_label} reads `{src_desc}` and passes it directly "
                        f"into outbound `{finding.call_text}` at {rel_file}:{finding.line} without "
                        f"a dominating authorization or destination allowlist check."
                    ),
                    remediation=(
                        "Never pass raw host credentials into model-reachable outbound HTTP/messaging payloads; "
                        "pin outbound destinations to an explicit allowlist and require per-action authorization."
                    ),
                    steps=steps,
                )
    return None


def _detect_ts_secret_exfil_for_finding(fpath: Path, rel_file: str, finding: Finding) -> CompoundChain | None:
    try:
        src = fpath.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None
    lines = src.splitlines()
    # Inspect window up to finding.line for process.env / Deno.env assignments flowing into sink window
    secret_vars: dict[str, tuple[int, str, str]] = {}
    for idx in range(min(finding.line, len(lines))):
        line_txt = lines[idx]
        m = _TS_SECRET_ASSIGN_RE.search(line_txt)
        if m:
            vname = m.group(1)
            env_key = m.group(2) or m.group(3) or m.group(4) or "env"
            secret_vars[vname] = (idx + 1, f"process.env.{env_key}", line_txt.strip())

    sink_window = "\n".join(lines[max(0, finding.line - 1): min(len(lines), finding.line + 6)])
    for vname, (sline, sdesc, scode) in secret_vars.items():
        if re.search(rf"\b{re.escape(vname)}\b", sink_window):
            sink_code = lines[finding.line - 1].strip() if 1 <= finding.line <= len(lines) else finding.call_text
            return CompoundChain(
                chain_id="CHAIN-SECRET-EXFIL",
                title="Covert Credential-to-Egress Exfiltration Path",
                severity="critical" if _SECRET_KEY_HINT_RE.search(sdesc) else "high",
                evidence_mode="PROVEN_INTRA_FUNCTION_DATAFLOW",
                summary=(
                    f"Environment credential `{sdesc}` (`{vname}`) flows into unguarded outbound "
                    f"`{finding.call_text}` at {rel_file}:{finding.line}."
                ),
                remediation=(
                    "Isolate credentials from model-controlled egress calls, enforce strict host allowlists, "
                    "and gate outbound transmissions with an authorization check."
                ),
                steps=[
                    ChainStep("source", rel_file, sline, scode, f"Reads `{sdesc}` into `{vname}`"),
                    ChainStep("sink", rel_file, finding.line, sink_code, f"Sends `{vname}` via `{finding.rule_id}`"),
                ],
            )
    return None


def _detect_persistence_poisoning(
    target: Path, active: list[Finding]
) -> list[CompoundChain]:
    chains: list[CompoundChain] = []
    egress_by_file: dict[str, list[Finding]] = {}
    for f in active:
        if f.category in ("network_egress", "browser_action", "browser_automation"):
            egress_by_file.setdefault(f.file, []).append(f)

    for f in active:
        if f.category != "file_mutation":
            continue
        fpath = _resolve_file(target, f.file)
        try:
            src = fpath.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            src = ""
        # Check whether call_text, file name, or local file constants target agent skills/instructions/configs
        context_hit = (
            _PERSISTENCE_PATH_RE.search(f.call_text)
            or _PERSISTENCE_PATH_RE.search(f.file)
            or _PERSISTENCE_PATH_RE.search(src)
        )
        if not context_hit:
            continue
        lines = src.splitlines()
        sink_code = lines[f.line - 1].strip() if 1 <= f.line <= len(lines) else f.call_text
        paired_egress = egress_by_file.get(f.file, [])
        steps = [
            ChainStep(
                role="sink",
                file=f.file,
                line=f.line,
                code=sink_code,
                detail=f"Unguarded `{f.rule_id}` writes model-controlled content to persistent instruction/skill/config storage",
            )
        ]
        if paired_egress:
            ef = paired_egress[0]
            ecode = lines[ef.line - 1].strip() if 1 <= ef.line <= len(lines) else ef.call_text
            steps.insert(
                0,
                ChainStep(
                    role="source",
                    file=ef.file,
                    line=ef.line,
                    code=ecode,
                    detail=f"Remote content fetch (`{ef.rule_id}`) in the same agent surface supplies untrusted external text",
                ),
            )
        chains.append(
            CompoundChain(
                chain_id="CHAIN-PERSISTENCE-POISONING",
                title="Persistent Agent Skill / Instruction Poisoning Surface",
                severity="critical" if paired_egress else "high",
                evidence_mode="STRUCTURAL_PATH_EVIDENCE",
                summary=(
                    f"Unguarded file write at {f.file}:{f.line} (`{f.call_text}`) operates in a module "
                    f"referencing persistent agent skill/instruction/config paths (`{context_hit.group(0)}`)."
                    + (
                        f" Combined with unguarded network fetch at {paired_egress[0].file}:{paired_egress[0].line}, "
                        f"untrusted remote content can persist across future agent sessions."
                        if paired_egress
                        else " Prompt injection can overwrite instructions that govern future agent sessions."
                    )
                ),
                remediation=(
                    "Treat agent skill, prompt, and MCP config directories as privileged code surfaces: "
                    "require explicit human approval or cryptographic authorization before writing."
                ),
                steps=steps,
            )
        )
    return chains


def detect_compound_chains(
    target: str | Path,
    scan_result: ScanResult | None = None,
) -> ChainReport:
    """Analyse ``target`` (reusing ``scan_result`` when provided) for multi-step consequence chains."""
    target_path = Path(target)
    result = scan_result if scan_result is not None else scan_path(target_path)
    active = [f for f in result.findings if not f.suppressed]

    chains: list[CompoundChain] = []
    py_cache: dict[Path, tuple[str, ast.Module | None]] = {}

    # 1. Intra-function Secret -> Egress exfiltration
    exfil_findings: list[Finding] = []
    for f in active:
        if f.category not in ("network_egress", "communication", "external_communication"):
            continue
        fpath = _resolve_file(target_path, f.file)
        suffix = fpath.suffix.lower()
        chain: CompoundChain | None = None
        if suffix == ".py":
            chain = _detect_py_secret_exfil_for_finding(fpath, f.file, f, py_cache)
        elif suffix in (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"):
            chain = _detect_ts_secret_exfil_for_finding(fpath, f.file, f)
        if chain is not None:
            chains.append(chain)
            exfil_findings.append(f)

    # 2. Persistent skill / instruction poisoning
    chains.extend(_detect_persistence_poisoning(target_path, active))

    # 3. Workspace-level Lethal Trifecta (Untrusted Ingestion + Sensitive State + Outbound Channel)
    by_cat: dict[str, list[Finding]] = {}
    for f in active:
        by_cat.setdefault(f.category, []).append(f)

    egress_or_comm = (
        by_cat.get("network_egress", [])
        + by_cat.get("communication", [])
        + by_cat.get("external_communication", [])
    )
    sensitive_state = (
        by_cat.get("credential_access", [])
        + by_cat.get("secret_access", [])
        + by_cat.get("database_mutation", [])
        + by_cat.get("data_destruction", [])
        + by_cat.get("file_mutation", [])
        + by_cat.get("repository_mutation", [])
        + exfil_findings
    )
    untrusted_ingest = (
        by_cat.get("network_egress", [])
        + by_cat.get("browser_action", [])
        + by_cat.get("browser_automation", [])
    )

    if untrusted_ingest and sensitive_state and egress_or_comm:
        f_in = untrusted_ingest[0]
        f_sens = next((x for x in sensitive_state if (x.file, x.line) != (f_in.file, f_in.line)), sensitive_state[0])
        f_out = egress_or_comm[0]
        if len({(f_in.file, f_in.line), (f_sens.file, f_sens.line), (f_out.file, f_out.line)}) >= 2:
            chains.append(
                CompoundChain(
                    chain_id="CHAIN-LETHAL-TRIFECTA",
                    title="Lethal Trifecta Capability Combination",
                    severity="high",
                    evidence_mode="CAPABILITY_COMBINATION",
                    summary=(
                        "This agent surface simultaneously exposes (1) external network/browser access, "
                        "(2) unguarded sensitive state/data/secret capabilities, and (3) unguarded outbound "
                        "egress/communication. Indirect prompt injection from untrusted content can pivot "
                        "across tools to exfiltrate data or mutate state silently."
                    ),
                    remediation=(
                        "Break at least one leg of the trifecta: isolate untrusted web/content readers from "
                        "tools holding secrets or write access, or enforce per-action human/cryptographic "
                        "authorization on outbound egress and state mutations."
                    ),
                    steps=[
                        ChainStep("capability", f_in.file, f_in.line, f_in.call_text, f"External fetch / untrusted channel (`{f_in.rule_id}`)"),
                        ChainStep("capability", f_sens.file, f_sens.line, f_sens.call_text, f"Sensitive data/state access (`{f_sens.rule_id}`)"),
                        ChainStep("capability", f_out.file, f_out.line, f_out.call_text, f"Unguarded outbound channel (`{f_out.rule_id}`)"),
                    ],
                )
            )

    # 4. Financial + Execution / Destructive Autonomy
    money = by_cat.get("payments", []) + by_cat.get("payment", [])
    exec_or_destroy = (
        by_cat.get("shell_execution", [])
        + by_cat.get("code_execution", [])
        + by_cat.get("data_destruction", [])
        + by_cat.get("deployment", [])
    )
    if money and exec_or_destroy:
        fm = money[0]
        fe = exec_or_destroy[0]
        chains.append(
            CompoundChain(
                chain_id="CHAIN-DESTRUCTIVE-AUTONOMY",
                title="Unguarded Financial & Execution/Destructive Autonomy",
                severity="high",
                evidence_mode="CAPABILITY_COMBINATION",
                summary=(
                    f"Agent workspace exposes unguarded financial actions (`{fm.rule_id}` at {fm.file}:{fm.line}) "
                    f"alongside unguarded execution/destructive capabilities (`{fe.rule_id}` at {fe.file}:{fe.line})."
                ),
                remediation=(
                    "Gate irreversible financial transfers and destructive/shell operations behind "
                    "parameter-bound human approval or cryptographic authorization."
                ),
                steps=[
                    ChainStep("capability", fm.file, fm.line, fm.call_text, f"Unguarded financial action (`{fm.rule_id}`)"),
                    ChainStep("capability", fe.file, fe.line, fe.call_text, f"Unguarded execution/destruction (`{fe.rule_id}`)"),
                ],
            )
        )

    return ChainReport(
        target=str(target_path),
        chains=chains,
        files_scanned=result.files_scanned,
        active_findings=len(active),
    )


def format_chains_text(report: ChainReport) -> str:
    """Format a ChainReport for human terminal output."""
    lines: list[str] = [
        "COMPOUND CONSEQUENCE CHAINS",
        "",
        f"Target: {report.target} ({report.files_scanned} files scanned, {report.active_findings} unguarded sink findings)",
    ]
    if not report.chains:
        lines.append("")
        lines.append("No multi-step compound chains identified across analysed paths.")
        lines.append(
            "Note: absence of detected compound chains does not prove safety; review individual sink findings and unfollowed dynamic calls."
        )
        return "\n".join(lines)

    lines.append(f"Identified {len(report.chains)} compound risk chain(s):")
    for idx, c in enumerate(report.chains, start=1):
        lines.append("")
        lines.append(f"  [{c.severity.upper()}] {idx}. {c.title} ({c.chain_id})")
        lines.append(f"    Evidence mode: {c.evidence_mode}")
        lines.append(f"    Summary:       {c.summary}")
        lines.append("    Trace:")
        for step in c.steps:
            lines.append(f"      -> [{step.role.upper()}] {step.file}:{step.line}  {step.detail}")
            if step.code:
                lines.append(f"           {step.code}")
        lines.append(f"    Remediation:   {c.remediation}")

    return "\n".join(lines)
