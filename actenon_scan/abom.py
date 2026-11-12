"""Agent Bill of Materials (ABOM) & Consequence Lockfile (``actenon.lock.json``).

Provides two enterprise-grade primitives with zero runtime dependencies:
  1. ``actenon-scan abom [path]`` : Emit a complete, schema-versioned inventory
     (``actenon-abom/v1``) of an agent repository's consequential capabilities,
     guard proof states, compound risk chains, MCP servers, skill files, and
     explicit coverage/honesty boundaries.
  2. ``actenon-scan lock [path]`` / ``actenon-scan lock --check [path]`` :
     Pin the approved consequential capability surface in ``actenon.lock.json``
     (line-number-resilient) and fail CI whenever a PR or coding agent silently
     introduces a new consequential power, weakens/removes an existing guard,
     introduces a compound exfiltration chain, or wires in an unapproved MCP server.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from actenon_scan import __version__
from actenon_scan.chains import detect_compound_chains
from actenon_scan.engine import ScanResult, scan_path
from actenon_scan.mcp_audit import audit_agent_surface
from actenon_scan.onboarding import _write_file_secure_public
from actenon_scan.report.blast_radius import consequence_label
from actenon_scan.suppress import collect_suppressions_from_target

DEFAULT_LOCKFILE_NAME = "actenon.lock.json"


def _norm_rel(p: str) -> str:
    return p.replace("\\", "/")


def generate_abom(
    target: str | Path = ".",
    *,
    scan_result: ScanResult | None = None,
    config: str | Path | None = None,
) -> dict[str, Any]:
    """Generate a deterministic ``actenon-abom/v1`` dictionary for ``target``."""
    target_path = Path(target).resolve()
    if scan_result is not None:
        result = scan_result
    else:
        suppressions = collect_suppressions_from_target(target_path)
        result = scan_path(target_path, config=config, suppressions=suppressions)
    chain_rep = detect_compound_chains(target_path, scan_result=result)
    surface_rep = audit_agent_surface(
        target_path, include_machine=False, scan_local_sources=False
    )

    caps_sorted = sorted(
        result.capabilities,
        key=lambda c: (_norm_rel(c.file), c.line, c.rule_id, c.call_text),
    )
    capabilities_out: list[dict[str, Any]] = []
    by_consequence: Counter[str] = Counter()
    for c in caps_sorted:
        clabel = consequence_label(c.category)
        by_consequence[clabel] += 1
        capabilities_out.append(
            {
                "file": _norm_rel(c.file),
                "line": c.line,
                "language": c.language,
                "rule_id": c.rule_id,
                "category": c.category,
                "consequence": clabel,
                "severity": c.severity,
                "call_text": c.call_text,
                "state": c.state,
                "guard_status": c.guard_status or "unguarded",
                "guard_message": c.guard_message,
                "confidence": c.confidence,
                "reachability_reason": c.reachability_reason,
                "tier": c.tier,
                "snippet_hash": c.snippet_hash,
            }
        )

    active_findings = [f for f in result.findings if not f.suppressed]
    unsupported_by_lang = Counter(lang for _, lang in result.unsupported_files)

    abom: dict[str, Any] = {
        "schema": "actenon-abom/v1",
        "scanner": "actenon-scan",
        "scanner_version": __version__,
        "summary": {
            "total_capabilities": len(capabilities_out),
            "guarded_capabilities": sum(1 for c in capabilities_out if c["state"] == "GUARD_FOUND"),
            "unguarded_capabilities": sum(1 for c in capabilities_out if c["state"] == "REVIEW_REQUIRED"),
            "active_findings": len(active_findings),
            "compound_chains": len(chain_rep.chains),
            "mcp_servers": len(surface_rep.mcp_servers),
            "instruction_files": len(surface_rep.instruction_files),
            "surface_risks": len(surface_rep.risks),
            "by_consequence": dict(sorted(by_consequence.items())),
        },
        "capabilities": capabilities_out,
        "compound_chains": [c.to_dict() for c in chain_rep.chains],
        "mcp_servers": [
            {
                "harness": s.harness,
                "name": s.name,
                "transport": s.transport,
                "command_summary": s.command_summary,
                "exposed_env_keys": s.exposed_env_keys,
                "risk_ids": sorted({r.rule_id for r in s.risks}),
            }
            for s in sorted(surface_rep.mcp_servers, key=lambda x: (x.harness, x.name))
        ],
        "instruction_files": [
            {
                "path": _norm_rel(ins.path),
                "kind": ins.kind,
                "risk_ids": sorted({r.rule_id for r in ins.risks}),
            }
            for ins in sorted(surface_rep.instruction_files, key=lambda x: _norm_rel(x.path))
        ],
        "coverage_ledger": {
            "files_scanned": result.files_scanned,
            "unsupported_file_count": len(result.unsupported_files),
            "unsupported_by_language": dict(sorted(unsupported_by_lang.items())),
            "analysis_error_count": len(result.analysis_errors),
            "repository_analysis_enabled": result.repository_analysis_enabled,
            "transitive_followed_count": result.transitive_followed_count,
            "transitive_unfollowed_count": result.transitive_unfollowed_count,
            "local_calls_followed": result.local_calls_followed,
            "local_calls_unfollowed": result.local_calls_unfollowed,
            "honesty_statement": (
                "Zero findings or an unchanged ABOM never proves absence of risk; "
                "unsupported languages, dynamic dispatch, and external MCP packages remain outside static proof."
            ),
        },
    }
    digest_src = json.dumps(
        {
            "capabilities": abom["capabilities"],
            "compound_chains": abom["compound_chains"],
            "mcp_servers": abom["mcp_servers"],
            "instruction_files": abom["instruction_files"],
        },
        sort_keys=True,
    )
    abom["surface_fingerprint"] = hashlib.sha256(digest_src.encode("utf-8")).hexdigest()[:16]
    return abom


def format_abom_text(abom: dict[str, Any]) -> str:
    s = abom["summary"]
    cov = abom["coverage_ledger"]
    lines = [
        f"AGENT BILL OF MATERIALS (ABOM)  [fingerprint: {abom['surface_fingerprint']}]",
        "",
        f"Consequential capabilities: {s['total_capabilities']} "
        f"(guarded: {s['guarded_capabilities']}, review required: {s['unguarded_capabilities']})",
        f"Compound consequence chains: {s['compound_chains']}",
        f"Configured MCP servers:      {s['mcp_servers']}",
        f"Instruction / skill files:   {s['instruction_files']} (surface risks: {s['surface_risks']})",
    ]
    if s["by_consequence"]:
        lines.append("")
        lines.append("Capabilities by Consequence:")
        for cons, count in s["by_consequence"].items():
            lines.append(f"  {cons:16s} {count}")

    if abom["capabilities"]:
        lines.append("")
        lines.append("Capability Inventory:")
        for c in abom["capabilities"]:
            badge = "GUARDED" if c["state"] == "GUARD_FOUND" else c["guard_status"].upper()
            lines.append(
                f"  [{badge:9s}] {c['consequence']:12s} {c['file']}:{c['line']}  "
                f"{c['call_text']}  ({c['rule_id']})"
            )

    if abom["compound_chains"]:
        lines.append("")
        lines.append("Compound Risk Chains:")
        for ch in abom["compound_chains"]:
            lines.append(f"  [{ch['severity'].upper()}] {ch['chain_id']}: {ch['title']}")
            lines.append(f"    {ch['summary']}")

    if abom["mcp_servers"]:
        lines.append("")
        lines.append("MCP Servers:")
        for srv in abom["mcp_servers"]:
            risk_txt = f" [risks: {', '.join(srv['risk_ids'])}]" if srv["risk_ids"] else ""
            lines.append(f"  - {srv['name']} ({srv['harness']}, {srv['transport']}){risk_txt}")

    lines.append("")
    lines.append(
        f"Coverage: {cov['files_scanned']} file(s) scanned, "
        f"{cov['unsupported_file_count']} unsupported, "
        f"{cov['transitive_unfollowed_count']} unresolved transitive call(s)."
    )
    lines.append(cov["honesty_statement"])
    return "\n".join(lines)


def format_abom_markdown(abom: dict[str, Any]) -> str:
    s = abom["summary"]
    cov = abom["coverage_ledger"]
    lines = [
        f"# Agent Bill of Materials (ABOM) — `{abom['surface_fingerprint']}`",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Total Consequential Capabilities | {s['total_capabilities']} |",
        f"| Guarded Capabilities (`GUARD_FOUND`) | {s['guarded_capabilities']} |",
        f"| Unguarded / Review Required | {s['unguarded_capabilities']} |",
        f"| Compound Consequence Chains | {s['compound_chains']} |",
        f"| Workspace MCP Servers | {s['mcp_servers']} |",
        f"| Agent Instruction / Skill Files | {s['instruction_files']} |",
        "",
    ]
    if abom["capabilities"]:
        lines.extend([
            "## Consequential Capability Inventory",
            "",
            "| Status | Consequence | Location | Call | Rule |",
            "|---|---|---|---|---|",
        ])
        for c in abom["capabilities"]:
            badge = "GUARDED" if c["state"] == "GUARD_FOUND" else c["guard_status"].upper()
            lines.append(
                f"| `{badge}` | {c['consequence']} | `{c['file']}:{c['line']}` | "
                f"`{c['call_text']}` | `{c['rule_id']}` |"
            )
        lines.append("")

    if abom["compound_chains"]:
        lines.extend(["## Compound Risk Chains", ""])
        for ch in abom["compound_chains"]:
            lines.append(f"- **[{ch['severity'].upper()}] `{ch['chain_id']}` — {ch['title']}**: {ch['summary']}")
        lines.append("")

    lines.extend([
        "## Coverage & Epistemic Boundaries",
        "",
        f"- **Files scanned:** {cov['files_scanned']} (unsupported: {cov['unsupported_file_count']}, "
        f"analysis errors: {cov['analysis_error_count']})",
        f"- **Unfollowed transitive calls:** {cov['transitive_unfollowed_count']}",
        f"- _{cov['honesty_statement']}_",
    ])
    return "\n".join(lines)


def _base_rule_id(rule_id: str) -> str:
    for suffix in ("-WEAK", "-UNBOUND"):
        if rule_id.endswith(suffix):
            return rule_id[: -len(suffix)]
    return rule_id


def build_lockfile_payload(abom: dict[str, Any]) -> dict[str, Any]:
    """Build a deterministic, line-number-resilient ``actenon.lock.json`` payload."""
    locked_caps = []
    for c in abom["capabilities"]:
        locked_caps.append(
            {
                "file": c["file"],
                "base_rule_id": _base_rule_id(c["rule_id"]),
                "rule_id": c["rule_id"],
                "category": c["category"],
                "call_text": c["call_text"],
                "state": c["state"],
                "guard_status": c["guard_status"],
            }
        )
    locked_caps.sort(
        key=lambda x: (x["file"], x["base_rule_id"], x["call_text"], x["state"])
    )

    locked_chains = sorted(
        {
            (
                ch["chain_id"],
                tuple(sorted({_norm_rel(s["file"]) for s in ch.get("steps", [])})),
            )
            for ch in abom.get("compound_chains", [])
        }
    )

    locked_mcp = [
        {
            "harness": m["harness"],
            "name": m["name"],
            "transport": m["transport"],
            "exposed_env_keys": m["exposed_env_keys"],
            "risk_ids": m["risk_ids"],
        }
        for m in abom.get("mcp_servers", [])
    ]

    locked_instr_risks = [
        {"path": ins["path"], "risk_ids": ins["risk_ids"]}
        for ins in abom.get("instruction_files", [])
        if ins.get("risk_ids")
    ]

    return {
        "schema": "actenon-scan/lock/v1",
        "scanner": "actenon-scan",
        "capabilities": locked_caps,
        "compound_chains": [
            {"chain_id": cid, "files": list(files)} for cid, files in locked_chains
        ],
        "mcp_servers": locked_mcp,
        "instruction_risks": locked_instr_risks,
    }


def write_lockfile(
    target: str | Path = ".",
    *,
    output_path: str | Path | None = None,
    config: str | Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Generate and atomically write ``actenon.lock.json``."""
    target_path = Path(target).resolve()
    default_dir = target_path if target_path.is_dir() else target_path.parent
    out = Path(output_path) if output_path is not None else (default_dir / DEFAULT_LOCKFILE_NAME)
    abom = generate_abom(target_path, config=config)
    payload = build_lockfile_payload(abom)
    _write_file_secure_public(out, json.dumps(payload, indent=2) + "\n")
    return out, payload


@dataclass
class LockDriftReport:
    passed: bool
    lockfile_path: str
    added_capabilities: list[dict[str, Any]] = field(default_factory=list)
    regressed_guards: list[dict[str, Any]] = field(default_factory=list)
    removed_capabilities: list[dict[str, Any]] = field(default_factory=list)
    added_chains: list[dict[str, Any]] = field(default_factory=list)
    added_mcp_servers: list[dict[str, Any]] = field(default_factory=list)
    added_surface_risks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "actenon-scan/lock-check/v1",
            "passed": self.passed,
            "lockfile_path": self.lockfile_path,
            "added_capabilities": self.added_capabilities,
            "regressed_guards": self.regressed_guards,
            "removed_capabilities": self.removed_capabilities,
            "added_chains": self.added_chains,
            "added_mcp_servers": self.added_mcp_servers,
            "added_surface_risks": self.added_surface_risks,
        }


def check_lockfile(
    target: str | Path = ".",
    *,
    lockfile_path: str | Path | None = None,
    config: str | Path | None = None,
) -> LockDriftReport:
    """Compare current workspace capability surface against ``actenon.lock.json``."""
    target_path = Path(target).resolve()
    default_dir = target_path if target_path.is_dir() else target_path.parent
    lpath = Path(lockfile_path) if lockfile_path is not None else (default_dir / DEFAULT_LOCKFILE_NAME)
    if not lpath.is_file():
        raise FileNotFoundError(
            f"Lockfile not found at {lpath}. Create one first with: actenon-scan lock {target}"
        )

    expected = json.loads(lpath.read_text(encoding="utf-8"))
    current_abom = generate_abom(target_path, config=config)
    current = build_lockfile_payload(current_abom)

    # Index capabilities by (file, base_rule_id, call_text) with multiset counts
    def _cap_key(c: dict[str, Any]) -> tuple[str, str, str]:
        return (c["file"], c["base_rule_id"], c["call_text"])

    exp_by_key: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for c in expected.get("capabilities", []):
        exp_by_key.setdefault(_cap_key(c), []).append(c)

    cur_by_key: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for c in current.get("capabilities", []):
        cur_by_key.setdefault(_cap_key(c), []).append(c)

    added_caps: list[dict[str, Any]] = []
    regressed: list[dict[str, Any]] = []
    removed_caps: list[dict[str, Any]] = []

    all_keys = sorted(set(exp_by_key.keys()) | set(cur_by_key.keys()))
    for k in all_keys:
        exp_list = exp_by_key.get(k, [])
        cur_list = cur_by_key.get(k, [])
        if not exp_list:
            added_caps.extend(cur_list)
            continue
        if not cur_list:
            removed_caps.extend(exp_list)
            continue
        exp_guarded = sum(1 for x in exp_list if x.get("state") == "GUARD_FOUND")
        cur_guarded = sum(1 for x in cur_list if x.get("state") == "GUARD_FOUND")
        if len(cur_list) > len(exp_list):
            added_caps.extend(cur_list[len(exp_list):])
        if cur_guarded < exp_guarded:
            for x in cur_list:
                if x.get("state") != "GUARD_FOUND":
                    regressed.append(x)
                    break

    exp_chains = {
        (c["chain_id"], tuple(c.get("files", [])))
        for c in expected.get("compound_chains", [])
    }
    added_chains = [
        c for c in current.get("compound_chains", [])
        if (c["chain_id"], tuple(c.get("files", []))) not in exp_chains
    ]

    exp_mcp_names = {(m["harness"], m["name"]) for m in expected.get("mcp_servers", [])}
    added_mcp = [
        m for m in current.get("mcp_servers", [])
        if (m["harness"], m["name"]) not in exp_mcp_names
    ]

    exp_risks: set[str] = set()
    for m in expected.get("mcp_servers", []):
        for r in m.get("risk_ids", []):
            exp_risks.add(f"mcp:{m['name']}:{r}")
    for ins in expected.get("instruction_risks", []):
        for r in ins.get("risk_ids", []):
            exp_risks.add(f"skill:{ins['path']}:{r}")

    cur_risks: set[str] = set()
    for m in current.get("mcp_servers", []):
        for r in m.get("risk_ids", []):
            cur_risks.add(f"mcp:{m['name']}:{r}")
    for ins in current.get("instruction_risks", []):
        for r in ins.get("risk_ids", []):
            cur_risks.add(f"skill:{ins['path']}:{r}")

    added_risks = sorted(cur_risks - exp_risks)

    passed = not (added_caps or regressed or added_chains or added_mcp or added_risks)
    return LockDriftReport(
        passed=passed,
        lockfile_path=str(lpath),
        added_capabilities=added_caps,
        regressed_guards=regressed,
        removed_capabilities=removed_caps,
        added_chains=added_chains,
        added_mcp_servers=added_mcp,
        added_surface_risks=added_risks,
    )


def format_lock_drift_text(report: LockDriftReport) -> str:
    if report.passed:
        removed_note = (
            f" ({len(report.removed_capabilities)} capability(ies) removed — run `actenon-scan lock` to tighten lockfile)"
            if report.removed_capabilities
            else ""
        )
        return f"OK: capability surface matches {report.lockfile_path} (no unapproved powers or guard regressions){removed_note}."

    lines = [
        f"CONSEQUENCE LOCK DRIFT DETECTED ({report.lockfile_path})",
        "",
    ]
    if report.added_capabilities:
        lines.append(f"New unapproved consequential capabilities (+{len(report.added_capabilities)}):")
        for c in report.added_capabilities:
            lines.append(f"  + [{c['state']}] {c['file']}  {c['call_text']} ({c['rule_id']})")
    if report.regressed_guards:
        lines.append(f"Guard regressions ({len(report.regressed_guards)} previously guarded capability became unguarded/weak):")
        for c in report.regressed_guards:
            lines.append(f"  ! [REGRESSED -> {c['guard_status'].upper()}] {c['file']}  {c['call_text']} ({c['rule_id']})")
    if report.added_chains:
        lines.append(f"New compound consequence chains (+{len(report.added_chains)}):")
        for ch in report.added_chains:
            lines.append(f"  + {ch['chain_id']} in {', '.join(ch.get('files', []))}")
    if report.added_mcp_servers:
        lines.append(f"New unapproved MCP servers (+{len(report.added_mcp_servers)}):")
        for m in report.added_mcp_servers:
            lines.append(f"  + [{m['harness']}] {m['name']} ({m['transport']})")
    if report.added_surface_risks:
        lines.append(f"New MCP / skill surface risks (+{len(report.added_surface_risks)}):")
        for r in report.added_surface_risks:
            lines.append(f"  + {r}")
    lines.append("")
    lines.append("Either authorize/remediate the new capability or, if intentionally approved, update the lockfile with:")
    lines.append("  actenon-scan lock .")
    return "\n".join(lines)
