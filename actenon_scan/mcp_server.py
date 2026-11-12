"""Zero-dependency Model Context Protocol (MCP) stdio server (``actenon-scan mcp-server``).

Lets Claude Code, Cursor, Antigravity, Claude Desktop, Windsurf, Gemini CLI, Codex,
and any MCP-compatible coding agent invoke Actenon Scan's consequence engine natively
as structured, read-only tools — with 0 third-party runtime dependencies.

Supported JSON-RPC 2.0 stdio framings (auto-detected per client):
  - Newline-delimited JSON (MCP 2024-11-05 / 2025-03-26 standard stdio transport)
  - ``Content-Length: <bytes>\\r\\n\\r\\n`` header-framed JSON-RPC
"""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path
from typing import Any, BinaryIO

from actenon_scan import __version__

SUPPORTED_PROTOCOL_VERSION = "2024-11-05"
MAX_FRAME_BYTES = 32 * 1024 * 1024

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "actenon_blast_radius",
        "description": (
            "Scan a file or repository for the AI-agent execution gap: agent-reachable "
            "consequential actions (payments, data deletion, shell/code execution, file/DB "
            "mutations, secret reads, network egress) lacking a dominating authorization check, "
            "plus multi-step compound consequence chains."
        ),
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File or directory path to scan (default: '.').",
                    "default": ".",
                },
                "changed_only": {
                    "type": "string",
                    "description": "Optional git ref (e.g. 'HEAD' or 'origin/main') to scan only changed files.",
                },
            },
        },
    },
    {
        "name": "actenon_audit",
        "description": (
            "Static X-ray of MCP server configurations (.mcp.json, .cursor/mcp.json, etc.) "
            "and agent skill/instruction files (SKILL.md, CLAUDE.md, AGENTS.md, .cursorrules) "
            "for exposed credentials (values redacted), unpinned npx/uvx execution, broad "
            "filesystem mounts, Trojan/invisible Unicode, and pipe-to-shell directives."
        ),
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Workspace directory or config file to audit (default: '.').",
                    "default": ".",
                },
                "include_machine": {
                    "type": "boolean",
                    "description": "Also audit host-level IDE/agent MCP configs in the user home directory.",
                    "default": False,
                },
            },
        },
    },
    {
        "name": "actenon_abom",
        "description": (
            "Generate the Agent Bill of Materials (actenon-abom/v1) or verify the workspace "
            "against actenon.lock.json to detect unapproved new agent capabilities or guard regressions."
        ),
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to inspect (default: '.').",
                    "default": ".",
                },
                "check_lock": {
                    "type": "boolean",
                    "description": "When true, verify against actenon.lock.json and report drift.",
                    "default": False,
                },
            },
        },
    },
    {
        "name": "actenon_explain",
        "description": (
            "Explain the exact analysed execution path, model-controlled inputs, transitive "
            "call chain, and guard-dominance evidence for a finding at file:line."
        ),
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "Finding location as 'path/to/file.py:42'.",
                },
                "rule": {
                    "type": "string",
                    "description": "Optional rule ID when multiple rules fire on the same line.",
                },
            },
            "required": ["location"],
        },
    },
    {
        "name": "actenon_fix",
        "description": (
            "Generate a read-only unified remediation diff for a finding at file:line "
            "(modes: 'guard', 'approval', or 'actenon'). Never modifies files on disk."
        ),
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "Finding location as 'path/to/file.py:42'.",
                },
                "mode": {
                    "type": "string",
                    "enum": ["guard", "approval", "actenon"],
                    "description": "Optional remediation mode (auto-selected when omitted).",
                },
                "rule": {
                    "type": "string",
                    "description": "Optional rule ID disambiguator.",
                },
            },
            "required": ["location"],
        },
    },
    {
        "name": "actenon_doctor",
        "description": (
            "Check Python/TypeScript/Go parser availability, git support, CI/pre-commit hooks, "
            "and agent SKILL.md installation status."
        ),
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Workspace directory to inspect (default: '.').",
                    "default": ".",
                }
            },
        },
    },
]


def _parse_location_str(loc: str) -> tuple[Path, int]:
    if ":" not in loc:
        raise ValueError(f"Expected 'file:line' format, got: {loc!r}")
    fpath_str, line_str = loc.rsplit(":", 1)
    return Path(fpath_str), int(line_str)


def dispatch_tool_call(name: str, arguments: dict[str, Any] | None) -> tuple[bool, str]:
    """Execute a read-only MCP tool call, returning ``(is_error, json_or_text_payload)``."""
    args = arguments or {}
    # Redirect any incidental stdout writes inside engine helpers to stderr so
    # stdio JSON-RPC framing remains 100% uncorrupted.
    with contextlib.redirect_stdout(sys.stderr):
        try:
            if name == "actenon_blast_radius":
                from actenon_scan.chains import detect_compound_chains
                from actenon_scan.engine import scan_path
                from actenon_scan.report.json_out import format_json
                from actenon_scan.suppress import collect_suppressions_from_target

                target = Path(str(args.get("path") or "."))
                if not target.exists():
                    return True, f"Path not found: {target}"
                explicit_files = None
                changed_ref = args.get("changed_only")
                if changed_ref:
                    from actenon_scan.cli import _get_changed_files

                    cfiles = _get_changed_files(str(changed_ref), target)
                    if cfiles is None:
                        return True, f"Could not compute git diff for ref: {changed_ref}"
                    base = target if target.is_dir() else target.parent
                    explicit_files = [
                        (base / cf) if not Path(cf).is_absolute() else Path(cf)
                        for cf in cfiles
                    ]
                suppressions = collect_suppressions_from_target(target)
                res = scan_path(target, explicit_files=explicit_files, suppressions=suppressions)
                payload = json.loads(format_json(res))
                chains = detect_compound_chains(target, scan_result=res)
                payload["compound_chains"] = [c.to_dict() for c in chains.chains]
                payload["compound_chain_count"] = len(chains.chains)
                return False, json.dumps(payload, indent=2)

            if name == "actenon_audit":
                from actenon_scan.mcp_audit import audit_agent_surface

                target = Path(str(args.get("path") or "."))
                rep = audit_agent_surface(
                    target,
                    include_machine=bool(args.get("include_machine", False)),
                )
                return False, json.dumps(rep.to_dict(), indent=2)

            if name == "actenon_abom":
                from actenon_scan.abom import check_lockfile, generate_abom

                target = Path(str(args.get("path") or "."))
                if bool(args.get("check_lock", False)):
                    drift = check_lockfile(target)
                    return (not drift.passed), json.dumps(drift.to_dict(), indent=2)
                abom = generate_abom(target)
                return False, json.dumps(abom, indent=2)

            if name == "actenon_explain":
                from actenon_scan.brief import build_brief
                from actenon_scan.explain import format_explain

                fpath, line = _parse_location_str(str(args.get("location") or ""))
                brief = build_brief(fpath, line, rule_id=args.get("rule"))
                if brief is None:
                    return True, f"No finding identified at {fpath}:{line}"
                return False, format_explain(brief)

            if name == "actenon_fix":
                from actenon_scan.fix import generate_fix_diff

                fpath, line = _parse_location_str(str(args.get("location") or ""))
                computed = generate_fix_diff(
                    fpath,
                    line,
                    mode=args.get("mode"),
                    rule_id=args.get("rule"),
                )
                if computed is None:
                    return True, f"No remediable finding identified at {fpath}:{line}"
                fres, _ = computed
                return False, json.dumps(
                    {
                        "mode": fres.mode,
                        "file": str(fpath),
                        "line": line,
                        "rule_id": args.get("rule"),
                        "note": fres.note,
                        "diff": fres.diff,
                    },
                    indent=2,
                )

            if name == "actenon_doctor":
                from actenon_scan.onboarding import collect_doctor_report

                cwd = Path(str(args.get("path") or "."))
                return False, json.dumps(collect_doctor_report(cwd=cwd), indent=2)

            return True, f"Unknown tool: {name}"
        except Exception as exc:
            return True, f"{type(exc).__name__}: {exc}"


def handle_jsonrpc_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Process a single JSON-RPC 2.0 request or notification."""
    method = msg.get("method")
    msg_id = msg.get("id")

    # JSON-RPC notifications (no 'id') expect no response frame.
    if msg_id is None:
        return None

    if method == "initialize":
        params = msg.get("params") or {}
        client_proto = params.get("protocolVersion")
        negotiated = (
            client_proto
            if isinstance(client_proto, str) and client_proto in ("2024-11-05", "2025-03-26", "2025-06-18")
            else SUPPORTED_PROTOCOL_VERSION
        )
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "actenon-scan",
                    "version": __version__,
                },
                "instructions": (
                    "Use actenon_blast_radius and actenon_audit to inspect AI-agent consequential "
                    "actions, MCP configs, and skill files. Never claim a zero-finding scan proves safety."
                ),
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": MCP_TOOLS}}

    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}}

    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}

    if method == "tools/call":
        params = msg.get("params") or {}
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        is_error, text_out = dispatch_tool_call(tool_name, arguments)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": text_out}],
                "isError": is_error,
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def _read_next_frame(in_stream: BinaryIO) -> tuple[dict[str, Any] | None, str]:
    """Read one JSON-RPC message from ``in_stream``, returning ``(msg, framing_mode)``."""
    while True:
        first_line = in_stream.readline()
        if not first_line:
            return None, "line"
        stripped = first_line.strip()
        if not stripped:
            continue

        # Header framing: Content-Length: <N>\r\n\r\n<N bytes>
        if stripped.lower().startswith(b"content-length:"):
            try:
                length = int(stripped.split(b":", 1)[1].strip())
            except ValueError as exc:
                raise json.JSONDecodeError(f"Invalid Content-Length header: {exc}", "", 0) from exc
            if length < 0 or length > MAX_FRAME_BYTES:
                raise json.JSONDecodeError(f"Content-Length out of bounds: {length}", "", 0)
            while True:
                hdr = in_stream.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            body = in_stream.read(length)
            if not body:
                return None, "header"
            return json.loads(body.decode("utf-8")), "header"

        # Newline-delimited JSON framing
        return json.loads(stripped.decode("utf-8")), "line"


def _write_frame(out_stream: BinaryIO, response: dict[str, Any], framing: str) -> None:
    encoded = json.dumps(response, separators=(",", ":")).encode("utf-8")
    if framing == "header":
        header = f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii")
        out_stream.write(header)
        out_stream.write(encoded)
    else:
        out_stream.write(encoded + b"\n")
    out_stream.flush()


def serve_mcp_stdio(
    in_stream: BinaryIO | None = None,
    out_stream: BinaryIO | None = None,
) -> int:
    """Run the blocking JSON-RPC 2.0 MCP server over stdio."""
    reader = in_stream if in_stream is not None else sys.stdin.buffer
    writer = out_stream if out_stream is not None else sys.stdout.buffer

    while True:
        try:
            msg, framing = _read_next_frame(reader)
        except json.JSONDecodeError as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            _write_frame(writer, err_resp, "line")
            continue
        if msg is None:
            return 0
        resp = handle_jsonrpc_message(msg)
        if resp is not None:
            _write_frame(writer, resp, framing)
