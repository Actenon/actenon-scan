"""Execution-path explanation formatter.

Work Order 2, Part 2: ``actenon-scan explain <file:line>`` shows the
analysed execution path for a finding. It consumes the same reusable
typed internal representations as the brief (Part 6.1 of W1).

Output structure (Part 2.1):
  1. AGENT ENTRY
  2. MODEL-CONTROLLED INPUTS
  3. EXECUTION PATH
  4. GUARD EVIDENCE
  5. CONSEQUENCE
  What this means
  What this does NOT establish
  Coverage
"""

from __future__ import annotations

from actenon_scan.brief import Brief, build_brief


def format_explain(brief: Brief) -> str:
    """Format a brief as an execution-path explanation."""
    lines: list[str] = []

    # Header
    call_short = _short_call(brief.sink.call_text)
    lines.append(f"{brief.location.file}:{brief.location.line}  {call_short}")
    lines.append("")

    # 1. AGENT ENTRY
    lines.append("1. AGENT ENTRY")
    if brief.agent_entry_point.decorator:
        lines.append(f"   {brief.agent_entry_point.decorator}")
        lines.append(f"   The model can invoke `{brief.agent_entry_point.function_name}` by name.")
    else:
        lines.append(f"   {brief.agent_entry_point.function_name}")
        lines.append("   The model can invoke this entry point.")
    lines.append("")

    # 2. MODEL-CONTROLLED INPUTS
    lines.append("2. MODEL-CONTROLLED INPUTS")
    if brief.caller_controlled_parameters:
        for p in brief.caller_controlled_parameters:
            lines.append(f"   {p.name}")
    else:
        lines.append("   (none identified in the analysed path)")
    lines.append("")

    # 3. EXECUTION PATH
    lines.append("3. EXECUTION PATH")
    lines.append(f"   tool input")
    lines.append(f"   -> {brief.agent_entry_point.function_name}()")
    if brief.receiver_chain:
        lines.append(f"   -> {brief.receiver_chain.origin}...")
    lines.append(f"   -> {brief.sink.call_text}")
    lines.append("")

    # 4. GUARD EVIDENCE
    lines.append("4. GUARD EVIDENCE")
    if brief.existing_checks.checks:
        for c in brief.existing_checks.checks:
            dom = " [DOMINATING]" if c.dominates else ""
            lines.append(f"   {c.description}{dom}")
            lines.append(f"   {c.reason}")
    else:
        lines.append("   No dominating authorization check was identified on the analysed path.")
    lines.append("")

    # 5. CONSEQUENCE
    lines.append("5. CONSEQUENCE")
    consequence_desc = _consequence_description(brief.sink.category)
    lines.append(f"   {consequence_desc}")
    lines.append("")

    # What this means
    lines.append("What this means")
    lines.append(_what_this_means(brief))
    lines.append("")

    # What this does NOT establish
    lines.append("What this does NOT establish")
    for para in brief.limitations.text.split("\n"):
        if para.strip():
            lines.append(f"   {para}")
    lines.append("")

    # Coverage
    lines.append("Coverage")
    # The docs/ directory is not shipped in the wheel (only the actenon_scan
    # package is). Point users at the canonical GitHub URL so the reference
    # resolves whether they installed via pip or are running from source.
    lines.append("   See https://github.com/Actenon/actenon-scan/blob/main/docs/COVERAGE.md")
    lines.append("   for supported architectures and analysis limits.")

    return "\n".join(lines) + "\n"


def _short_call(call_text: str) -> str:
    """Short readable name from a call text."""
    if "(" in call_text:
        before = call_text[: call_text.index("(")]
        if "." in before:
            return before.rsplit(".", 1)[-1].strip() + "()"
        return before.strip() + "()"
    return call_text.strip()


def _consequence_description(category: str) -> str:
    """Human-readable description of the consequence."""
    descriptions = {
        "repository_mutation": "A repository mutation request is sent using model-controlled parameters.",
        "vcs_mutation": "A repository mutation request is sent using model-controlled parameters.",
        "payments": "A payment operation is sent using model-controlled payment values.",
        "data_destruction": "A data-destruction operation is sent using model-controlled parameters.",
        "database_mutation": "A database mutation is executed using model-controlled SQL.",
        "code_execution": "Arbitrary code is executed using model-controlled input.",
        "shell_execution": "A shell command is executed using model-controlled input.",
        "network_egress": "A network request is sent to a model-controlled URL.",
        "communication": "A message is sent using model-controlled content and recipients.",
        "identity_change": "An identity-mutating operation is performed using model-controlled parameters.",
        "access_control": "An access-control mutation is performed using model-controlled parameters.",
        "credential_access": "A secret is read using model-controlled parameters.",
        "file_mutation": "A file is mutated using model-controlled path or content.",
        "browser_action": "A browser action is performed using model-controlled input.",
        "deployment": "A deployment is triggered using model-controlled parameters.",
        "provider_sdk": "A provider SDK call is made using model-controlled parameters.",
    }
    return descriptions.get(category, f"A consequential action is performed using model-controlled parameters.")


def _what_this_means(brief: Brief) -> str:
    """The 'what this means' section — adapted to confidence."""
    if brief.sink.confidence == "high":
        return (
            f"The model can supply the parameters to a consequential "
            f"{brief.sink.category.replace('_', ' ')} operation. "
            f"The analysed path does not establish independent authority for this "
            f"exact action before the side effect."
        )
    elif brief.sink.confidence == "medium":
        return (
            f"The model likely supplies the parameters to a consequential "
            f"{brief.sink.category.replace('_', ' ')} operation, but some links "
            f"in the chain are heuristic. The analysed path does not establish "
            f"independent authority for this exact action before the side effect."
        )
    else:
        return (
            f"A consequential {brief.sink.category.replace('_', ' ')} operation "
            f"may be reachable from the model, but the analysis could not fully "
            f"bind the chain. See the guard-evidence section for which link is weak."
        )
