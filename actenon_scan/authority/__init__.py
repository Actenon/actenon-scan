"""Structured authority evidence: what each consequential call does and to which resource.

    from actenon_scan.authority import extract_authority
    report = extract_authority("path/to/agent")
    for ev in report.evidence:
        print(ev.action, ev.resource, ev.resource_state, ev.file, ev.line)

See ``model.py`` for the evidence fields and ``routes.py`` for the action vocabulary shared with runtime
enforcement.
"""

from .model import AuthorityEvidence, AuthorityReport, ResourceState, ValueSource
from .python import extract_authority, load_env_files
from .routes import HOLE, HttpAuthority, classify_http, resource_matches

__all__ = [
    "HOLE",
    "AuthorityEvidence",
    "AuthorityReport",
    "HttpAuthority",
    "ResourceState",
    "ValueSource",
    "classify_http",
    "extract_authority",
    "load_env_files",
    "resource_matches",
]
