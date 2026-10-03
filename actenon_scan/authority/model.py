"""Structured authority evidence.

One ``AuthorityEvidence`` records one consequential capability found in source code: the action it
performs, the resource it acts on, whether that resource is fully known, and where every part of the
answer came from. Consumers (Airlock) compile runtime authority from these fields, never from source
text.

Resource states:
  RESOLVED    the resource is fully known (literals, constants, or project configuration read at scan
              time, recorded in ``sources``)
  TEMPLATE    the host/route shape is known and only whole path segments vary, e.g.
              ``api.example.com/sessions/{}``: the code can act on any value of those segments, nothing
              else
  UNRESOLVED  some part that decides *where* the action goes is not statically known (a host, a
              repository name, a URL passed in by the model). Never widened to a wildcard.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ResourceState(str, Enum):
    RESOLVED = "RESOLVED"
    TEMPLATE = "TEMPLATE"
    UNRESOLVED = "UNRESOLVED"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class ValueSource:
    """Where one input of the resource came from."""

    kind: str  # literal | constant | env | config | parameter | attribute | call | unknown
    name: str = ""  # variable / env var / parameter name
    file: str = ""
    line: int = 0
    detail: str = ""  # e.g. "set in .env", "parameter of tool function delete_session"


@dataclass(frozen=True)
class AuthorityEvidence:
    action: str  # e.g. github.issue.create, http.post, filesystem.write, process.exec
    resource: str | None  # canonical resource; None when UNRESOLVED
    resource_state: ResourceState
    file: str
    line: int
    col: int
    end_line: int
    function: str  # enclosing function qualname, "<module>" at top level
    call: str  # the complete call expression (never truncated)
    via: str  # the API that performs the effect, e.g. "requests.request", "PyGithub Repository.create_issue"
    confidence: str  # high | medium | low
    reason: str  # why this is consequential and how the resource was derived
    unresolved_parts: tuple[str, ...] = ()  # what is not known, e.g. ("host",), ("repository",)
    template_params: tuple[str, ...] = ()  # names of the variable segments of a TEMPLATE resource
    sources: tuple[ValueSource, ...] = ()
    method: str = ""  # HTTP method when the effect is an HTTP request
    url: str = ""  # the URL as far as known ("{}" marks unknown parts)
    tool_entry: bool = False  # the enclosing function is registered as an agent tool
    call_path: tuple[str, ...] = ()  # local call chain from the call site to the effect, outermost first

    @property
    def key(self) -> tuple[str, str]:
        """The authority entry this evidence supports: (action, resource or UNRESOLVED marker)."""
        return (self.action, self.resource if self.resource is not None else f"<unresolved:{self.file}:{self.line}>")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["resource_state"] = self.resource_state.value
        d["unresolved_parts"] = list(self.unresolved_parts)
        d["template_params"] = list(self.template_params)
        d["call_path"] = list(self.call_path)
        d["sources"] = [asdict(s) for s in self.sources]
        return d


@dataclass
class AuthorityReport:
    root: str
    evidence: list[AuthorityEvidence] = field(default_factory=list)
    files_analysed: int = 0
    parse_errors: list[dict[str, Any]] = field(default_factory=list)
    env_files: list[str] = field(default_factory=list)  # project configuration files consulted

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "actenon-scan/authority-evidence/v1",
            "root": self.root,
            "files_analysed": self.files_analysed,
            "parse_errors": list(self.parse_errors),
            "env_files": list(self.env_files),
            "evidence": [e.to_dict() for e in self.evidence],
        }
