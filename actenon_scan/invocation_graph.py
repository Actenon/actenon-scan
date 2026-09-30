"""Language-neutral invocation identity, root provenance and bounded traversal.

This graph describes calls and possible implementations, never effects.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from pathlib import PurePosixPath

from actenon_scan.repository.symbol_index import ResolutionCertainty
from actenon_scan.binding_claims import BindingClaim, BindingState


class RootKind(str, Enum):
    MODEL_CALLABLE = "MODEL_CALLABLE"
    PROGRAM_ENTRY = "PROGRAM_ENTRY"
    RESOURCE_ENTRY = "RESOURCE_ENTRY"
    PUBLIC_API = "PUBLIC_API"


def stable_id(prefix: str, *coordinates: object) -> str:
    # Length framing avoids collisions between coordinates containing separators.
    payload = "".join(f"{len(str(x))}:{x}" for x in coordinates)
    return prefix + "-" + sha256(payload.encode()).hexdigest()[:24]


@dataclass(frozen=True)
class Entrypoint:
    path: str
    symbol: str
    kind: RootKind = RootKind.PROGRAM_ENTRY

    def __post_init__(self):
        path = PurePosixPath(str(self.path).replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("entrypoint path must be relative to the workspace")
        if not self.symbol or not self.symbol.strip():
            raise ValueError("entrypoint symbol must not be empty")
        object.__setattr__(self, "path", str(path))
        object.__setattr__(self, "kind", RootKind(self.kind))


@dataclass(frozen=True)
class GraphLimits:
    max_depth: int = 32
    max_invocations: int = 50000
    max_files: int = 4000
    max_bytes: int = 268435456

    def __post_init__(self):
        if any(type(v) is not int or v < 0 for v in vars(self).values()):
            raise ValueError("graph limits must be nonnegative integers")


@dataclass(frozen=True)
class CallableSymbol:
    language: str
    file: str
    symbol: str
    line: int
    column: int
    # Used by adapters for simple, explicitly scoped lexical bindings.
    scope: str = ""

    @property
    def key(self) -> str:
        return stable_id("symbol", self.language, self.file, self.symbol, self.line, self.column)


@dataclass(frozen=True)
class ImplementationTarget:
    """A possible local body, opaque target, or computed/unresolved dispatch."""
    candidate_id: str
    symbol: str | None = None
    file: str | None = None
    line: int | None = None
    column: int | None = None
    callable_key: str | None = None
    opaque: bool = False
    dynamic: bool = False

    @classmethod
    def local(cls, symbol: CallableSymbol):
        return cls(stable_id("candidate", symbol.key), symbol.symbol, symbol.file,
                   symbol.line, symbol.column, symbol.key)

    def to_dict(self):
        return vars(self).copy()


@dataclass(frozen=True)
class InvocationRoot:
    root_id: str
    language: str
    file: str
    symbol: str
    kind: RootKind
    callable_key: str
    provenance: tuple[str, ...]

    def to_dict(self):
        return {**vars(self), "kind": self.kind.value, "provenance": list(self.provenance)}


@dataclass
class InvocationNode:
    invocation_id: str
    language: str
    file: str
    line: int
    column: int
    caller_symbol: str
    caller_key: str
    callee_spelling: str
    resolution_certainty: ResolutionCertainty
    possible_implementations: tuple[ImplementationTarget, ...]
    resolved_callee_identity: str | None = None
    leaves_workspace: bool | None = None
    matched_rule_ids: tuple[str, ...] = ()
    resolution_error: str | None = None
    root_paths: dict[str, tuple[str, ...]] = field(default_factory=dict)

    binding_claims: tuple[BindingClaim, ...] = ()
    lexical_scope_id: str | None = None

    @property
    def execution_owner_key(self):
        return self.caller_key

    @property
    def established_targets(self):
        if any(b.subject != self.invocation_id or b.state in {BindingState.POSSIBLE, BindingState.UNKNOWN}
               for b in self.binding_claims):
            return ()
        established = {b.candidate_id for b in self.binding_claims
                       if b.state == BindingState.ESTABLISHED}
        # Unique binding authority is required even for externally constructed graphs.
        targets = [t for t in self.possible_implementations
                   if t.candidate_id in established and t.callable_key]
        return tuple(targets) if len(established) == len(targets) == 1 and not self.resolution_error else ()

    @property
    def root_ids(self):
        return tuple(sorted(self.root_paths))

    def to_dict(self):
        return {**vars(self), "resolution_certainty": self.resolution_certainty.value,
                "possible_implementations": [c.to_dict() for c in self.possible_implementations],
                "matched_rule_ids": list(self.matched_rule_ids),
                "binding_claims": [b.to_dict() for b in self.binding_claims],
                "execution_owner_key": self.execution_owner_key,
                "root_ids": list(self.root_ids),
                "root_paths": {r: list(p) for r, p in sorted(self.root_paths.items())}}


@dataclass
class InvocationGraph:
    roots: list[InvocationRoot] = field(default_factory=list)
    # Contains only root-reached calls. Enumeration accounting includes the rest.
    invocations: dict[str, InvocationNode] = field(default_factory=dict)
    invocations_enumerated: int = 0
    roots_discovered: int = 0
    roots_supplied: int = 0
    analysis_errors: list[tuple[str, str]] = field(default_factory=list)
    unsupported_files: list[tuple[str, str]] = field(default_factory=list)
    coverage_gaps: list[tuple[str, str]] = field(default_factory=list)

    def traverse(self, calls: list[InvocationNode], limits: GraphLimits):
        self.invocations.clear()
        adjacency = defaultdict(list)
        for call in calls:
            call.root_paths.clear()
            adjacency[call.caller_key].append(call)
        self.invocations_enumerated = len(calls)
        occurrences = 0
        for root in self.roots:
            queue = deque([(root.callable_key, ())])
            visited = set()
            while queue:
                caller_key, path = queue.popleft()
                if caller_key in visited:
                    continue
                visited.add(caller_key)
                outgoing = adjacency.get(caller_key, ())
                if len(path) >= limits.max_depth:
                    if outgoing:
                        self.coverage_gaps.append((root.root_id, "max_depth reached"))
                    continue
                for call in outgoing:
                    if occurrences >= limits.max_invocations:
                        self.coverage_gaps.append((root.root_id, "max_invocations reached"))
                        return
                    call_path = path + (call.invocation_id,)
                    call.root_paths[root.root_id] = call_path
                    self.invocations[call.invocation_id] = call
                    occurrences += 1
                    # Names and heuristic matches do not establish reachability.
                    for target in call.established_targets:
                        queue.append((target.callable_key, call_path))

    @property
    def coverage(self):
        calls = list(self.invocations.values())
        resolved = sum(bool(c.established_targets) for c in calls)
        return {
            "roots_discovered": self.roots_discovered,
            "roots_supplied": self.roots_supplied,
            "roots_selected": len(self.roots),
            "invocations_enumerated": self.invocations_enumerated,
            "invocations_reached": len(calls),
            "root_invocation_occurrences": sum(len(c.root_paths) for c in calls),
            "resolved_local_calls": resolved,
            "established_edges": resolved,
            "possible_edges": sum(b.state == BindingState.POSSIBLE for c in calls for b in c.binding_claims),
            "unknown_edges": sum(b.state == BindingState.UNKNOWN for c in calls for b in c.binding_claims),
            "refuted_edges": sum(b.state == BindingState.REFUTED for c in calls for b in c.binding_claims),
            "unresolved_calls": len(calls) - resolved,
            "analysis_errors": len(self.analysis_errors),
            "unsupported_files": len(self.unsupported_files),
            "unsupported_languages": sorted({lang for _, lang in self.unsupported_files}),
            "coverage_gaps": len(self.coverage_gaps),
        }

    def to_dict(self):
        return {"roots": [r.to_dict() for r in self.roots],
                "invocations": [c.to_dict() for _, c in sorted(self.invocations.items())]}
