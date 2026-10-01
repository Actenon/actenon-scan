"""Trusted, language-neutral policy for local reachability (never effects).

Frontends provide observations. They cannot select sufficient requirements or
issue authority by constructing SUPPORTED facts. Issuance binds the entire proof
and its context; replacement/serialization is diagnostic, not new authority.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
from enum import Enum
from hashlib import sha256
import json
from actenon_scan.semantic_ir import (
    BASE_OBLIGATIONS, BindingEdgeProof, EdgeObligation as O,
    SemanticState as S, EvaluationMode, meet,
)

GRAMMAR_POLICY = "m1r4-audited-grammar-v1"
LEXICAL_POLICY = "m1r4-lexical-environments-v1"

class ResolutionStepKind(str, Enum):
    LEXICAL_LOOKUP = "LEXICAL_LOOKUP"
    ALIAS_HOP = "ALIAS_HOP"
    IMPORT_HOP = "IMPORT_HOP"
    NAMESPACE_MEMBER = "NAMESPACE_MEMBER"
    RECEIVER_DISPATCH = "RECEIVER_DISPATCH"
    CALLABLE_SELF_BINDING = "CALLABLE_SELF_BINDING"
    DECLARATION = "DECLARATION"
    PACKAGE_LOOKUP = "PACKAGE_LOOKUP"
    UNKNOWN = "UNKNOWN"

@dataclass(frozen=True)
class ResolutionStep:
    kind: ResolutionStepKind
    identity: str
    provenance: str
    def to_dict(self):
        return {"kind": getattr(self.kind, "value", str(self.kind)),
                "identity": self.identity, "provenance": self.provenance}

@dataclass(frozen=True)
class ResolutionContext:
    subject: str
    candidate: str
    language: str
    file: str
    callee: str
    environment: str
    execution_region: str
    owner: str
    candidate_file: str
    candidate_key: str
    steps: tuple[ResolutionStep, ...]
    evidence: frozenset[str]
    candidate_namespace: str
    candidate_kind: str
    line: int
    column: int
    ordinal: int
    complete: bool = True
    binding_kinds: frozenset[str] = frozenset()
    def to_dict(self):
        return {**vars(self), "steps": [s.to_dict() for s in self.steps],
                "evidence": sorted(self.evidence), "binding_kinds": sorted(self.binding_kinds)}

@dataclass(frozen=True)
class LexicalEnvironment:
    environment_id: str
    language: str
    construct_kind: str
    syntactic_parent: str
    lookup_parent: str
    binding_namespace: str
    execution_owner: str
    execution_region: tuple[str, ...]
    closure: S
    provenance: tuple[str, ...]
    def to_dict(self):
        return {**vars(self), "closure": self.closure.value,
                "execution_region": list(self.execution_region), "provenance": list(self.provenance)}

@dataclass(frozen=True)
class ProofWitness:
    obligation: O
    identity: str
    provenance: tuple[str, ...]
    source_digest: str
    policy: str
    state: S
    def to_dict(self):
        return {**vars(self), "obligation": self.obligation.value,
                "state": self.state.value, "provenance": list(self.provenance)}

class CalleeFrame(str, Enum):
    LOCAL_PROVEN = "LOCAL_PROVEN"
    EXTERNAL_OR_UNKNOWN = "EXTERNAL_OR_UNKNOWN"
    AMBIGUOUS = "AMBIGUOUS"

class MutationGuarantee(str, Enum):
    NON_MUTATING_PROVEN = "NON_MUTATING_PROVEN"
    MUTATION_POSSIBLE = "MUTATION_POSSIBLE"

@dataclass(frozen=True)
class EscapeEvent:
    identity: str
    file: str
    scope: str
    site: str
    line: int
    callee: CalleeFrame
    mutation: MutationGuarantee
    destinations: tuple[tuple[str, str], ...]
    provenance: tuple[str, ...]
    intrinsic_identity: str = ""
    capabilities: tuple[str, ...] = ()
    def to_dict(self):
        return {**vars(self), "callee": self.callee.value, "mutation": self.mutation.value,
                "destinations": [list(d) for d in self.destinations], "provenance": list(self.provenance)}


def derive_required_obligations(context):
    """The sole obligation policy. Unknown context never means base-only."""
    if not isinstance(context, ResolutionContext) or not context.complete:
        return None
    if context.language not in {"python", "typescript", "go"}:
        return None
    if any(not getattr(context, name) for name in (
            "subject", "candidate", "file", "callee", "environment", "execution_region",
            "owner", "candidate_file", "candidate_key", "candidate_namespace", "candidate_kind")):
        return None
    from actenon_scan.invocation_graph import stable_id
    if type(context.line) is not int or type(context.column) is not int or type(context.ordinal) is not int or context.line<1 or context.column<1 or context.ordinal<0:
        return None
    if context.subject != stable_id('invocation',context.language,context.file,context.line,context.column,context.ordinal):return None
    if context.candidate != stable_id('candidate',context.candidate_key):return None
    if not context.steps or any(not isinstance(s, ResolutionStep) or
            not isinstance(s.kind, ResolutionStepKind) or s.kind == ResolutionStepKind.UNKNOWN or
            not s.identity or not s.provenance for s in context.steps):
        return None
    kinds = {s.kind for s in context.steps}
    if not context.binding_kinds or not context.binding_kinds <= {
            'callable','coroutine_callable','self_callable','alias','import','ts_import','receiver'}:
        return None
    for observed,step,evidence in (
            ({'alias'},ResolutionStepKind.ALIAS_HOP,'STRUCTURALLY_EXACT_ALIAS'),
            ({'import','ts_import'},ResolutionStepKind.IMPORT_HOP,'IMPORT_PROVENANCE'),
            ({'receiver'},ResolutionStepKind.RECEIVER_DISPATCH,'RECEIVER_IDENTITY')):
        if context.binding_kinds & observed and (step not in kinds or evidence not in context.evidence):return None
    if ResolutionStepKind.LEXICAL_LOOKUP not in kinds or not kinds & {
            ResolutionStepKind.DECLARATION, ResolutionStepKind.CALLABLE_SELF_BINDING}:
        return None
    if context.candidate_kind not in {'FUNCTION','INSTANCE_METHOD','STATIC_METHOD','CALLABLE_VALUE','SELF'}:
        return None
    required = set(BASE_OBLIGATIONS)
    if context.candidate_kind in {'INSTANCE_METHOD','STATIC_METHOD'}:
        if not any(s.kind==ResolutionStepKind.RECEIVER_DISPATCH and s.identity==context.candidate_namespace for s in context.steps):return None
        required.add(O.RECEIVER_COMPATIBLE)
    # Independent contextual cross-checks prevent deleting a path step while
    # leaving the import/receiver/alias evidence or cross-file target intact.
    requirements = {
        "IMPORT_PROVENANCE": ResolutionStepKind.IMPORT_HOP,
        "RECEIVER_IDENTITY": ResolutionStepKind.RECEIVER_DISPATCH,
        "STRUCTURALLY_EXACT_ALIAS": ResolutionStepKind.ALIAS_HOP,
        "CALLABLE_SELF_BINDING": ResolutionStepKind.CALLABLE_SELF_BINDING,
    }
    if any(e in context.evidence and k not in kinds for e, k in requirements.items()):
        return None
    if (context.language != "go" and context.candidate_file != context.file and
            ResolutionStepKind.IMPORT_HOP not in kinds):
        return None
    if (context.language == 'go' and context.candidate_file != context.file and
            ResolutionStepKind.PACKAGE_LOOKUP not in kinds):
        return None
    if kinds & {ResolutionStepKind.IMPORT_HOP, ResolutionStepKind.NAMESPACE_MEMBER}:
        required.add(O.IMPORT_PROVENANCE_EXACT)
    if ResolutionStepKind.RECEIVER_DISPATCH in kinds:
        required.add(O.RECEIVER_COMPATIBLE)
    # An unexplained member spelling cannot masquerade as lexical-only lookup.
    if "." in context.callee and not kinds & {
            ResolutionStepKind.IMPORT_HOP, ResolutionStepKind.NAMESPACE_MEMBER,
            ResolutionStepKind.RECEIVER_DISPATCH, ResolutionStepKind.PACKAGE_LOOKUP}:
        return None
    return frozenset(required)


_ISSUER = object()
@dataclass(frozen=True)
class _Attestation:
    issuer: object
    fingerprint: str
    def __deepcopy__(self, memo):
        return self


def _fingerprint(proof):
    value = {"required": sorted(o.value for o in proof.required),
             "facts": [(o.value, s.value) for o, s in proof.facts],
             "provenance": proof.provenance,
             "context": proof.context.to_dict() if isinstance(proof.context, ResolutionContext) else None,
             "witnesses": [w.to_dict() for w in proof.witnesses]}
    return sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _witnesses_valid(context, required, witnesses):
    if not witnesses or any(not isinstance(w, ProofWitness) for w in witnesses):
        return False
    for obligation in required:
        selected = [w for w in witnesses if w.obligation == obligation]
        if not selected or meet(w.state for w in selected) != S.SUPPORTED:
            return False
        if any(not w.identity or not w.provenance or any(not p for p in w.provenance) or
               len(w.source_digest) != 64 or not w.policy for w in selected):
            return False
        if obligation == O.LEXICAL_ENVIRONMENT_EXACT and not any(
                w.identity == context.environment and w.policy == LEXICAL_POLICY for w in selected):
            return False
        if obligation in {O.WRITE_SET_CLOSED, O.RECEIVER_COMPATIBLE, O.IMPORT_PROVENANCE_EXACT} and any(
                w.policy != GRAMMAR_POLICY for w in selected):
            return False
        if obligation == O.EXECUTION_OWNER_EXACT and not any(w.identity == context.owner for w in selected):
            return False
        if obligation == O.EVALUATION_EAGER and not any(w.identity == context.execution_region for w in selected):
            return False
        if obligation == O.TARGET_EXACT and not any(w.identity == context.candidate_key for w in selected):
            return False
    return True


def _issue(*, context, semantic_facts, witnesses, candidates, counter_evidence=()):
    """Validate observations and issue a content-bound result; no required input."""
    required = derive_required_obligations(context)
    facts = tuple(semantic_facts)
    proof = BindingEdgeProof(required or frozenset(O), facts,
        tuple(sorted({p for w in witnesses for p in w.provenance})), context, tuple(witnesses))
    if (required is not None and not counter_evidence and set(candidates) == {context.candidate} and
            proof.closed and _witnesses_valid(context, required, witnesses)):
        proof = replace(proof, _attestation=_Attestation(_ISSUER, _fingerprint(proof)))
    return proof


def authorizes(proof, subject, candidate, evidence):
    context = proof.context
    stamp = proof._attestation
    if not isinstance(stamp, _Attestation) or stamp.issuer is not _ISSUER:
        return False
    if not isinstance(context, ResolutionContext) or (context.subject, context.candidate) != (subject, candidate):
        return False
    if context.evidence != frozenset(getattr(e, "value", str(e)) for e in evidence):
        return False
    required = derive_required_obligations(context)
    return bool(required is not None and required == proof.required and proof.closed and
        _witnesses_valid(context, required, proof.witnesses) and stamp.fingerprint == _fingerprint(proof))


def non_mutating_frame(statement_kinds, *, exact):
    """Small central frame policy; unknown statements never imply no mutation."""
    return bool(exact and all(k in {"PASS", "RETURN_CONSTANT"} for k in statement_kinds))


def escape_opens_closure(event):
    return not (event.callee == CalleeFrame.LOCAL_PROVEN and
                event.mutation == MutationGuarantee.NON_MUTATING_PROVEN and event.provenance)

@dataclass(frozen=True)
class ScopeAudit:
    environment: LexicalEnvironment
    facets: tuple[tuple[str, S], ...]
    limitations: tuple[str, ...]
    writes: tuple
    source_digest: str
    grammar_digest: str
    grammar_nodes: tuple[tuple[str, str], ...]
    def state(self, facet):
        return meet(v for k,v in self.facets if k == facet)

@dataclass(frozen=True)
class CallableDeclaration:
    callable_key: str
    namespace: str
    file: str
    kind: str
    binding: str
    line: int
    provenance: tuple[str, ...]

@dataclass(frozen=True)
class BindingDeclaration:
    namespace: str
    name: str
    kind: str
    callable_key: str
    alias_scope: str
    alias_name: str
    receiver_namespace: str
    import_namespaces: tuple[str, ...]
    import_member: str | None
    qualified_import: str
    conditional: bool
    counter_evidence: tuple[str, ...]

@dataclass(frozen=True)
class NamespaceObservation:
    namespace: str
    language: str
    file: str
    module: str
    package: str
    exports: frozenset[str] = frozenset()

@dataclass(frozen=True)
class InvocationObservation:
    subject: str
    language: str
    file: str
    callee: str
    line: int
    column: int
    ordinal: int
    environment: str
    owner: str
    region: str
    resumes_coroutine: bool

@dataclass(frozen=True)
class SemanticInventory:
    scopes: tuple[ScopeAudit, ...]
    regions: tuple
    escapes: tuple[EscapeEvent, ...]
    declarations: tuple[CallableDeclaration, ...]
    compiler_symbols: tuple = ()
    bindings: tuple[BindingDeclaration, ...] = ()
    namespaces: tuple[NamespaceObservation, ...] = ()
    sites: tuple[InvocationObservation, ...] = ()
    _audit: object = None

@dataclass(frozen=True)
class LookupObservation:
    environment: str
    binding_environment: str
    classification: str
    provenance: tuple[str, ...]


def evaluate(*, context, inventory=None, lookup=None, candidates=(), counter_evidence=(),
             semantic_facts=(), witnesses=()):
    """Only normalized inventories can issue authority; raw facts are diagnostic.

    The frontend cannot choose the obligation set, seal missing witnesses, choose
    eager execution, or ignore a recorded escape. UNKNOWN observations are met,
    never overwritten by positive evidence from another path.
    """
    if not isinstance(context,ResolutionContext) or not isinstance(inventory, SemanticInventory) or not _inventory_valid(inventory) or not isinstance(lookup, LookupObservation):
        return BindingEdgeProof(frozenset(O), tuple(semantic_facts), (), context, tuple(witnesses))
    site=inventory._audit.sites.get(context.subject)
    if site is None or (site.language,site.file,site.callee,site.line,site.column,site.ordinal,
            site.environment,site.owner,site.region)!=(context.language,context.file,context.callee,
            context.line,context.column,context.ordinal,context.environment,context.owner,context.execution_region):
        return BindingEdgeProof(frozenset(O),tuple(semantic_facts),(),context,tuple(witnesses))
    exact_keys,binding_kinds,binding_environment = _canonical_lookup(inventory,context)
    context=replace(context,binding_kinds=frozenset(binding_kinds))
    declarations = inventory._audit.declarations.get(context.candidate_key,())
    declaration_valid = bool(exact_keys=={context.candidate_key} and len(declarations)==1 and declarations[0].provenance and
        (any(s.kind==ResolutionStepKind.LEXICAL_LOOKUP and s.identity==declarations[0].namespace for s in context.steps) or
         any(s.kind==ResolutionStepKind.CALLABLE_SELF_BINDING and s.identity==context.candidate_key for s in context.steps)) and
        (declarations[0].namespace,declarations[0].file,declarations[0].kind) ==
        (context.candidate_namespace,context.candidate_file,context.candidate_kind))
    required = derive_required_obligations(context)
    scopes = inventory._audit.scopes
    environment = scopes.get(context.environment)
    region = inventory._audit.regions.get(context.execution_region)
    dependencies = {context.environment, lookup.binding_environment}
    for step in context.steps:
        if step.kind in {ResolutionStepKind.LEXICAL_LOOKUP,ResolutionStepKind.IMPORT_HOP,
                         ResolutionStepKind.NAMESPACE_MEMBER,ResolutionStepKind.RECEIVER_DISPATCH}:
            dependencies.add(step.identity)
    audits = [scopes.get(d) for d in sorted(dependencies)]
    def closed(facet):
        if not audits or any(a is None for a in audits):return S.UNKNOWN
        states = []
        for audit in audits:
            if not audit.source_digest or not audit.grammar_digest or not audit.grammar_nodes:
                states.append(S.UNKNOWN)
            else:
                states.append(audit.state(facet))
                from actenon_scan.repository.semantic_frontends import classify_node
                if any(label != classify_node(audit.environment.language,kind) or label == 'CONSERVATIVELY_UNKNOWN'
                        for kind,label in audit.grammar_nodes):states.append(S.UNKNOWN)
            if facet in {'lexical_writes_complete','member_writes_complete'}:
                from actenon_scan.semantic_ir import TargetKind,WriteOperation
                names = {context.callee.split('.')[0],context.callee.split('.')[-1]}
                if declarations:names.add(declarations[0].binding)
                for write in audit.writes:
                    if write.target_kind == TargetKind.UNKNOWN_TARGET:
                        states.append(S.UNKNOWN)
                    elif write.operation == WriteOperation.MAY_WRITE and write.binding in names:
                        states.append(S.UNKNOWN)
                    elif write.target_kind in {TargetKind.MEMBER,TargetKind.NAMESPACE_MEMBER} and write.member in names|{'*'} and write.operation != WriteOperation.DECLARE:
                        states.append(S.UNKNOWN)
                    elif (declarations and write.target_kind == TargetKind.LEXICAL_BINDING and
                          write.operation in {WriteOperation.ASSIGN,WriteOperation.DELETE} and
                          audit.environment.environment_id == declarations[0].namespace and
                          write.binding == declarations[0].binding and write.line != declarations[0].line):
                        states.append(S.UNKNOWN)
            # Independently account for recorded escapes, even if a frontend
            # erroneously left its certificate sealed.
            if facet in inventory._audit.escape_facets.get(audit.environment.environment_id,()):
                states.append(S.UNKNOWN)
        return meet(states)
    lexical = S.UNKNOWN
    if environment and lookup.environment == context.environment and lookup.binding_environment==binding_environment and lookup.provenance and environment.environment.closure == S.SUPPORTED:
        env = environment.environment
        cursor = context.environment; seen = set()
        while cursor and cursor not in seen:
            seen.add(cursor)
            if cursor == lookup.binding_environment:
                lexical = S.SUPPORTED;break
            current = scopes.get(cursor)
            cursor = current.environment.lookup_parent if current else ''
        if context.language == 'python':
            names = dict(dict(inventory.compiler_symbols).get(context.environment,()))
            if names.get(context.callee.split('.')[0]) != lookup.classification:lexical = S.UNKNOWN
            if not any('symtable' in p for p in lookup.provenance):lexical = S.UNKNOWN
            if lookup.classification not in {'LOCAL','FREE','GLOBAL'}:lexical = S.UNKNOWN
            if lookup.classification == 'GLOBAL' and scopes.get(lookup.binding_environment) and scopes[lookup.binding_environment].environment.construct_kind != 'module':lexical = S.UNKNOWN
            if lookup.classification == 'FREE' and scopes.get(lookup.binding_environment) and scopes[lookup.binding_environment].environment.construct_kind == 'class':lexical = S.UNKNOWN
        elif lookup.classification != 'BOUNDED_LEXICAL':lexical = S.UNKNOWN
    eager = S.SUPPORTED if region and region.mode == EvaluationMode.EAGER else S.UNKNOWN
    if 'coroutine_callable' in binding_kinds and not site.resumes_coroutine:eager=S.UNKNOWN
    owner = S.SUPPORTED if region and region.owner_key == context.owner and region.lexical_scope == context.environment and region.owner_exact == S.SUPPORTED else S.UNKNOWN
    if environment and environment.environment.execution_owner != context.owner:owner = S.UNKNOWN
    if closed('execution_semantics_complete') != S.SUPPORTED:eager = S.UNKNOWN
    values = {
        O.TARGET_EXACT: S.SUPPORTED if declaration_valid and set(candidates) == {context.candidate} and not counter_evidence
            and any(s.identity == context.candidate_key and s.kind in {ResolutionStepKind.DECLARATION,ResolutionStepKind.CALLABLE_SELF_BINDING} for s in context.steps) else S.UNKNOWN,
        O.LEXICAL_ENVIRONMENT_EXACT: lexical,
        O.EXECUTION_OWNER_EXACT: owner,
        O.EVALUATION_EAGER: eager,
        O.WRITE_SET_CLOSED: closed('lexical_writes_complete'),
        O.RECEIVER_COMPATIBLE: closed('receiver_semantics_complete') if 'RECEIVER_IDENTITY' in context.evidence else S.UNKNOWN,
        O.IMPORT_PROVENANCE_EXACT: closed('import_semantics_complete') if 'IMPORT_PROVENANCE' in context.evidence else S.UNKNOWN,
    }
    if context.language == 'python' or required and required & {O.RECEIVER_COMPATIBLE,O.IMPORT_PROVENANCE_EXACT}:
        values[O.WRITE_SET_CLOSED] = meet((values[O.WRITE_SET_CLOSED],closed('member_writes_complete')))
    # Caller observations can only lower a derived state.
    for obligation,state in semantic_facts:
        values[obligation] = meet((values.get(obligation,S.UNKNOWN),state))
    provenance = tuple(sorted({p for a in audits if a for p in
        a.environment.provenance + (a.grammar_digest, a.environment.environment_id,
            'write-ledger:'+sha256(json.dumps([w.to_dict() for w in a.writes],sort_keys=True).encode()).hexdigest(),
            'binding-ledger:'+inventory._audit.binding_digests.get(a.environment.environment_id,sha256(b'[]').hexdigest()),
            'escape-ledger:'+inventory._audit.escape_digests.get(a.environment.environment_id,sha256(b'[]').hexdigest()))}))
    digest = environment.source_digest if environment else ''
    observations = []
    for obligation,state in values.items():
        identity = context.candidate_key if obligation == O.TARGET_EXACT else context.owner if obligation == O.EXECUTION_OWNER_EXACT else context.execution_region if obligation == O.EVALUATION_EAGER else context.environment
        origin = lookup.provenance + provenance if obligation == O.LEXICAL_ENVIRONMENT_EXACT else provenance
        observations.append(ProofWitness(obligation,identity,origin,digest,
            LEXICAL_POLICY if obligation == O.LEXICAL_ENVIRONMENT_EXACT else GRAMMAR_POLICY,state))
    return _issue(context=context,semantic_facts=tuple(values.items()),witnesses=observations,
        candidates=candidates,counter_evidence=counter_evidence)

# Language/runtime binding mutation only. These are not resource-effect rules.
STANDARD_INTRINSICS = {
    'python': frozenset({'setattr','delattr'}),
    'typescript': frozenset({'Object.assign','Object.defineProperty','Object.defineProperties',
        'Object.setPrototypeOf','Reflect.set','Reflect.deleteProperty','Reflect.defineProperty',
        'Reflect.setPrototypeOf'}),
}

def intrinsic_capabilities(language, identity):
    return ('MEMBER_MUTATION',) if identity in STANDARD_INTRINSICS.get(language, ()) else ()

@dataclass(frozen=True)
class _InventoryAudit:
    issuer: object
    components: tuple
    scopes: object
    regions: object
    declarations: object
    escape_facets: object
    escape_digests: object
    bindings: object
    namespaces: object
    binding_digests: object
    sites: object

def _inventory_valid(inventory):
    stamp=inventory._audit
    return bool(isinstance(stamp,_InventoryAudit) and stamp.issuer is _ISSUER and
        all(a is b for a,b in zip(stamp.components,(inventory.scopes,inventory.regions,
            inventory.escapes,inventory.declarations,inventory.compiler_symbols,
            inventory.bindings,inventory.namespaces,inventory.sites),strict=True)))

def audit_inventory(inventory, sources):
    """Authenticate compiler/grammar provenance before target resolution.

    Source digests, audited node inventory and environment graph are mandatory.
    Python name classifications are obtained independently from the compiler;
    the frontend's classification can decline these facts, never strengthen them.
    Mutation and escape ledgers are immutable common observations subsequently
    rechecked for each dependent edge. Raw SUPPORTED labels cannot issue proofs.
    """
    import symtable
    from actenon_scan.repository.semantic_frontends import classify_node
    tables={};symbols=[];scopes={a.environment.environment_id:a for a in inventory.scopes}
    if len(scopes)!=len(inventory.scopes) or len({n.namespace for n in inventory.namespaces})!=len(inventory.namespaces) or len({s.subject for s in inventory.sites})!=len(inventory.sites):return inventory
    for audit in inventory.scopes:
        env=audit.environment
        if not env.environment_id or len(audit.source_digest)!=64 or len(audit.grammar_digest)!=64 or not env.provenance or not audit.grammar_nodes:
            return inventory
        source=sources.get(next((p for p in env.provenance if p in sources),''))
        if source is None or sha256(source.encode()).hexdigest()!=audit.source_digest:return inventory
        if any(label!=classify_node(env.language,kind) for kind,label in audit.grammar_nodes):return inventory
        parent=env.syntactic_parent
        if env.language=='python' and env.construct_kind in {'function','lambda','comprehension'}:
            seen=set()
            while parent and parent not in seen and parent in scopes and scopes[parent].environment.construct_kind=='class':
                seen.add(parent);parent=scopes[parent].environment.syntactic_parent
            if parent!=env.lookup_parent:return inventory
        elif env.construct_kind=='module' and env.lookup_parent:return inventory
        if env.language!='python':continue
        file=next(p for p in env.provenance if p in sources)
        if file not in tables:
            root=symtable.symtable(source,file,'exec');found={}
            def visit(table):
                key=f'symtable:{table.get_type()}:{table.get_name()}:{table.get_lineno()}'
                found.setdefault(key,[]).append(table)
                inline=f'symtable-inlined:{table.get_name()}:{table.get_lineno()}'
                found.setdefault(inline,[]).append(table)
                for child in table.get_children():visit(child)
            visit(root);tables[file]=found
        labels=[p for p in env.provenance if p.startswith(('symtable:','symtable-inlined:'))]
        matched=tables[file].get(labels[-1],[]) if labels else []
        if len(matched)!=1:continue # missing compiler map is UNKNOWN, never exact
        if labels[-1].startswith('symtable-inlined:') and env.syntactic_parent in scopes and scopes[env.syntactic_parent].environment.construct_kind=='class':continue
        table=matched[0];facts=[]
        for name in table.get_identifiers():
            symbol=table.lookup(name)
            classification='GLOBAL' if symbol.is_global() and not symbol.is_local() else 'FREE' if symbol.is_free() else 'LOCAL'
            facts.append((name,classification))
        symbols.append((env.environment_id,tuple(sorted(facts))))
    result=replace(inventory,compiler_symbols=tuple(sorted(symbols)))
    components=(result.scopes,result.regions,result.escapes,result.declarations,result.compiler_symbols,
        result.bindings,result.namespaces,result.sites)
    from collections import defaultdict
    from types import MappingProxyType
    declaration_map=defaultdict(list)
    for d in result.declarations:declaration_map[d.callable_key].append(d)
    binding_map=defaultdict(list)
    for b in result.bindings:binding_map[(b.namespace,b.name)].append(b)
    binding_records=defaultdict(list)
    for b in result.bindings:binding_records[b.namespace].append(vars(b))
    binding_digests={k:sha256(json.dumps(sorted(v,key=lambda r:json.dumps(r,sort_keys=True)),sort_keys=True).encode()).hexdigest() for k,v in binding_records.items()}
    opened=defaultdict(set);escape_records=defaultdict(list)
    for event in result.escapes:
        for _,namespace in event.destinations:
            escape_records[namespace].append(event.to_dict())
            if escape_opens_closure(event) and namespace in scopes:
                env=scopes[namespace].environment
                opened[namespace].update(escape_facets(env.language,env.construct_kind))
    digests={key:sha256(json.dumps(records,sort_keys=True).encode()).hexdigest() for key,records in escape_records.items()}
    stamp=_InventoryAudit(_ISSUER,components,MappingProxyType(scopes),
        MappingProxyType({r.region_id:r for r in result.regions}),
        MappingProxyType({k:tuple(v) for k,v in declaration_map.items()}),
        MappingProxyType({k:frozenset(v) for k,v in opened.items()}),MappingProxyType(digests),
        MappingProxyType({k:tuple(v) for k,v in binding_map.items()}),
        MappingProxyType({n.namespace:n for n in result.namespaces}),MappingProxyType(binding_digests),
        MappingProxyType({s.subject:s for s in result.sites}))
    return replace(result,_audit=stamp)


def _canonical_lookup(inventory,context):
    """Check candidate paths against common lexical declarations, not claims.

    Nearest bindings, aliases, import namespaces and receiver namespaces are
    observations sealed before resolution. Conditional/ambiguous/dynamic entries
    cannot manufacture uniqueness by passing a shorter candidate list. This is
    bounded structural verification; unsupported paths fail closed.
    """
    import re
    from pathlib import PurePosixPath
    ledger=inventory._audit.bindings;scopes=inventory._audit.scopes
    namespaces=inventory._audit.namespaces
    if not re.fullmatch(r'[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*',context.callee):return set(),set(),''
    parts=context.callee.split('.');head,tail=parts[0],parts[1:];observed=set()
    def nearest(scope,name):
        seen=set()
        while scope and scope not in seen:
            seen.add(scope)
            entries=ledger.get((scope,name),())+ledger.get((scope,'*'),())
            if entries:return scope,entries
            audit=scopes.get(scope)
            scope=audit.environment.lookup_parent if audit else ''
        return '',()
    def member(namespace,names,seen,loaded='',explicit=False):
        if not names:return set()
        info=namespaces.get(namespace)
        if info and info.language=='typescript' and names[0] not in info.exports:return set()
        entries=ledger.get((namespace,names[0]),())+ledger.get((namespace,'*'),())
        if entries:return resolve(entries,names[1:],seen)
        if info and info.language=='python':
            child=info.module+'.'+names[0]
            if explicit or loaded==child or loaded.startswith(child+'.'):
                matches=[n.namespace for n in namespaces.values() if n.language=='python' and n.module==child]
                if len(matches)==1:return member(matches[0],names[1:],seen,loaded,False)
        return set()
    def resolve(entries,names,seen):
        if len(entries)!=1 or len(seen)>=32:return set()
        b=entries[0];coordinate=(b.namespace,b.name,tuple(names))
        if coordinate in seen or b.conditional or b.counter_evidence:return set()
        seen=seen|{coordinate};observed.add(b.kind)
        if b.kind in {'callable','coroutine_callable','self_callable'}:
            declarations=inventory._audit.declarations.get(b.callable_key,())
            justified=(len(declarations)==1 and (b.kind=='self_callable' and b.namespace==b.callable_key or
                (declarations[0].namespace,declarations[0].binding)==(b.namespace,b.name)))
            return {b.callable_key} if justified and b.callable_key and not names else set()
        if b.kind=='alias' and b.alias_name:
            alias=b.alias_name.split('.');_,bound=nearest(b.alias_scope or b.namespace,alias[0])
            return resolve(bound,alias[1:]+names,seen)
        if b.kind=='receiver' and b.receiver_namespace and len(names)==1:
            return member(b.receiver_namespace,names,seen)
        if b.kind in {'import','ts_import'} and len(b.import_namespaces)==1:
            # A package's explicit `from . import child` loads the child
            # before binding its own name. Do not mistake that declaration
            # for a recursive lookup of the same not-yet-initialized binding.
            source=namespaces.get(b.namespace)
            if (b.kind=='import' and source and b.import_namespaces==(b.namespace,) and
                    b.import_member==b.name):
                children=[n.namespace for n in namespaces.values() if n.language=='python' and n.module==source.module+'.'+b.name]
                if len(children)==1:return member(children[0],names,seen,b.qualified_import)
            names=([b.import_member] if b.import_member not in {None,'*'} else [])+names
            return member(b.import_namespaces[0],names,seen,b.qualified_import,b.import_member is not None)
        return set()
    origin,entries=nearest(context.environment,head)
    # Go package names share a declaration namespace across files. Local names
    # still stop lookup before the package fallback, irrespective of value kind.
    if context.language=='go' and (not entries or scopes.get(origin) and scopes[origin].environment.construct_kind=='module'):
        current=next((n for n in namespaces.values() if n.file==context.file and n.language=='go'),None)
        if current:
            active=[ledger.get((n.namespace,head),()) for n in namespaces.values() if n.language=='go' and
                n.package==current.package and PurePosixPath(n.file).parent==PurePosixPath(current.file).parent]
            active=[e for e in active if e]
            if len(active)!=1:return set(),observed,origin or current.namespace
            entries=active[0];origin=origin or current.namespace
    return resolve(entries,tail,frozenset()),observed,origin


def escape_facets(language, construct_kind):
    """Mutable identity escape is not lexical rebinding in every language.

    JS function bodies and lexical variable cells cannot be replaced by writing
    the captured object. Receiver members and imported namespace provenance
    remain open. Python namespaces/callable bodies are mutable; decline all
    corresponding closure. No resource-effect semantics are involved.
    """
    if language=='typescript':
        return frozenset({'member_writes_complete','receiver_semantics_complete',
            'import_semantics_complete'})
    return frozenset({'lexical_writes_complete','member_writes_complete',
        'receiver_semantics_complete','import_semantics_complete'})
