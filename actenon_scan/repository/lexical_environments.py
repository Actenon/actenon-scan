"""Compiler-backed lexical observations, independent of call-target selection."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
import symtable
from actenon_scan.reachability_kernel import LexicalEnvironment, LEXICAL_POLICY
from actenon_scan.semantic_ir import SemanticState as S


def construct_environments(unit):
    digest = sha256(unit.source.encode()).hexdigest()
    unit.grammar_digest = sha256(json.dumps(sorted({type(n).__name__ for n in ast.walk(unit.tree)})
        if unit.language == 'python' else sorted({n.type for n in _tree_nodes(unit.tree)})).encode()).hexdigest()
    tables = {}
    if unit.language == 'python':
        root = symtable.symtable(unit.source, unit.file, 'exec')
        def visit(table):
            kind = getattr(table.get_type(), 'value', table.get_type())
            tables.setdefault((kind, table.get_name(), table.get_lineno()), []).append(table)
            for child in table.get_children():visit(child)
        visit(root)
        unit.compiler_tables[unit.module_key] = root
        for scope, node in unit.scope_nodes.items():
            if scope == unit.module_key:continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                key = ('class' if isinstance(node, ast.ClassDef) else 'function', node.name, node.lineno)
            elif isinstance(node, ast.Lambda):key = ('function', 'lambda', node.lineno)
            elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                key = ('function', {ast.ListComp:'listcomp',ast.SetComp:'setcomp',ast.DictComp:'dictcomp',ast.GeneratorExp:'genexpr'}[type(node)], node.lineno)
            else:continue
            found = tables.get(key, [])
            if len(found) == 1:unit.compiler_tables[scope] = found[0]
    scopes = set(unit.certificates) | set(unit.scope_nodes) | {unit.module_key}
    for scope in sorted(scopes):
        kind = unit.scope_constructs.get(scope, 'bounded_scope' if unit.language != 'python' else 'unknown')
        syntactic = unit.syntactic_parents.get(scope, unit.scope_parents.get(scope, ''))
        parent = syntactic
        if unit.language == 'python' and kind in {'function','lambda','comprehension'}:
            while unit.scope_constructs.get(parent) == 'class':
                parent = unit.syntactic_parents.get(parent, unit.scope_parents.get(parent, ''))
        if kind == 'module':parent = ''
        unit.scope_parents[scope] = parent
        table = unit.compiler_tables.get(scope)
        state = S.SUPPORTED if kind!='unknown' and (unit.language != 'python' or table) else S.UNKNOWN
        if kind=='unknown' and scope in unit.certificates:
            certificate=unit.certificates[scope]
            certificate.open(tuple(certificate.facets),'declaration environment not established')
        provenance = [LEXICAL_POLICY, unit.file, digest]
        if table:
            provenance.append(f"symtable:{table.get_type()}:{table.get_name()}:{table.get_lineno()}")
        elif unit.language == 'python' and kind == 'comprehension':
            # PEP 709 may inline eager comprehensions. Compiler table mapping
            # cannot then authenticate class lookup. Decline exactness rather
            # than reusing the enclosing class table. Simple function cases
            # can use the owning function's symbol classification, excluding
            # comprehension-local targets and walrus writes.
            p = parent
            if (unit.scope_constructs.get(syntactic) != 'class' and p in unit.compiler_tables and
                unit.scope_constructs.get(p) in {'function','lambda','module','comprehension'}):
                table = unit.compiler_tables[p]
                node = unit.scope_nodes[scope]
                if not any(isinstance(n, ast.NamedExpr) for n in ast.walk(node)):
                    unit.compiler_tables[scope] = table
                    state = S.SUPPORTED
                    provenance.append(f"symtable-inlined:{table.get_name()}:{table.get_lineno()}")
            if state == S.UNKNOWN:
                unit.semantic_gaps.add((unit.file, 'compiler lexical environment mapping incomplete: comprehension'))
        elif unit.language == 'python':
            unit.semantic_gaps.add((unit.file, 'compiler lexical environment mapping incomplete: ' + kind))
        owner = unit.execution_scopes.get(scope)
        regions = tuple(sorted(r.region_id for r in unit.regions.values() if r.lexical_scope == scope))
        unit.environments[scope] = LexicalEnvironment(scope, unit.language, kind, syntactic,
            parent, scope, owner.key if owner else '', regions, state, tuple(provenance))
        unit.compiler_provenance[scope] = tuple(provenance)


def _tree_nodes(root):
    yield root
    for child in root.named_children:yield from _tree_nodes(child)


def compiler_reference(unit, site, head, binding_scope):
    """Validate the environment used for the name against the compiler block.

    A free/global reference must not be rebound to a syntactically enclosing
    class, nor to a local declaration that the compiler says is global.
    """
    environment = unit.environments.get(site.lexical_scope)
    if not environment or environment.closure != S.SUPPORTED:return S.UNKNOWN, ()
    if unit.language != 'python':return S.SUPPORTED, environment.provenance
    table = unit.compiler_tables.get(site.lexical_scope)
    if table is None:return S.UNKNOWN, environment.provenance
    try: symbol = table.lookup(head)
    except KeyError:return S.UNKNOWN, environment.provenance
    local_names = unit.bindings.get(site.lexical_scope, {})
    if environment.construct_kind == 'comprehension' and head in local_names:
        # The bounded engine does not establish iteration-value identity.
        return S.UNKNOWN, environment.provenance
    global_name = symbol.is_global() and not symbol.is_local()
    if global_name and binding_scope != unit.module_key:return S.UNKNOWN, environment.provenance
    if (symbol.is_local() and environment.construct_kind != 'comprehension' and
            environment.construct_kind != 'module' and binding_scope != site.lexical_scope):
        return S.UNKNOWN, environment.provenance
    if symbol.is_free() and unit.scope_constructs.get(binding_scope) == 'class':
        return S.UNKNOWN, environment.provenance
    classification = 'GLOBAL' if global_name else 'FREE' if symbol.is_free() else 'LOCAL'
    return S.SUPPORTED, environment.provenance + (f"compiler-reference:{head}:{classification}",)
