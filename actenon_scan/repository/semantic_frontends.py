"""Syntax-to-semantic lowering. Resolution consumes these facts, not AST nodes.

The inventory is a bounded allowlist. An unfamiliar named parser node opens
closure; a newly introduced grammar node never inherits absence-of-writes proof.
"""
from __future__ import annotations

import ast
from actenon_scan.invocation_graph import CallableSymbol, stable_id
from actenon_scan.semantic_ir import (
    COMPLETENESS_FACETS, CompletenessCertificate, EvaluationMode as Mode,
    ExecutionRegion, SemanticState as State, TargetKind as TK,
    WriteCertainty as WC, WriteEvent, WriteOperation as WO,
)


PY_SUPPORTED = set("Module Expression Interactive FunctionDef AsyncFunctionDef Lambda ClassDef Return Delete Assign AnnAssign AugAssign For AsyncFor While If With AsyncWith Match Raise Try TryStar Assert Import ImportFrom Global Nonlocal Expr Pass Break Continue BoolOp NamedExpr BinOp UnaryOp IfExp Dict Set ListComp SetComp DictComp GeneratorExp Await Yield YieldFrom Compare Call FormattedValue JoinedStr Constant Attribute Subscript Starred Name List Tuple Slice comprehension ExceptHandler arguments arg keyword alias withitem match_case MatchValue MatchSingleton MatchSequence MatchMapping MatchClass MatchStar MatchAs MatchOr".split())
PY_NEUTRAL = set("Load Store Del And Or Add Sub Mult MatMult Div Mod Pow LShift RShift BitOr BitXor BitAnd FloorDiv Invert Not UAdd USub Eq NotEq Lt LtE Gt GtE Is IsNot In NotIn".split())
PY_SUPPORTED.difference_update({'Global','Nonlocal'})
TREE_SUPPORTED = set("program source_file expression_statement statement_block block return_statement throw_statement break_statement continue_statement empty_statement debugger_statement labeled_statement if_statement else_clause for_statement for_in_statement while_statement do_statement try_statement catch_clause finally_clause switch_statement switch_body switch_case switch_default select_statement communication_case default_case type_switch_statement type_case range_clause function_declaration function_expression arrow_function generator_function_declaration generator_function method_definition method_declaration func_literal class_declaration class class_body class_static_block public_field_definition field_definition variable_declaration lexical_declaration variable_declarator assignment_expression augmented_assignment_expression assignment_statement short_var_declaration update_expression unary_expression delete_expression var_declaration var_spec const_declaration const_spec type_declaration type_spec import_statement import_clause namespace_import named_imports import_specifier import_declaration import_spec import_spec_list export_statement export_clause export_specifier export_specifier_list required_parameter optional_parameter formal_parameters parameter_list parameter_declaration variadic_parameter_declaration rest_pattern object_pattern array_pattern pair_pattern assignment_pattern object_assignment_pattern parenthesized_expression parenthesized_pattern expression_list call_expression new_expression arguments argument_list argument binary_expression unary_expression ternary_expression conditional_expression sequence_expression member_expression subscript_expression selector_expression index_expression slice_expression await_expression yield_expression object object_literal array composite_literal literal_value keyed_element pair spread_element spread_element_pattern as_expression satisfies_expression type_assertion non_null_expression decorator computed_property_name receive_statement send_statement go_statement defer_statement inc_statement dec_statement assignment_statement package_clause interpreted_string_literal raw_string_literal string template_string template_substitution".split())
TREE_NEUTRAL = set("identifier property_identifier private_property_identifier shorthand_property_identifier shorthand_property_identifier_pattern type_identifier field_identifier package_identifier label_name number integer float int_literal float_literal imaginary_literal true false null undefined nil this super string_fragment escape_sequence comment hash_bang_line regex regex_pattern regex_flags automatic_semicolon semicolon statement_identifier property_signature method_signature type_annotation predefined_type primitive_type generic_type type_arguments type_parameters type_parameter constraint default_type required_parameter optional_parameter object_type function_type constructor_type array_type tuple_type union_type intersection_type literal_type type_query type_predicate type_predicate_annotation nested_type_identifier interface_declaration interface_body extends_type_clause implements_clause extends_clause class_heritage type_alias_declaration type_parameter_list qualified_type pointer_type slice_type map_type channel_type struct_type interface_type function_type type_elem field_declaration field_declaration_list embedded_field negated_type type_conversion_expression iota interpreted_string_literal_content raw_string_literal_content import_attribute import_attribute_specifier import_attributes meta_property accessibility_modifier override_modifier readonly_type rest_type optional_type lookup_type indexed_access_type parenthesized_type type_operator keyof_type infer_type mapped_type mapped_type_clause conditional_type index_signature property_name".split())
# These are deliberately not claimed complete: runtime extension, ambient
# merging, JSX activation and reflection require a different bounded model.
TREE_UNKNOWN = set("internal_module module enum_declaration enum_body enum_assignment with_statement jsx_element jsx_self_closing_element jsx_expression jsx_opening_element jsx_closing_element jsx_attribute jsx_namespace_name namespace_export export_namespace ambient_declaration import_require_clause".split())
TREE_SUPPORTED.add("statement_list")
TREE_SUPPORTED.discard("defer_statement")
TREE_UNKNOWN.add("defer_statement")
TREE_NEUTRAL.discard("class_heritage")
TREE_UNKNOWN.add("class_heritage")


def classify_node(language, name):
    supported, neutral = (PY_SUPPORTED, PY_NEUTRAL) if language == "python" else (TREE_SUPPORTED, TREE_NEUTRAL)
    if name in supported:
        return "SUPPORTED"
    if name in neutral:
        return "NOT_RELEVANT"
    return "CONSERVATIVELY_UNKNOWN"


def _children(unit, node):
    return list(ast.iter_child_nodes(node)) if unit.language == "python" else node.named_children


def _name(unit, node):
    return type(node).__name__ if unit.language == "python" else node.type


def _text(unit, node):
    if node is None:
        return ""
    return ast.unparse(node) if unit.language == "python" else unit.source.encode()[node.start_byte:node.end_byte].decode()


def _line(unit, node):
    return getattr(node, "lineno", 0) if unit.language == "python" else node.start_point[0] + 1


def call_operands(unit, node):
    """Normalized object captures; containers do not hide escaping identities."""
    if unit.language == 'python':
        roots = node.args + [k.value for k in node.keywords]
        def operands(value):
            if isinstance(value, ast.Lambda):
                key=next((k for k,n in unit.nodes.items() if n is value),None)
                return ['@callable:'+key] if key else []
            if isinstance(value, (ast.Name, ast.Attribute, ast.Subscript)):
                return [_text(unit, value)]
            if isinstance(value, (ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Starred)):
                return [name for child in ast.iter_child_nodes(value) for name in operands(child)]
            return []
    else:
        args = node.child_by_field_name('arguments')
        roots = args.named_children if args else []
        def operands(value):
            if value.type in {'function_expression','arrow_function','generator_function','func_literal'}:
                key=next((k for k,n in unit.nodes.items() if n==value),None)
                return ['@callable:'+key] if key else []
            if value.type in {'identifier','this','member_expression','selector_expression','subscript_expression'}:
                return [_text(unit, value)]
            if value.type in {'array','object','pair','spread_element','argument','keyed_element','literal_value','composite_literal','parenthesized_expression','as_expression'}:
                return [name for child in value.named_children for name in operands(child)]
            return []
    return tuple(sorted({name for value in roots for name in operands(value)}))


def callable_operands(unit,node):
    """Normalize captured callable/receiver identities, including computed reads.

    Whether these observations open closure is the common escape policy's
    decision. A callable alias is not erased just because its spelling is bare.
    """
    if unit.language=='python':
        # Invocation sites normally store the callee expression itself.
        function=node.func if isinstance(node,ast.Call) else node
        base=function.value if isinstance(function,(ast.Attribute,ast.Subscript)) else function
        return (_text(unit,base),)
    function=(node.child_by_field_name('function') or node.child_by_field_name('constructor')) if node.type in {'call_expression','new_expression'} else node
    if function is None:return ()
    base=function.child_by_field_name('object') or function.child_by_field_name('operand') or function
    return (_text(unit,base),)


def _open(unit, scope, facets, reason):
    unit.certificates[scope].open(facets, reason)
    unit.semantic_gaps.add((unit.file, reason))


def _event(unit, node, scope, operation, kind, *, binding="", base="", member="", possible=False):
    if kind == TK.MEMBER:
        head=base.split('.')[0]
        cursor=scope;seen=set();declarations=[]
        while cursor and cursor not in seen:
            seen.add(cursor)
            names=unit.bindings.get(cursor,{})
            if head in names:
                declarations=names[head];break
            cursor=unit.scope_parents.get(cursor,'')
        if any(b.kind in {'import','ts_import'} for b in declarations):
            kind=TK.NAMESPACE_MEMBER
        if len(declarations)!=1 or declarations[0].kind not in {'receiver','alias','import','ts_import','callable','self_callable'}:
            possible=True
    unit.write_events.append(WriteEvent(scope, kind, operation, binding, base, member,
        WC.POSSIBLE if possible else WC.EXACT, _line(unit, node), _name(unit, node)))


def lower_lvalue(unit, node, scope, operation):
    """One recursive grammar walker per frontend; RHS/keys are never lvalues."""
    if node is None:
        return
    if unit.language == "python":
        if isinstance(node, ast.Name):
            _event(unit, node, scope, operation, TK.LEXICAL_BINDING, binding=node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for child in node.elts:
                lower_lvalue(unit, child, scope, operation)
        elif isinstance(node, ast.Starred):
            lower_lvalue(unit, node.value, scope, operation)
        elif isinstance(node, (ast.Attribute, ast.Subscript)):
            member = node.attr if isinstance(node, ast.Attribute) else (
                node.slice.value if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str) else "*")
            _event(unit, node, scope, operation, TK.MEMBER, base=_text(unit, node.value), member=member, possible=member == "*")
        else:
            _event(unit, node, scope, WO.MAY_WRITE, TK.UNKNOWN_TARGET, possible=True)
            _open(unit, scope, ("lexical_writes_complete", "member_writes_complete"), "unsupported Python lvalue: " + _name(unit, node))
        return
    kind = node.type
    if kind in {"identifier", "shorthand_property_identifier_pattern"}:
        _event(unit, node, scope, operation, TK.LEXICAL_BINDING, binding=_text(unit, node))
    elif kind in {"member_expression", "subscript_expression", "selector_expression", "index_expression"}:
        base = node.child_by_field_name("object") or node.child_by_field_name("operand")
        prop = node.child_by_field_name("property") or node.child_by_field_name("field") or node.child_by_field_name("index")
        member = _text(unit, prop)
        if kind in {"subscript_expression", "index_expression"}:
            # Raw token spelling is not a decoded runtime property key. Escapes
            # and expression keys use a wildcard unless decoding is proved.
            member = member[1:-1] if prop and prop.type in {"string", "interpreted_string_literal"} and "\\" not in member else "*"
        _event(unit, node, scope, operation, TK.MEMBER, base=_text(unit, base), member=member, possible=member == "*")
    elif kind in {"pair_pattern", "pair", "assignment_pattern", "object_assignment_pattern"}:
        child = node.child_by_field_name("value") if kind in {"pair_pattern", "pair"} else node.child_by_field_name("left")
        lower_lvalue(unit, child, scope, operation)
    elif kind in {"array_pattern", "object_pattern", "array", "object", "rest_pattern", "spread_element", "spread_element_pattern", "expression_list", "parenthesized_expression", "parenthesized_pattern"}:
        for child in node.named_children:
            lower_lvalue(unit, child, scope, operation)
    else:
        _event(unit, node, scope, WO.MAY_WRITE, TK.UNKNOWN_TARGET, possible=True)
        _open(unit, scope, ("lexical_writes_complete", "member_writes_complete"), "unsupported lvalue: " + kind)


def literal_pattern_aliases(pattern, value, data, depth=0):
    """Exact aliases only from matching, non-sparse literal patterns.

    No getters, defaults, rests, spreads, computed keys or evaluated RHS values
    are admitted. Unsupported shapes return no positive evidence.
    """
    if not pattern or not value or depth >= 32:
        return {}
    text=lambda n:data[n.start_byte:n.end_byte].decode()
    if pattern.type in {"identifier", "shorthand_property_identifier_pattern"} and value.type == "identifier":
        return {text(pattern):text(value)}
    if pattern.type=='array_pattern' and value.type=='array':
        left,right=pattern.named_children,value.named_children
        # Commas without expressions are holes. Decline rather than shift slots.
        if any(n.type==',' for n in pattern.children) and text(pattern).count(',')!=max(0,len(left)-1):return {}
        if text(value).count(',')!=max(0,len(right)-1) or len(left)!=len(right):return {}
        result={}
        for a,b in zip(left,right):
            child=literal_pattern_aliases(a,b,data,depth+1)
            if not child or result.keys() & child.keys():return {}
            result.update(child)
        return result
    if pattern.type=='object_pattern' and value.type=='object':
        fields={}
        for pair in value.named_children:
            key=pair.child_by_field_name('key');val=pair.child_by_field_name('value')
            if pair.type!='pair' or not key or key.type not in {'property_identifier','identifier'} or text(key) in fields:return {}
            fields[text(key)]=val
        result={}
        for pair in pattern.named_children:
            if pair.type=='shorthand_property_identifier_pattern':key=pair;target=pair
            elif pair.type=='pair_pattern':key=pair.child_by_field_name('key');target=pair.child_by_field_name('value')
            else:return {}
            if not key or text(key) not in fields:return {}
            child=literal_pattern_aliases(target,fields[text(key)],data,depth+1)
            if not child or result.keys() & child.keys():return {}
            result.update(child)
        return result
    return {}


def lower_semantics(unit, make_site):
    """Seal only audited scopes; populate region and write IR before resolution."""
    scopes = set(unit.execution_scopes) | set(unit.bindings) | set(unit.scope_parents) | {unit.module_key}
    unit.certificates = {s: CompletenessCertificate(s, {f: State.SUPPORTED for f in COMPLETENESS_FACETS}) for s in scopes}
    unit.sites.clear()
    unit.regions.clear()
    unit.semantic_gaps.clear()
    # Declarations are semantic facts too. Candidate construction has already
    # emitted these; assignments are lowered below, independently of names.
    unit.write_events[:] = [e for e in unit.write_events if e.operation == WO.DECLARE or
                           e.syntax == "accumulated binding counter-evidence"]
    # Audit the *entire* parse tree independently of evaluation lowering.
    # Otherwise a new field underneath a handled definition/type/annotation
    # could be skipped by a specialized visitor and falsely inherit closure.
    pending = [(unit.tree, unit.module_key)]
    while pending:
        node, inherited = pending.pop()
        scope = unit.node_scopes.get(node, inherited)
        if scope not in unit.certificates:
            unit.certificates[scope] = CompletenessCertificate(scope)
        if classify_node(unit.language, _name(unit, node)) == "CONSERVATIVELY_UNKNOWN":
            _open(unit, scope, COMPLETENESS_FACETS, "unclassified semantic syntax: " + _name(unit, node))
        if unit.language == 'python' and isinstance(node, ast.ClassDef):
            custom_lookup=any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and
                              n.name in {'__getattribute__','__getattr__'} for n in node.body)
            if node.bases or node.keywords or custom_lookup:
                _open(unit,scope,('receiver_semantics_complete',),'class receiver dispatch outside bounded model')
        elif unit.language == 'typescript' and node.type == 'class_heritage':
            _open(unit,scope,('receiver_semantics_complete',),'class receiver dispatch outside bounded model')
        pending.extend((child, scope) for child in _children(unit, node))

    def region(node, scope, owner, mode, reason):
        # One evaluation region per lexical/execution owner and mode. Neutral
        # token coordinates (such as import spelling lengths) do not invent
        # separate regions or make candidate-order invariance unstable.
        identity = stable_id("region", unit.file, scope, owner.key, mode.value, reason)
        value = ExecutionRegion(identity, scope, owner.key, mode, reason,
                                State.UNKNOWN if mode == Mode.UNKNOWN else State.SUPPORTED)
        unit.regions[identity] = value
        return value

    def walk(node, inherited_scope, inherited_owner, mode=Mode.EAGER, reason="callable execution"):
        scope = unit.node_scopes.get(node, inherited_scope)
        owner = unit.execution_scopes.get(scope, inherited_owner)
        name = _name(unit, node)
        if scope not in unit.certificates:
            unit.certificates[scope] = CompletenessCertificate(scope)
        if classify_node(unit.language, name) == "CONSERVATIVELY_UNKNOWN":
            _open(unit, scope, COMPLETENESS_FACETS, "unclassified semantic syntax: " + name)
            mode = Mode.UNKNOWN
        if mode == Mode.UNKNOWN:
            # A lexical enclosing function is not proof that an unfamiliar
            # construct executes in that function. Keep a synthetic owner,
            # rather than attributing its call-shaped children to the root.
            line = _line(unit, node)
            owner = CallableSymbol(unit.language, unit.file,
                f"<unknown-region@{line}:{scope}>", line, 1)
            reason = "execution semantics not established"
        unit.node_regions[node] = region(node, scope, owner, mode, reason)
        if unit.language == "python":
            if isinstance(node, ast.GeneratorExp):
                # The outer iterable is eagerly evaluated; all computations
                # made by the iterator belong to a synthetic deferred owner.
                synthetic = CallableSymbol(unit.language, unit.file,
                    owner.symbol + f".<generator@{node.lineno}:{node.col_offset+1}>", node.lineno, node.col_offset+1)
                deferred_scope = synthetic.key
                unit.scope_parents[deferred_scope] = scope
                unit.execution_scopes[deferred_scope] = synthetic
                unit.certificates[deferred_scope] = CompletenessCertificate(deferred_scope, {f: State.SUPPORTED for f in COMPLETENESS_FACETS})
                walk(node.generators[0].iter, scope, owner, mode, reason)
                # Do not propagate the parent's AST-assigned owner into this
                # execution region; lexical lookup still uses the outer scope.
                deferred = [node.elt] + node.generators[0].ifs
                for generator in node.generators[1:]:
                    deferred += [generator.iter] + generator.ifs
                for child in deferred:
                    walk_deferred(child, scope, synthetic, "unconsumed generator computation")
                return
            if isinstance(node, ast.AnnAssign):
                annotation(node.annotation, scope, owner)
                if node.value:
                    walk(node.value, scope, owner, mode, reason)
                    lower_lvalue(unit, node.target, scope, WO.ASSIGN)
                return
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for expression in node.decorator_list + node.args.defaults + [v for v in node.args.kw_defaults if v]:
                    walk(expression, scope, owner, mode, reason)
                for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs + [v for v in (node.args.vararg, node.args.kwarg) if v]:
                    if arg.annotation:
                        annotation(arg.annotation, scope, owner)
                if node.returns:
                    annotation(node.returns, scope, owner)
                for child in node.body:
                    walk(child, scope, owner, mode, reason)
                return
            if isinstance(node, ast.Lambda):
                for expression in node.args.defaults + [v for v in node.args.kw_defaults if v]:
                    walk(expression, scope, owner, mode, reason)
                walk(node.body, scope, owner, mode, reason)
                return
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    lower_lvalue(unit, target, scope, WO.ASSIGN)
            elif isinstance(node, (ast.AugAssign, ast.NamedExpr)):
                lower_lvalue(unit, node.target, scope, WO.ASSIGN)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    lower_lvalue(unit, target, scope, WO.DELETE)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                lower_lvalue(unit, node.target, scope, WO.ASSIGN)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars:
                        lower_lvalue(unit, item.optional_vars, scope, WO.ASSIGN)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval", "setattr", "delattr", "globals", "locals", "vars"}:
                _open(unit, scope, ("lexical_writes_complete", "member_writes_complete"), "dynamic Python namespace operation")
            if isinstance(node, ast.Call) and mode != Mode.NON_RUNTIME:
                r = unit.node_regions[node]
                resumed = isinstance(getattr(node, "_semantic_parent", None), ast.Await)
                unit.sites.append(make_site(owner, node.lineno, node.col_offset+1, ast.unparse(node.func),
                    node.func, not isinstance(node.func, (ast.Name, ast.Attribute)), scope, resumed, r,
                    arguments=call_operands(unit, node)))
            for child in _children(unit, node):
                if isinstance(node, ast.Await) and isinstance(child, ast.Call):
                    child._semantic_parent = node
                walk(child, scope, owner, mode, reason)
        else:
            if name in {"type_annotation", "type_alias_declaration", "interface_declaration", "ambient_declaration"}:
                # No type syntax can inherit its enclosing runtime owner.
                for child in node.named_children:
                    walk_deferred(child, scope, owner, "non-runtime type syntax", Mode.NON_RUNTIME)
                return
            if name in {"assignment_expression", "augmented_assignment_expression", "assignment_statement", "update_expression", "inc_statement", "dec_statement"}:
                left = node.child_by_field_name("left") or node.child_by_field_name("argument")
                if left is None and name in {"inc_statement", "dec_statement"}:
                    left = next(iter(node.named_children), None)
                if left is None:
                    _event(unit,node,scope,WO.MAY_WRITE,TK.UNKNOWN_TARGET,possible=True)
                    _open(unit,scope,("lexical_writes_complete","member_writes_complete"),"unmodeled assignment target layout")
                else:
                    lower_lvalue(unit, left, scope, WO.ASSIGN)
            elif name in {"range_clause", "receive_statement", "short_var_declaration"}:
                left = node.child_by_field_name("left")
                short = any(c.type == ":=" for c in node.children)
                before = len(unit.write_events)
                lower_lvalue(unit, left, scope, WO.DECLARE if short else WO.ASSIGN)
                if short:
                    from dataclasses import replace
                    if unit.language == 'go':
                        cursor=node.parent
                        while cursor and cursor.type not in {'function_declaration','method_declaration','func_literal'}:
                            if cursor.type in {'for_statement','if_statement','type_switch_statement','communication_case'} or (
                                    cursor.type=='block' and cursor.parent and cursor.parent.type not in
                                    {'function_declaration','method_declaration','func_literal'}):
                                _open(unit,scope,('lexical_writes_complete',),'Go block short-declaration scope summarized')
                                break
                            cursor=cursor.parent
                    for i in range(before, len(unit.write_events)):
                        event = unit.write_events[i]
                        declarations = unit.bindings.get(scope, {}).get(event.binding, [])
                        # Repeated names in the same block are assignments;
                        # the remaining names introduce new bindings. Block
                        # summaries can over-downgrade, never prove stability.
                        column = node.start_point[1] + 1
                        prior = [b for b in declarations if b.line == 0 or
                                 (b.line, b.column) < (event.line, column)]
                        if prior:
                            unit.write_events[i] = replace(event, operation=WO.ASSIGN)
            elif name in {"unary_expression", "delete_expression"} and any(c.type == "delete" for c in node.children):
                target = node.child_by_field_name("argument") or next(iter(node.named_children), None)
                lower_lvalue(unit, target, scope, WO.DELETE)
            elif name == "for_in_statement":
                left = node.child_by_field_name("left")
                declaration = any(c.type in {"let", "const", "var"} for c in node.children)
                lower_lvalue(unit, left, scope, WO.DECLARE if declaration else WO.ASSIGN)
            elif name == "call_expression":
                function = node.child_by_field_name("function")
                spelling = _text(unit, function)
                if spelling in {"eval", "Object.assign", "Object.defineProperty", "Object.defineProperties", "Object.setPrototypeOf", "Reflect.set", "Reflect.deleteProperty", "Reflect.defineProperty", "Reflect.setPrototypeOf"}:
                    _open(unit, scope, ("lexical_writes_complete", "member_writes_complete"), "dynamic JavaScript namespace operation")
            if name in {"call_expression", "new_expression"} and mode != Mode.NON_RUNTIME:
                callee = node.child_by_field_name("function") or node.child_by_field_name("constructor")
                if callee:
                    spelling = _text(unit, callee)
                    unit.sites.append(make_site(owner, node.start_point[0]+1, node.start_point[1]+1,
                        spelling, callee, any(c in spelling for c in "[]()?"), scope, False, unit.node_regions[node],
                        arguments=call_operands(unit, node)))
            for child in node.named_children:
                walk(child, scope, owner, mode, reason)

    def walk_deferred(node, lexical, owner, reason, mode=Mode.DEFERRED):
        # A deferred expression gets independent execution identity, even though
        # its names may be looked up through the enclosing lexical environment.
        value = region(node, lexical, owner, mode, reason)
        unit.node_regions[node] = value
        name = _name(unit, node)
        if classify_node(unit.language, name) == "CONSERVATIVELY_UNKNOWN":
            _open(unit, lexical, COMPLETENESS_FACETS, "unclassified deferred syntax: " + name)
        if mode != Mode.NON_RUNTIME and ((unit.language == "python" and isinstance(node, ast.Call)) or
                (unit.language != "python" and name in {"call_expression", "new_expression"})):
            callee = node.func if unit.language == "python" else node.child_by_field_name("function") or node.child_by_field_name("constructor")
            line = _line(unit, node)
            column = node.col_offset+1 if unit.language == "python" else node.start_point[1]+1
            if callee:
                unit.sites.append(make_site(owner, line, column, _text(unit, callee), callee, True, lexical, False, value))
        for child in _children(unit, node):
            walk_deferred(child, unit.node_scopes.get(child, lexical), owner, reason, mode)

    def annotation(node, scope, owner):
        # Local annotations are never evaluated. Other annotation semantics vary
        # by future flags and Python version; no historical eager claim is made.
        future = any(isinstance(n, ast.ImportFrom) and n.module == "__future__" and
                     any(a.name == "annotations" for a in n.names) for n in unit.tree.body)
        local = isinstance(unit.nodes.get(scope), (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        mode = Mode.NON_RUNTIME if local or future else Mode.UNKNOWN
        synthetic = CallableSymbol(unit.language, unit.file,
            owner.symbol + f".<annotation@{node.lineno}:{node.col_offset+1}>", node.lineno, node.col_offset+1)
        if mode == Mode.UNKNOWN:
            unit.semantic_gaps.add((unit.file, "annotation runtime evaluation outside bounded model"))
        walk_deferred(node, scope, synthetic, "annotation evaluation not established", mode)

    walk(unit.tree, unit.module_key, unit.execution_scopes[unit.module_key])
    # A handled syntax form may skip metadata fields intentionally. Every
    # remaining call-shaped node still receives an explicit unknown region;
    # it cannot silently inherit an eager enclosing owner.
    pending=[unit.tree]
    while pending:
        node=pending.pop()
        name=_name(unit,node)
        is_call=isinstance(node,ast.Call) if unit.language=='python' else name in {'call_expression','new_expression'}
        if is_call and node not in unit.node_regions:
            scope=unit.node_scopes.get(node,unit.module_key)
            line=_line(unit,node)
            synthetic=CallableSymbol(unit.language,unit.file,f'<unsupported@{line}>',line,1)
            unit.node_regions[node]=region(node,scope,synthetic,Mode.UNKNOWN,'unlowered invocation syntax')
            unit.semantic_gaps.add((unit.file,'unlowered invocation syntax'))
        pending.extend(_children(unit,node))
