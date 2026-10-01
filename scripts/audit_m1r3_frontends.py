"""Record every installed grammar node; unlisted syntax defaults UNKNOWN."""
from __future__ import annotations
import ast
import json
import sys
from importlib.metadata import version
from pathlib import Path
from tree_sitter import Language
import tree_sitter_go
import tree_sitter_typescript
from actenon_scan.repository.semantic_frontends import classify_node


def inventory():
    languages = {}
    python = {}
    for name, value in vars(ast).items():
        if isinstance(value, type) and issubclass(value, ast.AST):
            abstract = name in {"AST", "mod", "stmt", "expr", "expr_context", "boolop", "operator",
                "unaryop", "cmpop", "excepthandler", "pattern", "type_param"}
            python[name] = {"classification": "NOT_RELEVANT" if abstract else classify_node("python", name),
                "fields": list(value._fields), "abstract": abstract}
    languages['python'] = {"parser": "stdlib ast", "version": sys.version.split()[0],
                           "nodes": dict(sorted(python.items()))}
    for name, grammar in [('typescript',tree_sitter_typescript.language_typescript()),
                          ('tsx',tree_sitter_typescript.language_tsx()),('go',tree_sitter_go.language())]:
        language=Language(grammar)
        nodes={}
        for i in range(language.node_kind_count):
            kind=language.node_kind_for_id(i)
            classification=classify_node(name,kind) if language.node_kind_is_named(i) else 'NOT_RELEVANT'
            nodes[kind]={'classification':classification,'named':language.node_kind_is_named(i)}
        languages[name]={'parser':'tree-sitter','abi':language.abi_version,'nodes':dict(sorted(nodes.items()))}
    return {'model':'bounded syntactic execution/write/import/receiver closure; no dependency semantics',
        'unknown_default':'CONSERVATIVELY_UNKNOWN; opens closure and discloses coverage limitation',
        'parser_versions':{p:version(p) for p in ['tree-sitter','tree-sitter-typescript','tree-sitter-go']},
        'families':{
            'execution_regions':['callable bodies','class definitions/initializers','default/decorator expressions','type/annotation metadata'],
            'delayed_execution':['generators','generator expressions','lambdas','async callable bodies','uninvoked callback bodies'],
            'binding_declarations':['parameters','function/class names','imports','variable/pattern declarations','Go short declarations'],
            'binding_writes':['assignments','augmented updates','destructuring','loop/range targets','receive targets','global/nonlocal'],
            'member_writes':['member/subscript lvalues','recursive patterns','computed targets','receiver/module aliases'],
            'deletion':['Python Delete','JavaScript delete'],
            'aliases':['identifier initializers','import/re-export paths','receiver captures'],
        },'languages':languages,'unclassified_relevant_node_types':0}


if __name__=='__main__':
    target=Path('research/M1R3/frontend-coverage.json');target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(inventory(),indent=2,sort_keys=True)+'\n')
