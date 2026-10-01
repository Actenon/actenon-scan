"""Permanent source regressions for the latest independent proof attacks."""
from pathlib import Path
from dataclasses import replace
import json
import pytest
from actenon_scan import Entrypoint,RootKind,scan_effect_claims
from actenon_scan.semantic_ir import BASE_OBLIGATIONS

CASES=json.loads((Path(__file__).parents[1]/'research/M1R4/review-falsifiers.json').read_text())
@pytest.mark.parametrize('case',CASES,ids=lambda c:c['name'])
def test_review_runtime_impossible_body_not_reached(tmp_path,case):
 for file,source in case['files'].items():(tmp_path/file).write_text(source)
 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint(case['file'],case['entrypoint'],RootKind(case['root_kind']))],discover_roots=False)
 assert not r.analysis_errors
 assert r.graph.invocations and r.claims
 assert all(c.root_ids for c in r.graph.invocations.values())
 assert not any(c.callee_spelling=='old_probe.signal' for c in r.graph.invocations.values())

@pytest.mark.parametrize('language,kind',[('python','method'),('python','import'),('typescript','method'),('typescript','import')])
def test_partial_contextual_proof_does_not_authorize(tmp_path,language,kind):
 if language=='python':
  file='app.py';symbol='Unit.entry' if kind=='method' else 'entry'
  source='class Unit:\n    def worker(self):\n        marker.signal()\n    def entry(self):\n        self.worker()' if kind=='method' else 'from dep import worker\ndef entry():\n    worker()'
  if kind=='import':(tmp_path/'dep.py').write_text('def worker():\n    marker.signal()')
 else:
  file='app.ts';symbol='Unit.entry' if kind=='method' else 'entry'
  source='class Unit{worker(){marker.signal()}entry(){this.worker()}}' if kind=='method' else 'import {worker} from "./dep";function entry(){worker()}'
  if kind=='import':(tmp_path/'dep.ts').write_text('export function worker(){marker.signal()}')
 (tmp_path/file).write_text(source)
 r=scan_effect_claims(tmp_path,entrypoints=[Entrypoint(file,symbol)],discover_roots=False)
 node=next(c for c in r.graph.invocations.values() if c.established_targets)
 claim=node.binding_claims[0];extra=claim.edge_proof.required-BASE_OBLIGATIONS
 partial=replace(claim.edge_proof,required=BASE_OBLIGATIONS,facts=tuple((k,v) for k,v in claim.edge_proof.facts if k not in extra))
 node.binding_claims=(replace(claim,edge_proof=partial),)
 assert not node.established_targets
