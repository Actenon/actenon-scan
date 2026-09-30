"""Re-run unchanged legacy tests at each local historical checkpoint; no network."""
from __future__ import annotations
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[2]
HISTORY=[('baseline','b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16'),
         ('failed_M0','a93b013383ce773b10708d3f30b2a1660e141527'),
         ('M0R1','ec4db0c2ab61c6d5b1c5d8537a9617f2d2534b30')]
results={}
for name,sha in HISTORY:
    with tempfile.TemporaryDirectory(prefix='m0r1b-'+name+'-') as directory:
        snapshot=Path(directory)/'snapshot';snapshot.mkdir()
        archive=subprocess.run(['git','archive','--format=zip',sha],cwd=ROOT,check=True,capture_output=True).stdout
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:zipped.extractall(snapshot)
        run=subprocess.run([sys.executable,'-B','-m','pytest','tests','--ignore=tests/effect_claims',
                            '-q','-p','no:cacheprovider','--basetemp',str(Path(directory)/'pytest')],
            cwd=snapshot,env={**os.environ,'PYTHONPATH':str(snapshot),'PYTHONDONTWRITEBYTECODE':'1'},
            capture_output=True,text=True)
        (ROOT/'research/M0R1-B'/('legacy_'+name+'.log')).write_text(run.stdout+run.stderr)
        results[name]={'sha':sha,'returncode':run.returncode,'summary':next((x for x in reversed(run.stdout.splitlines()) if 'passed' in x),'')}
        print(name,results[name],flush=True)
(ROOT/'research/M0R1-B/legacy_comparison.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(any(r['returncode'] for r in results.values()))
