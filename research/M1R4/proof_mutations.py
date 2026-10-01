"""Count mutations of genuine issued proofs; all outputs stay outside source."""
from pathlib import Path
import argparse,json,sys,tempfile

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tests'))
    from test_m1r4_kernel import POSITIVES,run,mutations,inventory_mutations
    from actenon_scan import reachability_kernel as K
    from unittest.mock import patch
    from actenon_scan.binding_claims import BindingState
    from dataclasses import replace
    rows=[];inventory_rows=[]
    with tempfile.TemporaryDirectory(prefix='m1r4-proof-') as directory:
        for index,case in enumerate(POSITIVES):
            folder=Path(directory)/str(index);folder.mkdir()
            captured=[];original=K.evaluate
            def record(**kw):
                captured.append(kw)
                return original(**kw)
            with patch.object(K,'evaluate',record):_,binding=run(folder,case)
            proof=binding.edge_proof
            assert proof.authorizes(binding.subject,binding.candidate_id,binding.positive_evidence)
            for name,damaged in mutations(proof):
                accepted=damaged.authorizes(binding.subject,binding.candidate_id,binding.positive_evidence)
                established=replace(binding,edge_proof=damaged).state==BindingState.ESTABLISHED
                rows.append({'positive':case[0],'mutation':name,'accepted':accepted,'established':established})
            arguments=next(k for k in captured if k['context'].subject==binding.subject and k['context'].candidate==binding.candidate_id)
            for name,inventory in inventory_mutations(arguments['inventory']):
                p=original(**{**arguments,'inventory':inventory})
                inventory_rows.append({'positive':case[0],'mutation':name,
                    'accepted':p.authorizes(binding.subject,binding.candidate_id,binding.positive_evidence)})
    summary={'positives':len(POSITIVES),'mutation_cases':len(rows),
             'forged_or_partial_accepted':sum(r['accepted'] or r['established'] for r in rows),
             'inventory_mutation_cases':len(inventory_rows),'inventory_mutations_accepted':sum(r['accepted'] for r in inventory_rows),
             'cases':rows,'inventory_cases':inventory_rows}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in {'cases','inventory_cases'}},indent=2))
    assert summary['forged_or_partial_accepted']==summary['inventory_mutations_accepted']==0

if __name__=='__main__':main()
