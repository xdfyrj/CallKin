"""Apply two source-grounded closure splits to copies, then rescore frozen predictions."""
import copy
import json
from itertools import combinations
from pathlib import Path

from run_followup import read, dump, input_path
from score_followup import metrics, truth_index
from prepare import sha

HERE=Path(__file__).resolve().parent
SITES={
 'zoxide':('zoxide::import::autojump::Iter<R>::parse_line::{{closure}}',
           'src/import/autojump.rs',{'FUN_00191360':42,'FUN_00191460':48,'FUN_001915a0':45}),
 'fd':('fd::walk::WorkerState::build_overrides::{{closure}}',
       'src/walk.rs',{'FUN_0027a400':339,'FUN_0027a470':344}),
}
FIELDS=('TP','FP','FN','TN','precision','recall','f1','positive_pairs','scored_pairs',
        'macro_origin_recall','exact_group_rate')


def sensitivity():
    manifest=read(HERE/'inputs.json');root=Path(manifest['input_root'])
    verification=read(HERE/'closure-site-check.json')
    output={}
    for case,(old_origin,source,sites) in SITES.items():
        gt_path=input_path(manifest,case,'ground_truth',root)
        linkage_path=input_path(manifest,case,'linkage',root)
        gt,audit=read(gt_path),read(linkage_path)
        matching=[g for g in gt['origins'] if g['origin']==old_origin]
        if len(matching)!=1 or set(matching[0]['members'])!=set(sites):
            raise ValueError('correction no longer matches the frozen origin group')
        checked={r['member']:r for r in verification[case]['members']}
        if set(checked)!=set(sites):raise ValueError('missing binary-to-source evidence')
        newgt,newaudit=copy.deepcopy(gt),copy.deepcopy(audit)
        newgt['origins']=[g for g in newgt['origins'] if g['origin']!=old_origin]
        overrides=[]
        for fid,line in sites.items():
            if checked[fid]['source_line']!=line:raise ValueError('source site mismatch')
            label=f'{old_origin}@{source}:{line}'
            if newaudit['addresses'][fid]['origins']!=[old_origin]:
                raise ValueError('ambiguous origin requires separate adjudication')
            newaudit['addresses'][fid]['origins']=[label]
            newgt['origins'].append({'origin':label,'members':[fid]})
            overrides.append({'member':fid,'old_origin':old_origin,'new_origin':label,
                              'source':source,'line':line,'evidence':checked[fid]})
        # Keep only the address mapping used by the evaluator; stale old group summaries are not copied.
        newaudit={'addresses':newaudit['addresses'],'provenance':{'parent_sha256':sha(linkage_path)},
                  'manual_source_site_overrides':overrides}
        newgt['manual_source_site_overrides']=overrides
        newgt['parent_ground_truth_sha256']=sha(gt_path)
        dump(HERE/'audit-corrections'/f'{case}.gt.v1.json',newgt)
        dump(HERE/'audit-corrections'/f'{case}.linkage.v1.json',newaudit)
        rows=[]
        for metadata_path in sorted((HERE/'runs'/case).glob('*/metadata.json')):
            meta=read(metadata_path)
            if meta['status']!='completed':continue
            pred_path=metadata_path.parent/'prediction.json'
            if sha(pred_path)!=meta['prediction_sha256']:raise ValueError('prediction hash mismatch')
            pred=read(pred_path)
            original=metrics(pred,gt,audit)
            corrected=metrics(pred,newgt,newaudit)
            if corrected['positive_pairs']!=original['positive_pairs']-len(list(combinations(sites,2))):
                raise ValueError('unexpected positive denominator change')
            if corrected['scored_pairs']!=original['scored_pairs']:
                raise ValueError('a closure split must not change scored universe')
            rows.append({'method':metadata_path.parent.name,'prediction_sha256':sha(pred_path),
                'original':{k:original[k] for k in FIELDS},'corrected':{k:corrected[k] for k in FIELDS},
                'old_positive_origin_count':len(original['per_origin']),
                'new_positive_origin_count':len(corrected['per_origin'])})
        output[case]={'overrides':overrides,'rows':rows}
        print(case, len(sites),'source sites,',len(rows),'completed predictions rescored',flush=True)
    dump(HERE/'audit-sensitivity.json',output)


if __name__=='__main__':sensitivity()
