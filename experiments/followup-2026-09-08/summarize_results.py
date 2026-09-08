"""Produce tables from completed evaluations; never treat missing runs as zero."""
import csv
import json
from collections import Counter
from pathlib import Path

HERE=Path(__file__).resolve().parent
from score_followup import truth_index
from run_followup import input_path


def read(p):return json.loads(p.read_text())


def summarize():
    config=read(HERE/'config.json');rows=[];details={}
    manifest=read(HERE/'inputs.json');input_root=Path(manifest['input_root'])
    for case in config['cases']:
        path=HERE/(case+'-results.json')
        if not path.exists():continue
        for item in read(path):
            m=item.get('metrics') or {};meta=item['metadata'];cost=m.get('comparison_cost') or {}
            row={'case':case,'method':item['name'],'status':meta['status'],
                 **{k:m.get(k) for k in ('TP','FP','FN','TN','precision','recall','f1','macro_origin_recall','exact_group_rate')},
                 'comparisons':cost.get('total_detailed_comparisons'),
                 'alignment_cells':cost.get('total_alignment_cells'),
                 'wall_seconds':meta.get('wall_seconds'),'max_rss_kib':meta.get('max_rss')}
            rows.append(row)
            if meta['status']=='completed' and item['name'].startswith(('body2-','combined3-')):
                pred=read(HERE/'runs'/case/item['name']/'prediction.json')
                audit=read(input_path(manifest,case,'linkage',input_root))
                positives=truth_index(pred['universe']['target_ids'],audit)[2]
                counts=Counter();positive_counts=Counter()
                for decision in pred['pair_decisions']:
                    f=decision['features']
                    if decision['decision']=='unknown' and f['structure_score']>=.95:
                        constant,data=f['constant_similarity'],f['data_reference_similarity']
                        if constant is None and data is None:reason='no_informative_channel'
                        elif constant is not None and constant<1 and data is not None and data<1:reason='both_channels_differ'
                        elif constant is not None and constant<1:reason='constant_channel_differs'
                        else:reason='data_channel_differs'
                        counts[reason]+=1
                        if tuple(decision['pair']) in positives:positive_counts[reason]+=1
                assert sum(positive_counts.values())==m['positive_first_outcome'].get('slot_policy_failed',0)
                details[case+'/'+item['name']]={
                    'positive_first_outcome':m['positive_first_outcome'],
                    'slot_failure_all_compared_pairs':dict(counts),
                    'slot_failure_positive_pairs':dict(positive_counts),
                    'note':'slot counts include positive and negative pairs; the separate first-outcome table uses only non-neutral positives',
                }
    if not rows:return
    with (HERE/'results-summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator="\n");w.writeheader();w.writerows(rows)
    (HERE/'stage-details.json').write_text(json.dumps(details,indent=2)+'\n')
    text=['# Results tables','', 'Original retained GT; source-correction sensitivity is in audit-sensitivity.json.',
          'Cases are previously exposed development data. NA denotes a non-completed inference, not zero accuracy.',
          'Timing is a single observation with up to two concurrent cases; shared retrieval preparation is reported separately.','',
          '| Case | Method | Status | TP | FP | FN | P | R | F1 | Macro R | Exact group |',
          '|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    def fmt(v):return 'NA' if v is None else f'{v:.4f}' if isinstance(v,float) else str(v)
    for r in rows:text.append('| '+' | '.join(fmt(r[k]) for k in ('case','method','status','TP','FP','FN','precision','recall','f1','macro_origin_recall','exact_group_rate'))+' |')
    (HERE/'results-tables.md').write_text('\n'.join(text)+'\n')
    print('Summarized',len(rows),'available evaluations.')


if __name__=='__main__':summarize()
