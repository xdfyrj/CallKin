"""Post-prediction evaluation using the frozen linkage pair-label rules."""
import argparse
from collections import Counter, defaultdict
from itertools import combinations
from math import comb
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from linkage_overlay import label_pair, load_overlay, POSITIVE, NEGATIVE
from run_followup import read, dump, input_path
from prepare import sha


def truth_index(ids, audit):
    origins, identities = load_overlay(audit)
    valid = [i for i in ids if origins.get(i) and identities.get(i)]
    clean = [i for i in valid if len(set(origins[i])) == 1]
    groups = defaultdict(list)
    for i in clean:
        groups[origins[i][0]].append(i)
    positive = set()
    per_origin = {}
    duplicates = 0
    within = 0
    for origin, members in groups.items():
        pairs = set()
        within += comb(len(members), 2)
        for pair in combinations(sorted(members), 2):
            kind = label_pair(*pair, origins_by_address=origins, identities_by_address=identities)
            if kind == POSITIVE:
                pairs.add(pair)
            else:
                assert kind == 'duplicate-neutral', kind
                duplicates += 1
        positive.update(pairs)
        per_origin[origin] = pairs
    neutral = {'unresolved-neutral': comb(len(ids),2) - comb(len(valid),2),
               'ambiguous-neutral': comb(len(valid),2) - comb(len(clean),2),
               'duplicate-neutral': duplicates}
    negative = comb(len(clean),2) - within
    assert len(positive)+negative+sum(neutral.values()) == comb(len(ids),2)
    return origins, identities, positive, per_origin, negative, neutral


def metrics(prediction, gt, audit, eligible=None, candidate_pairs=None):
    ids = prediction['universe']['target_ids']
    target = set(ids)
    assert len(target) == len(ids)
    origins, identities, positive, origin_pairs, negatives, neutral = truth_index(ids, audit)
    groups = [set(g['members']) for g in prediction['clusters'] if g['status']=='accepted']
    used = set()
    predicted = set()
    for group in groups:
        assert group <= target and not group & used
        used.update(group)
        predicted.update(combinations(sorted(group),2))
    tp = len(predicted & positive)
    fp = sum(label_pair(*p, origins_by_address=origins, identities_by_address=identities)==NEGATIVE
             for p in predicted)
    fn, tn = len(positive)-tp, negatives-fp
    ground_groups = {g['origin']:set(g['members']) & target for g in gt['origins']}
    per_origin = []
    for origin,pairs in sorted(origin_pairs.items()):
        if not pairs:
            continue
        hits = len(pairs & predicted)
        members = ground_groups.get(origin, set())
        per_origin.append({'origin':origin,'positive_pairs':len(pairs),'recovered_pairs':hits,
            'recall':hits/len(pairs),'target_members':len(members),
            'exact_group': bool(members) and any(g == members for g in groups)})
    result = {'target_count':len(ids),'TP':tp,'FP':fp,'FN':fn,'TN':tn,
              'precision':tp/(tp+fp) if tp+fp else None,
              'recall':tp/(tp+fn) if tp+fn else None,
              'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
              'neutral_pairs':neutral,'positive_pairs':len(positive),
              'scored_pairs':len(positive)+negatives,'per_origin':per_origin,
              'macro_origin_recall':sum(x['recall'] for x in per_origin)/len(per_origin) if per_origin else None,
              'exact_group_rate':sum(x['exact_group'] for x in per_origin)/len(per_origin) if per_origin else None}
    if 'pair_decisions' in prediction:
        decisions = {tuple(x['pair']):x for x in prediction['pair_decisions']}
        budget_pairs=set()
        for block in prediction.get('blocked_merges',[]):
            if block['reason']=='comparison_budget':
                for a in block['left_members']:
                    for b in block['right_members']:
                        p=tuple(sorted((a,b)))
                        if p in positive and p not in decisions:
                            budget_pairs.add(p)
        losses=Counter()
        for p in positive:
            if p in predicted:
                reason='recovered'
            elif eligible is not None and not set(p)<=eligible:
                reason='observation_ineligible'
            elif p in budget_pairs:
                reason='comparison_budget'
            elif p not in decisions:
                reason='not_retrieved_or_requested'
            else:
                entry=decisions[p]
                if entry['decision']=='abstain':
                    reason='observation_ineligible'
                elif entry['decision']=='match':
                    reason='complete_link_not_retained'
                elif entry['features']['structure_score'] < .95:
                    reason='structure_failed'
                else:
                    reason='slot_policy_failed'
            losses[reason]+=1
        assert sum(losses.values())==len(positive) and losses['recovered']==tp
        result['positive_first_outcome']=dict(sorted(losses.items()))
        result['on_demand_positive_compared']=sum(p in positive and e['source']=='on-demand' for p,e in decisions.items())
        result['comparison_cost']=prediction['metrics']
    if candidate_pairs is not None:
        result['candidate_positive_pairs']=len(candidate_pairs & positive)
        result['candidate_positive_recall']=len(candidate_pairs & positive)/len(positive) if positive else None
    assert tp+fp+fn+tn==result['scored_pairs']
    return result


def score(case):
    manifest=read(HERE/'inputs.json');root=Path(manifest['input_root'])
    # These files are opened only by this evaluation command, after inference.
    gt=read(input_path(manifest,case,'ground_truth',root))
    audit=read(input_path(manifest,case,'linkage',root))
    sample=read(HERE/'audit-sample.json')
    retrieval=read(HERE/'cache'/case/'retrieval.json')
    eligible=set(retrieval['eligible_ids'])
    records=[]
    for path in sorted((HERE/'runs'/case).glob('*/metadata.json')):
        metadata=read(path)
        assert metadata['input_manifest_sha256']==sha(HERE/'inputs.json')
        assert metadata['config_sha256']==sha(HERE/'config.json')
        output={'case':case,'name':path.parent.name,'metadata':metadata,
                'evaluator_sha256':sha(Path(__file__))}
        candidate_path=HERE/'cache'/case/(path.parent.name+'.candidates.json')
        candidates=read(candidate_path) if candidate_path.exists() else None
        if candidates and 'candidate_sha256' in metadata:
            assert sha(candidate_path)==metadata['candidate_sha256']
        if metadata['status']=='completed':
            pred_path=path.parent/'prediction.json'
            assert sha(pred_path)==metadata['prediction_sha256']
            pred=read(pred_path)
            output['metrics']=metrics(pred,gt,audit,eligible,
                {tuple(p['pair']) for p in candidates['pairs']} if candidates else None)
            for stratum in ['random','purposeful']:
                selected={r['origin'] for r in sample if r['case']==case and r['stratum']==stratum}
                rows=[r for r in output['metrics']['per_origin'] if r['origin'] in selected]
                output['metrics']['audit_'+stratum]={'sampled_groups':len(selected),'positive_groups':len(rows),
                    'macro_origin_recall':sum(r['recall'] for r in rows)/len(rows) if rows else None}
        else:
            output['metrics']=None
            if candidates:
                _,_,positive,_,_,_=truth_index(candidates['universe']['target_ids'],audit)
                hit=len(positive & {tuple(p['pair']) for p in candidates['pairs']})
                output['retrieval_only']={'positive_pairs':len(positive),'candidate_positive_pairs':hit,
                                          'candidate_recall':hit/len(positive) if positive else None}
        dump(path.parent/'evaluation.json',output)
        records.append(output)
        m=output.get('metrics') or {}
        print(case,path.parent.name,metadata['status'],{k:m.get(k) for k in ['TP','FP','FN','f1']},flush=True)
    dump(HERE/(case+'-results.json'),records)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',required=True)
    score(p.parse_args().case)
