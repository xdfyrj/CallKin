"""Small adversarial checks for named-view ablation, neutral counts and costs."""
import sys
from pathlib import Path
from itertools import combinations

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'tests'))
sys.path.insert(0,str(ROOT))
from test_v1_engine import _body
from v1_candidates import generate_multiview_candidate_pairs, build_multiview_candidate_artifact
from v1_engine import PairPolicyConfig, build_family_artifact
from linkage_overlay import score_labeled_pairs
from run_followup import derive
from score_followup import metrics, truth_index


def artifact(bodies,k,views,context):
    return build_multiview_candidate_artifact(case='toy',build='O3S',profile='plain',scope='subject',
        bodies=bodies,top_k=k,views=views,provenance={},
        pairs=generate_multiview_candidate_pairs(bodies,top_k=k,views=views,**context))


def test_prefix_and_named_intersection():
    bodies={f'FUN_{i:08x}':_body(f'FUN_{i:08x}',constant=i%7) for i in range(40)}
    ids=sorted(bodies)
    context={'final_groups':[ids[:15],ids[15:]],'prior_round_groups':[(0,[ids])],
             'out_signatures':{i:((ids[(n+1)%40],1),) for n,i in enumerate(ids)}}
    base=artifact(bodies,32,('token','cfg','relation'),context)
    for k in [8,16,32]:
        for views in [('token','cfg'),('token','cfg','relation')]:
            expected=artifact(bodies,k,views,context if 'relation' in views else {})
            expected=derive(expected,k,views)
            actual=derive(base,k,views)
            def signature(d):
                return {tuple(p['pair']):p['views'] for p in d['pairs']}
            assert signature(actual)==signature(expected)
        body=derive(base,k,('token','cfg'))
        combined=derive(base,k,('token','cfg','relation'))
        assert {tuple(p['pair']) for p in combined['pairs']} <= {tuple(p['pair']) for p in body['pairs']}
        assert all(p['same_final_color'] is None for p in body['pairs'])
    # Any2-of3 is not the body-only token&CFG intersection.
    example=dict(base)
    pair=dict(base['pairs'][0]); pair['views']={'token':{'rank':1,'score':1.},'cfg':None,'relation':{'rank':1,'score':1.}}
    pair['reasons']=['token_top_k','relation_top_k'];example['pairs']=[pair]
    assert derive(example,8,('token','cfg'))['pairs']==[]
    assert len(derive(example,8,('token','cfg','relation'),minimum=2)['pairs'])==1


def test_neutral_denominators_match_existing_evaluator():
    ids=list('ABCDEFGH')
    origins={'A':['f'],'B':['f'],'C':['f'],'D':['g'],'E':['f','g'],'F':['f'],'G':['g'],'H':['f']}
    identities={'A':['i1'],'B':['i2'],'C':['i1'],'D':['j'],'E':['e'],'F':[],'G':[],'H':['i3']}
    audit={'addresses':{i:{'origins':origins[i],'identities':identities[i]} for i in ids}}
    gt={'origins':[{'origin':'f','members':list('ABCH')},{'origin':'g','members':['D']} ]}
    pred={'universe':{'target_ids':ids},'clusters':[{'status':'accepted','members':list('ABE')},{'status':'accepted','members':list('CD')}]}
    got=metrics(pred,gt,audit)
    expected=score_labeled_pairs(combinations(ids,2),[('A','B'),('A','E'),('B','E'),('C','D')],
        origins_by_address=origins,identities_by_address=identities)['primary']
    for key in ('TP','FP','FN','TN'):
        assert got[key]==expected[key],(key,got,expected)
    assert (got['TP'],got['FP'],got['FN'],got['TN'])==(1,1,4,3)
    assert got['neutral_pairs']=={'unresolved-neutral':13,'ambiguous-neutral':5,'duplicate-neutral':1}


def test_whole_queue_refusal_and_stage_conservation():
    bodies={i:_body(i,constant=4) for i in ['A','B','C']}
    candidate=artifact(bodies,2,('token','cfg'),{})
    candidate=derive(candidate,2,('token','cfg'))
    policy=PairPolicyConfig.from_dict({'structure_match_threshold':.95,'slot_match_threshold':1.,
        'max_comparison_count':1,'max_alignment_cell_budget':500000000})
    try:
        build_family_artifact(candidate_artifact=candidate,bodies=bodies,config=policy)
    except ValueError as e:
        assert 'exceeds F6 comparison budget' in str(e)
    else:
        raise AssertionError('over-budget queue was scored')
    policy=PairPolicyConfig.from_dict({'structure_match_threshold':.95,'slot_match_threshold':1.,
        'max_comparison_count':10,'max_alignment_cell_budget':500000000})
    pred=build_family_artifact(candidate_artifact=candidate,bodies=bodies,config=policy)
    audit={'addresses':{i:{'origins':['f'],'identities':[i]} for i in bodies}}
    gt={'origins':[{'origin':'f','members':list(bodies)}]}
    got=metrics(pred,gt,audit,set(bodies),{tuple(p['pair']) for p in candidate['pairs']})
    assert got['TP']==3 and got['FP']==got['FN']==0
    assert got['positive_first_outcome']=={'recovered':3}
    assert got['exact_group_rate']==1


if __name__=='__main__':
    test_prefix_and_named_intersection()
    test_neutral_denominators_match_existing_evaluator()
    test_whole_queue_refusal_and_stage_conservation()
    print('Follow-up: prefix, named views, neutral accounting, whole-queue budget and stage conservation PASS')
