"""Verify retained predictions and recompute pair counts using only bundled data."""
import hashlib
import json
from collections import defaultdict
from itertools import combinations
from math import comb
from pathlib import Path
import sys
from linkage_overlay import label_pair, load_overlay, POSITIVE, NEGATIVE

ROOT=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).resolve().parent


def read(path):return json.loads(path.read_text())


def counts(pred,audit):
    ids=pred['universe']['target_ids'];o,i=load_overlay(audit)
    clean=[x for x in ids if i.get(x) and len(set(o.get(x,())))==1]
    by_origin=defaultdict(list)
    for x in clean:by_origin[o[x][0]].append(x)
    positives=0;within=0
    for members in by_origin.values():
        within+=comb(len(members),2)
        positives+=sum(label_pair(a,b,origins_by_address=o,identities_by_address=i)==POSITIVE
                       for a,b in combinations(members,2))
    negatives=comb(len(clean),2)-within
    predicted=set();seen=set()
    for group in pred['clusters']:
        if group['status']!='accepted':continue
        members=set(group['members'])
        if members & seen or not members<=set(ids):raise ValueError('invalid predicted partition')
        seen.update(members);predicted.update(combinations(sorted(members),2))
    tp=fp=0
    for a,b in predicted:
        label=label_pair(a,b,origins_by_address=o,identities_by_address=i)
        tp+=label==POSITIVE;fp+=label==NEGATIVE
    return {'TP':tp,'FP':fp,'FN':positives-tp,'TN':negatives-fp}


manifest=read(ROOT/'manifest.json')
for name,expected in manifest.items():
    actual=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
    if actual!=expected:raise ValueError('file identity mismatch: '+name)
verified=refused=0
for row in read(ROOT/'expected-results.json'):
    case,name=row['case'],row['name']
    path=ROOT/'runs'/case/name/'prediction.json'
    if row['status']!='completed':
        if row['counts'] is not None or path.exists():raise ValueError('incomplete run reported as prediction')
        refused+=1;continue
    got=counts(read(path),read(ROOT/'inputs'/case/'linkage.json'))
    if got!=row['counts']:raise ValueError((case,name,got,row['counts']))
    verified+=1
print(f'PASS: {verified} retained predictions rescored; {refused} budget-refused configurations remain NA.')
for case,data in read(ROOT/'audit-sensitivity.json').items():
    corrected=read(ROOT/'audit-corrections'/f'{case}.linkage.v1.json')
    for row in data['rows']:
        got=counts(read(ROOT/'runs'/case/row['method']/'prediction.json'),corrected)
        expected={k:row['corrected'][k] for k in ('TP','FP','FN','TN')}
        if got!=expected:raise ValueError(('corrected',case,row['method'],got,expected))
print('PASS: source-correction sensitivity counts also match.')
