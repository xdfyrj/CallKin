"""Bundle retained predictions and scoring inputs, not the large observation caches."""
import hashlib
import json
import zipfile
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]


def encode(value):return (json.dumps(value,indent=2,ensure_ascii=False,sort_keys=True)+'\n').encode()


manifest=json.loads((HERE/'inputs.json').read_text());input_root=Path(manifest['input_root'])
files={};expected=[]
for name in ('README.md','recheck.py'):
    files[name]=(HERE/'verification'/name).read_bytes()
files['linkage_overlay.py']=(ROOT/'linkage_overlay.py').read_bytes()
files['LICENSE']=(ROOT/'LICENSE').read_bytes()
for name in ('protocol.md','config.json','audit-sensitivity.json'):
    files[name]=(HERE/name).read_bytes()
for path in sorted((HERE/'audit-corrections').glob('*.json')):
    files['audit-corrections/'+path.name]=path.read_bytes()
for case,records in manifest['cases'].items():
    for key,name in [('ground_truth','ground-truth.json'),('linkage','linkage.json')]:
        record=records[key];data=(input_root/record['path']).read_bytes()
        if hashlib.sha256(data).hexdigest()!=record['sha256']:raise ValueError('input changed')
        files[f'inputs/{case}/{name}']=data
    result=json.loads((HERE/(case+'-results.json')).read_text())
    for row in result:
        directory=HERE/'runs'/case/row['name'];meta=row['metadata']
        entry={'case':case,'name':row['name'],'status':meta['status'],'counts':None}
        files[f'runs/{case}/{row["name"]}/metadata.json']=(directory/'metadata.json').read_bytes()
        if meta['status']=='completed':
            data=(directory/'prediction.json').read_bytes()
            if hashlib.sha256(data).hexdigest()!=meta['prediction_sha256']:raise ValueError('prediction changed')
            files[f'runs/{case}/{row["name"]}/prediction.json']=data
            entry['counts']={k:row['metrics'][k] for k in ('TP','FP','FN','TN')}
        expected.append(entry)
files['expected-results.json']=encode(expected)
files['manifest.json']=encode({name:hashlib.sha256(data).hexdigest() for name,data in sorted(files.items())})
path=HERE/'verification-bundle.zip'
with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for name,data in sorted(files.items()):z.writestr(name,data)
print('Created',path,'bytes',path.stat().st_size,'files',len(files))
