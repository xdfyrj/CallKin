"""Run independent cases with at most two inference processes; retain all logs."""
import concurrent.futures
import json
import subprocess
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent


def case_run(case):
    jobs=[('retrieval',['run_followup.py','retrieve','--case',case])]
    for method in ('combined3','body2','exact','v0','rescue'):
        jobs.append((method+'-k16',['run_followup.py','predict','--case',case,'--method',method,'--k','16']))
    # Score the primary point before the sensitivity runs, without changing settings.
    jobs.append(('scoring-primary',['score_followup.py','--case',case]))
    for k in ('8','32'):
        for method in ('combined3','body2'):
            jobs.append((method+'-k'+k,['run_followup.py','predict','--case',case,'--method',method,'--k',k]))
    jobs.append(('scoring-all',['score_followup.py','--case',case]))
    for label,args in jobs:
        log=HERE/'logs'/f'{case}-{label}.log'
        with log.open('a') as stream:
            code=subprocess.run([sys.executable,'-B',str(HERE/args[0]),*args[1:]],stdout=stream,stderr=subprocess.STDOUT).returncode
        print(case,label,'exit',code,flush=True)
        if code:return {'case':case,'failed_stage':label,'returncode':code}
    return {'case':case,'status':'finished'}


if __name__=='__main__':
    (HERE/'logs').mkdir(exist_ok=True)
    (HERE/'execution-environment.json').write_text(json.dumps({
        'maximum_concurrent_case_processes':2,
        'timing_scope':'single-run process observations under up to two concurrent independent cases; not isolated timing benchmarks',
    },indent=2)+'\n')
    cases=json.loads((HERE/'config.json').read_text())['cases']
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(case_run,cases))
    (HERE/'matrix-status.json').write_text(json.dumps(results,indent=2)+'\n')
    raise SystemExit(any('failed_stage' in r for r in results))
