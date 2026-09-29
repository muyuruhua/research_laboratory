#!/usr/bin/env python3
"""Verify the supplied per-run evidence against all filled manuscript tables.

This does not reconstruct unobserved runs or infer causal effects. The ledger
contains extracted numeric fields and source paths, without request/prompt text.
"""
import csv
import json
import math
from pathlib import Path
import statistics

BASE = Path(__file__).resolve().parent
NAMES = dict(zip(['lightftp','bftpd','proftpd','pure-ftpd','exim','live555','kamailio','forked-daapd','lighttpd1'], ['LightFTP','bftpd','ProFTPD','Pure-FTPd','Exim','Live555','Kamailio','Forked-daapd','Lighttpd1']))
ARMS = {'A':'AFLNet','B':'ChatAFL','C':'LoopFuzz-direct','D':'LoopFuzz-gated-fixed','E':'LoopFuzz-gated-calibrated','E-gamma099':r'E, $\gamma=.99$','E-gamma100':r'E, $\gamma=1.0$'}

def stat(values):
    values = [float(v) for v in values if v is not None and v != '' and math.isfinite(float(v))]
    return {'n':len(values),'mean':statistics.mean(values) if values else None,'sd':statistics.stdev(values) if len(values)>1 else None}

def agree(actual, expected):
    if expected is None:
        assert actual is None or actual == '', (actual, expected)
    else:
        assert math.isclose(float(actual), expected, rel_tol=1e-12, abs_tol=1e-9), (actual, expected)

def main():
    runs=json.loads((BASE/'filled_run_evidence.json').read_text())['runs']
    aggregate=json.loads((BASE/'filled_experiment_data.json').read_text())['aggregate']
    csvrows=list(csv.DictReader((BASE/'archive_arm_results.csv').open()))
    text=(BASE/'main.revised.tex').read_text()
    archive=(BASE/'archive_arm_results.tex').read_text()
    observed=(BASE/'observed_tables.tex').read_text()
    costs=(BASE/'observed_costs.tex').read_text()
    source=BASE.parents[1]/'Key_Experiment'
    assert len(runs)==517 and len(aggregate)==len(csvrows)==60
    assert len({r['source_rel'] for r in runs})==len(runs), 'Duplicate archive paths'
    summaries={}
    for r in runs:
        path=source/r['source_rel']
        assert path.is_file(), path
        summary_path=path.parent/'run_summary.csv'
        if summary_path not in summaries:
            summaries[summary_path]=list(csv.DictReader(summary_path.open()))
        matching=[x for x in summaries[summary_path] if x['source']==path.name and x['subject']==r['target']]
        assert len(matching)==1,(path,len(matching))
        for key in ['runtime_min','b_abs','edges']:
            agree(matching[0].get(key),float(r['summary'][key]) if r['summary'].get(key) not in ('',None) else None)
        assert r['duplicate_candidate_ids']==r['duplicate_trial_ids']==r['orphan_trials']==0
        if r['arm']=='D': assert r['source_rel'].startswith('benchmark/')
    mappings={'branches':('summary','b_abs'),'ipsm_edges':('summary','edges'),'runtime_min':('summary','runtime_min'),'auc_branch_hours':(None,'auc_branch_hours'),'model_calls':(None,'model_calls'),'prompt_tokens':(None,'prompt_tokens'),'completion_tokens':(None,'completion_tokens')}
    csvmetrics={'branch':'branches','auc':'auc_branch_hours','ipsm':'ipsm_edges'}
    for row in csvrows:
        arm,target=row['arm'],row['target']
        group=[r for r in runs if (r['arm'],r['target'])==(arm,target)]
        a=aggregate[f'{arm}|{target}']
        assert int(row['nominal_runs'])==a['runs_nominal']==10
        assert int(row['runs_available'])==a['runs_available']==len(group)
        for metric,(parent,key) in mappings.items():
            values=[(r[parent] if parent else r).get(key) for r in group]
            expected=stat(values)
            assert a[metric]['n']==expected['n']
            for k in ['mean','sd']: agree(a[metric].get(k),expected[k])
        for prefix,metric in csvmetrics.items():
            for k in ['mean','sd']: agree(row[f'{prefix}_{k}'],a[metric].get(k))
        for key in ['candidates','trials','episodes','episode_rewards']:
            assert sum(r[key] for r in group)==a[key]==int(row[key])
        for key in ['reject','provisional','durable']:
            assert sum(r['dispositions'].get(key,0) for r in group)==a['dispositions'].get(key,0)==int(row[key])
        line=next(l for l in archive.splitlines() if l.startswith(f'{ARMS[arm]} & {NAMES[target]} &'))
        for metric in csvmetrics.values():
            d=a[metric]
            assert f"{d['mean']:.1f} $\\pm$ {d['sd']:.1f} (n={d['n']})" in line
        if arm in 'ABCDE':
            line=next(l for l in text.splitlines() if l.startswith(NAMES[target]+' & '+r'\shortstack'))
            cell=line.split(' & ')[1+'ABCDE'.index(arm)]
            for metric in ['branches','auc_branch_hours']:
                d=a[metric]
                assert f"{d['mean']:.1f}$\\pm${d['sd']:.1f}" in cell
            assert f"n={len(group)}" in cell
        if arm in 'AD':
            line=next(l for l in observed.splitlines() if l.startswith(NAMES[target]+' & ') and '$\\pm$' in l)
            for metric in ['branches','ipsm_edges']:
                d=a[metric];assert f"{d['mean']:.1f} $\\pm$ {d['sd']:.1f}" in line
    assert 'E|bftpd' not in aggregate
    bftpd=next(l for l in text.splitlines() if l.startswith('bftpd & '+r'\shortstack'))
    assert bftpd.endswith(r'& \missing \\')
    for target,name in NAMES.items():
        rr=[r for r in runs if r['arm']=='D' and r['target']==target]
        calls=[r['model_calls'] for r in rr if r['model_calls'] is not None]
        tokens=[(r['prompt_tokens']+r['completion_tokens'])/1000 for r in rr if r['prompt_tokens'] is not None and r['completion_tokens'] is not None]
        line=next(l for l in costs.splitlines() if l.startswith(name+' & '))
        assert f'{min(calls)}--{max(calls)}' in line
        assert f'{min(tokens):.1f}--{max(tokens):.1f}' in line
    mechanisms=json.loads((BASE/'filled_mechanism_data.json').read_text())
    totals={}
    for arm in 'CDE':
        rr=[r for r in runs if r['arm']==arm]
        lat=stat([r['trial_latency_ms_mean'] for r in rr]);m=mechanisms[arm]['trial_latency_ms']
        assert m['n_runs_with_trials']==lat['n']
        for key in ['mean','sd']: agree(m[key],lat[key])
        assert f"{m['mean']:.1f}$\\pm${m['sd']:.1f}" in text
        for key,val in mechanisms[arm]['first_failed_logged_predicate'].items():
            assert sum(r['first_failed_logged_predicate'].get(key,0) for r in rr)==val
        totals[arm]={key:sum(r[key] for r in rr) for key in ['candidates','trials','episodes','unmatched_candidates']}
    assert len(text.split(r'\begin{enumerate}',1)[1].split(r'\end{enumerate}',1)[0].split(r'\item'))-1==3
    for label in ['Downstream productivity@64','Provisional conversion / expiration','Promotion latency','Brier / ECE / AUPRC']:
        line=next(l for l in text.splitlines() if l.startswith(label+' &'))
        assert line.count(r'\missing')==3
    assert 'native_endpoints_filled.pdf' in text
    assert 'Calls range from 52 to 248' in text
    assert 'zero to 18,816' in text
    log=(BASE/'main.revised.log').read_text()
    for error in ['! LaTeX Error','! Undefined','undefined citations','undefined references','Overfull','Float too large']:
        assert error not in log,error
    result={'status':'PASS','archive_paths':len(runs),'arm_target_groups':len(csvrows),'main_table_filled_cells':44,'main_table_blank_cells':1,'mechanisms':totals,'latex':'No errors, undefined references/citations, overfull boxes or oversized floats. Underfull paragraph notices may remain.'}
    (BASE/'filled_validation.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
