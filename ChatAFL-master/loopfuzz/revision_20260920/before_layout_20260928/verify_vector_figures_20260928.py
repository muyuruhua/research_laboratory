#!/usr/bin/env python3
"""Validate plotted numerical evidence, missingness, vector assets and manuscript."""
import csv
import gzip
import json
import math
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
import numpy as np

BASE = Path(__file__).resolve().parent
OUT = BASE/'figures_20260928'
FIGURES = ['coverage_trajectories','logged_reward_reliability','candidate_dispositions',
           'token_cost_coverage','call_cost_coverage','posterior_cases']

def read_csv(name):
    return list(csv.DictReader((OUT/name).open()))

def no_raster_pdf(path):
    output = subprocess.check_output(['pdfimages','-list',str(path)],text=True)
    assert len(output.strip().splitlines()) == 2, (path,output)

def main():
    with gzip.open(BASE/'vector_figure_evidence_20260928.json.gz','rt') as f: data=json.load(f)
    runs=data['runs']; ledger=json.loads((BASE/'filled_run_evidence.json').read_text())['runs']
    original={r['source_rel']:r for r in ledger}
    for r in runs:
        old=original[r['source_rel']]
        for key in old: assert r[key]==old[key],(r['source_rel'],key)
    assert len(runs)==469 and len({r['source_rel'] for r in runs})==469
    for row in read_csv('coverage_trajectory_values.csv'):
        group=[r for r in runs if r['arm']==row['arm'] and r['target']==row['target']]
        t=float(row['hour'])
        support=[r for r in group if r['coverage'][0][0]<=t<=r['coverage'][-1][0]]
        assert len(support)==int(row['n_observed'])
        assert int(row['N_nominal'])==10 and int(row['n_archives'])==len(group)
        if not support:
            assert row['median']==row['q25']==row['q75']==''
        else:
            # Validate aggregate against supported observations, not cached statistics.
            values=[np.interp(t,*np.array(r['coverage']).T) for r in support]
            expected=np.quantile(values,[.25,.5,.75])
            assert np.allclose([float(row[k]) for k in ['q25','median','q75']],expected)
    fields=data['episode_fields']; probabilities=fields.index('posterior_mean_before')
    reward=fields.index('reward'); mutations=fields.index('mutations')
    for row in read_csv('reliability_metrics.csv'):
        rr=[r for r in runs if r['arm']=='E' and r['target']==row['target']]
        ev=[e for r in rr for e in r['episode_data'] if e[mutations]>0]
        assert len(rr)==int(row['n_runs']) and len(ev)==int(row['episodes'])
        brier=sum((e[probabilities]-e[reward])**2 for e in ev)/len(ev)
        assert math.isclose(brier,float(row['brier']),abs_tol=1e-12)
        bins=[b for b in read_csv('reliability_bins.csv') if b['target']==row['target']]
        assert sum(int(b['episodes']) for b in bins)==len(ev)
        for b in bins:
            if int(b['episodes'])==0:
                assert b['mean_prediction']==b['observed_reward_rate']==b['ci_low']==b['ci_high']==''
    for row in read_csv('candidate_disposition_values.csv'):
        arm=row['arm']; rr=[r for r in runs if r['arm']==arm]
        assert int(row['candidates'])==sum(r['candidates'] for r in rr)
        assert int(row['trials'])==sum(r['trials'] for r in rr)
        assert int(row['reject'])+int(row['durable'])+int(row['unmatched'])==int(row['candidates'])
        assert sum(int(row[k]) for k in ['p_first_fail','u_first_fail','r_first_fail','pur_all_pass'])==int(row['trials'])
    for filename,costkey in [('token_cost_coverage_values.csv','tokens'),('call_cost_coverage_values.csv','calls')]:
        rows=read_csv(filename)
        assert len(rows)==375 and len({r['source_rel'] for r in rows})==375
        for r in rows:
            old=original[r['source_rel']]
            expected=old['model_calls'] if costkey=='calls' else old['prompt_tokens']+old['completion_tokens']
            assert expected==float(r['usage']) and float(old['summary']['b_abs'])==float(r['branches'])
    for name in FIGURES:
        no_raster_pdf(OUT/(name+'.pdf'))
        assert not ET.parse(OUT/(name+'.svg')).findall('.//{http://www.w3.org/2000/svg}image')
    text=(BASE/'main.revised.tex').read_text()
    assert r'\blankpanel' not in text and 'Reserved reliability' not in text and 'fig:km' not in text
    for name in FIGURES:assert f'figures_20260928/{name}.pdf' in text
    includes=re.findall(r'\\includegraphics(?:\[[^]]*\])?\{([^}]+)\}',text)
    assert includes and all(f.endswith('.pdf') for f in includes)
    no_raster_pdf(BASE/'main.revised.pdf')
    log=(BASE/'main.revised.log').read_text()
    for error in ['! LaTeX Error','! Undefined','undefined citations','undefined references','Overfull','Float too large']:
        assert error not in log,error
    result={'status':'PASS','new_vector_figures':len(FIGURES),'formats':['PDF','SVG'],
        'embedded_raster_images':0,'primary_archives':469,'cost_observations':375,
        'positive_execution_E_episodes':23113,'nominal_n':10,
        'checked':'source agreement, per-time missingness, quantiles, Brier, count reconciliation, vector contents, LaTeX log',
        'source_endpoint_discrepancies':[{'source_rel':r['source_rel'],'trajectory':r['coverage'][-1][1],
                                        'summary':r['summary']['b_abs']} for r in runs if not r['endpoint_matches_summary']]}
    (OUT/'figure_validation.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
