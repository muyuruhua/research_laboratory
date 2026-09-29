#!/usr/bin/env python3
"""Rebuild the manuscript evidence ledger from the current Key_Experiment archive.

Only current tar.gz files with a matching run_summary.csv row are included.
A=benchmark AFLNet, B=benchmark ChatAFL, D=benchmark LoopFuzz.  The
ablation/gated_fixed directory is an explicitly documented duplicate of D and
is excluded to prevent double counting. C/direct, E/calibrated, and the two E
gamma sensitivity groups are read from their ablation directories.
"""
from __future__ import annotations
import csv, hashlib, io, json, math, statistics, tarfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1] / 'Key_Experiment'
TARGETS = ['lightftp','bftpd','proftpd','pure-ftpd','exim','live555','kamailio','forked-daapd','lighttpd1']
NAMES = dict(zip(TARGETS,['LightFTP','bftpd','ProFTPD','Pure-FTPd','Exim','Live555','Kamailio','Forked-daapd','Lighttpd1']))
EP_FIELDS=['episode_id','time_ms','selected_state','alpha_before','beta_before','posterior_mean_before','sampled_theta','frontier_score','final_selection_score','mutations','new_code_edges','new_state_edges','reward','alpha_after','beta_after','episode_latency_ms']
SUMMARY={}
SUMMARY_HASHES={}
for p in sorted(list((ROOT/'benchmark').glob('*/run_summary.csv'))+
                [q for arm in ['direct','calibrated','cal_gamma099','cal_gamma100'] for q in (ROOT/'ablation'/arm).glob('*/run_summary.csv')]):
    rel=str(p.relative_to(ROOT)); SUMMARY_HASHES[rel]=hashlib.sha256(p.read_bytes()).hexdigest()
    for row in csv.DictReader(p.open()):
        reltar=str((p.parent/row['source']).relative_to(ROOT))
        if reltar in SUMMARY: raise RuntimeError(f'duplicate summary mapping {reltar}')
        SUMMARY[reltar]=row

def mapping(rel: str, row: dict) -> str|None:
    parts=Path(rel).parts
    if parts[0]=='benchmark':
        if row['fuzzer']=='aflnet': return 'A'
        if row['fuzzer']=='chatafl': return 'B'
        if row['fuzzer']=='loopfuzz': return 'D'
    if parts[0]=='ablation':
        if parts[1]=='direct': return 'C'
        if parts[1]=='calibrated': return 'E'
        if parts[1]=='cal_gamma099': return 'E-gamma099'
        if parts[1]=='cal_gamma100': return 'E-gamma100'
        if parts[1]=='gated_fixed': return None
    return None

ARCHIVES=[]
for sub in ['benchmark','ablation/direct','ablation/calibrated','ablation/cal_gamma099','ablation/cal_gamma100']:
    for p in sorted((ROOT/sub).rglob('*.tar.gz')):
        rel=str(p.relative_to(ROOT)); row=SUMMARY.get(rel)
        if row is None: raise RuntimeError(f'archive has no summary row: {rel}')
        arm=mapping(rel,row)
        if arm is None: continue
        ARCHIVES.append((p,rel,arm,row))
if len({x[1] for x in ARCHIVES}) != len(ARCHIVES): raise RuntimeError('duplicate archive paths')
missing=set(SUMMARY)-{x[1] for x in ARCHIVES}
if missing: raise RuntimeError(f'summary rows without selected archive: {sorted(missing)[:10]} ({len(missing)})')

def num(v):
    try: return float(v) if '.' in str(v) else int(v)
    except (TypeError,ValueError): return None

def parse_stats(raw: bytes):
    out={}
    for line in raw.decode('utf-8','replace').splitlines():
        if ':' in line:
            k,v=line.split(':',1);out[k.strip()]=v.strip()
    return out

def one(item):
    path,rel,arm,row=item
    raw={}
    with tarfile.open(path,'r|*') as tf:
        for m in tf:
            if not m.isfile(): continue
            name=m.name.rsplit('/',1)[-1]
            if name in {'cov_over_time.csv','fuzzer_stats','candidate-events.jsonl','admission-events.jsonl','state-episodes.jsonl','run-config.jsonl','provisional-events.jsonl','repair-events.jsonl','bug-events.jsonl'}:
                if name in raw: raise RuntimeError(f'multiple {name}: {rel}')
                raw[name]=tf.extractfile(m).read()
    if 'cov_over_time.csv' not in raw or 'fuzzer_stats' not in raw: raise RuntimeError(f'missing core member: {rel}')
    st=parse_stats(raw['fuzzer_stats'])
    points={}
    duplicates=0
    for x in csv.DictReader(io.StringIO(raw['cov_over_time.csv'].decode('utf-8','replace'))):
        t=float(x['Time']); y=float(x['b_abs'])
        if not (math.isfinite(t) and math.isfinite(y)): raise RuntimeError(f'nonfinite coverage: {rel}')
        duplicates += int(t in points)
        points[t]=max(points.get(t,-math.inf),y)
    points=sorted(points.items())
    if len(points)<2: raise RuntimeError(f'too few coverage points: {rel}')
    start=num(st.get('start_time'))
    if start is None: raise RuntimeError(f'no start_time: {rel}')
    auc=sum((b[0]-a[0])*(a[1]+b[1])/7200 for a,b in zip(points,points[1:]))
    if not math.isclose(float(row['b_abs']),points[-1][1],abs_tol=1e-6):
        # Preserve the archive summary endpoint but record the discrepancy.
        endpoint_matches=False
    else: endpoint_matches=True
    def events(name):
        return [json.loads(line) for line in raw.get(name,b'').decode('utf-8','replace').splitlines() if line.strip()]
    cand=events('candidate-events.jsonl'); trials=events('admission-events.jsonl'); episodes=events('state-episodes.jsonl')
    cids=[e.get('candidate_id') for e in cand]; tcids={e.get('candidate_id') for e in trials}; tids=[e.get('trial_id') for e in trials]
    lat=[float(e['latency_ms']) for e in trials if e.get('latency_ms') is not None]
    first=Counter()
    for e in trials:
        for k in ['p_pass','u_pass','r_pass']:
            if e.get(k) is False: first[k]+=1;break
        else: first['pass_all']+=1
    dispositions=dict(Counter(e.get('disposition','missing') for e in trials))
    stats={
      'llm_total_calls':num(st.get('llm_total_calls')),
      'llm_prompt_tokens':num(st.get('llm_prompt_tokens')),
      'llm_completion_tok':num(st.get('llm_completion_tok'))}
    model_calls=stats['llm_total_calls'];prompt=stats['llm_prompt_tokens'];completion=stats['llm_completion_tok']
    ep_data=[[e.get(k) for k in EP_FIELDS] for e in episodes] if arm=='E' else None
    config=[]
    for e in events('run-config.jsonl'):
        config.append({k:e.get(k) for k in ['phase','arm','calibration','cal_gamma','cal_epsilon','start_time_ms','end_time_ms','fuzzer_commit']})
    return {
      'arm':arm,'target':row['subject'],'run':int(row['run']),'source_rel':rel,
      'summary':{k:row.get(k,'') for k in ['source','subject','fuzzer','run','status','invalid_reason','exit_code','runtime_min','elapsed_min','b_abs','edges','nodes']},
      'archive_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'archive_bytes':path.stat().st_size,
      'archive_mtime_ns':path.stat().st_mtime_ns,'fuzzer_start_time':start,'duplicate_timestamps':duplicates,
      'auc_branch_hours':auc,'model_calls':model_calls,'prompt_tokens':prompt,'completion_tokens':completion,
      'candidates':len(cand),'trials':len(trials),'dispositions':dispositions,'episodes':len(episodes),
      'episode_rewards':sum(e.get('reward',0) or 0 for e in episodes),
      'episode_mutations_min':min([e.get('mutations') for e in episodes if e.get('mutations') is not None],default=None),
      'episode_mutations_max':max([e.get('mutations') for e in episodes if e.get('mutations') is not None],default=None),
      'trial_latency_ms_mean':statistics.mean(lat) if lat else None,'trial_latency_n':len(lat),
      'first_failed_logged_predicate':dict(first),'unmatched_candidates':len(set(cids)-tcids),
      'orphan_trials':len(tcids-set(cids)),'duplicate_candidate_ids':len(cids)-len(set(cids)),
      'duplicate_trial_ids':len(tids)-len(set(tids)),'endpoint_matches_summary':endpoint_matches,
      'coverage':[[ (t-start)/3600, y] for t,y in points],
      'coverage_sha256':hashlib.sha256(raw['cov_over_time.csv']).hexdigest(),
      'config_evidence':config[-1] if config else {},
      'episode_data':ep_data,
      'episode_sha256':hashlib.sha256(raw['state-episodes.jsonl']).hexdigest() if 'state-episodes.jsonl' in raw else None,
      'raw_file_hashes':{k:hashlib.sha256(v).hexdigest() for k,v in raw.items()}}

runs=[]
with ThreadPoolExecutor(max_workers=4) as pool:
    fs=[pool.submit(one,x) for x in ARCHIVES]
    for i,f in enumerate(as_completed(fs),1):
        runs.append(f.result())
        if i%50==0 or i==len(fs): print(f'Parsed {i}/{len(fs)} archives',flush=True)
runs.sort(key=lambda r:(r['arm'],TARGETS.index(r['target']) if r['target'] in TARGETS else 99,r['source_rel']))

def stats(vals):
    vals=[float(v) for v in vals if v is not None and math.isfinite(float(v))]
    return {'n':len(vals),'mean':statistics.mean(vals) if vals else None,'sd':statistics.stdev(vals) if len(vals)>1 else None,'min':min(vals) if vals else None,'max':max(vals) if vals else None}

groups=defaultdict(list)
for r in runs: groups[(r['arm'],r['target'])].append(r)
aggregate={}
for (arm,target),rr in sorted(groups.items()):
    aggregate[f'{arm}|{target}']={'target':target,'arm':arm,'runs_available':len(rr),'runs_nominal':10,
      'status':dict(Counter(r['summary']['status'] for r in rr)),
      'exit_code':dict(Counter(r['summary']['exit_code'] for r in rr)),
      'runtime_min':stats([r['summary']['runtime_min'] for r in rr]),
      'branches':stats([r['summary']['b_abs'] for r in rr]),
      'ipsm_edges':stats([r['summary']['edges'] for r in rr]),
      'auc_branch_hours':stats([r['auc_branch_hours'] for r in rr]),
      'model_calls':stats([r['model_calls'] for r in rr]),
      'prompt_tokens':stats([r['prompt_tokens'] for r in rr]),
      'completion_tokens':stats([r['completion_tokens'] for r in rr]),
      'candidates':sum(r['candidates'] for r in rr),'trials':sum(r['trials'] for r in rr),
      'episodes':sum(r['episodes'] for r in rr),'episode_rewards':sum(r['episode_rewards'] for r in rr),
      'dispositions':dict(sum((Counter(r['dispositions']) for r in rr),Counter())),
      'first_failed_logged_predicate':dict(sum((Counter(r['first_failed_logged_predicate']) for r in rr),Counter())),
      'unmatched_candidates':sum(r['unmatched_candidates'] for r in rr),'orphan_trials':sum(r['orphan_trials'] for r in rr)}
policy='Current tar.gz files with matching run_summary.csv; nominal N=10 retained, actual n shown; missing combinations blank; ablation/gated_fixed excluded because it duplicates benchmark LoopFuzz D.'
(BASE/'filled_run_evidence_20260929.json').write_text(json.dumps({'source_root':str(ROOT),'policy':policy,'summary_hashes':SUMMARY_HASHES,'runs':runs},indent=2,ensure_ascii=False)+'\n')
(BASE/'filled_experiment_data_20260929.json').write_text(json.dumps({'policy':policy,'aggregate':aggregate},indent=2,ensure_ascii=False)+'\n')
# Machine-readable per-arm CSV.
fields=['arm','target','runs_nominal','runs_available','branches_mean','branches_sd','auc_mean','auc_sd','ipsm_mean','ipsm_sd','candidates','trials','episodes','reject','provisional','durable']
with (BASE/'archive_arm_results_20260929.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
 for key,a in aggregate.items():
  w.writerow({'arm':a['arm'],'target':a['target'],'runs_nominal':10,'runs_available':a['runs_available'],
   'branches_mean':a['branches']['mean'],'branches_sd':a['branches']['sd'],'auc_mean':a['auc_branch_hours']['mean'],'auc_sd':a['auc_branch_hours']['sd'],
   'ipsm_mean':a['ipsm_edges']['mean'],'ipsm_sd':a['ipsm_edges']['sd'],'candidates':a['candidates'],'trials':a['trials'],'episodes':a['episodes'],
   'reject':a['dispositions'].get('reject',0),'provisional':a['dispositions'].get('provisional',0),'durable':a['dispositions'].get('durable',0)})
# Mechanism summary for primary C/D/E.
mech={}
for arm in ['C','D','E']:
 rr=[r for r in runs if r['arm']==arm]
 mech[arm]={'candidates':sum(r['candidates'] for r in rr),'trials':sum(r['trials'] for r in rr),'episodes':sum(r['episodes'] for r in rr),'episode_rewards':sum(r['episode_rewards'] for r in rr),'dispositions':dict(sum((Counter(r['dispositions']) for r in rr),Counter())),'first_failed_logged_predicate':dict(sum((Counter(r['first_failed_logged_predicate']) for r in rr),Counter())),'unmatched_candidates':sum(r['unmatched_candidates'] for r in rr),'orphan_trials':sum(r['orphan_trials'] for r in rr)}
 lat=[r['trial_latency_ms_mean'] for r in rr if r['trial_latency_ms_mean'] is not None]
 mech[arm]['trial_latency_ms']={'n_runs_with_trials':len(lat),'mean':statistics.mean(lat) if lat else None,'sd':statistics.stdev(lat) if len(lat)>1 else None}
(BASE/'filled_mechanism_data_20260929.json').write_text(json.dumps(mech,indent=2,ensure_ascii=False)+'\n')
# Source manifest and compact update report.
manifest={'generated_at':'2026-09-29','source_root':str(ROOT),'policy':policy,'summary_files':SUMMARY_HASHES,'selected_archives':len(runs),'archive_sha256':{r['source_rel']:r['archive_sha256'] for r in runs},'excluded_duplicate_tree':'ablation/gated_fixed','groups':{f'{k[0]}|{k[1]}':len(v) for k,v in sorted(groups.items())},'summary_rows_total':len(SUMMARY)}
(BASE/'data_update_manifest_20260929.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
print(json.dumps({'selected_archives':len(runs),'summary_rows':len(SUMMARY),'groups':{f'{k[0]}|{k[1]}':len(v) for k,v in sorted(groups.items())},'endpoint_discrepancies':sum(not r['endpoint_matches_summary'] for r in runs)},indent=2))
