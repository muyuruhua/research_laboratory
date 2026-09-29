#!/usr/bin/env python3
"""Independently read original archives; emit numeric provenance, never raw prompts."""
import csv, hashlib, io, json, math, re, statistics, tarfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1] / 'Key_Experiment'
OUT = BASE / 'table_source_audit_20260928'
OUT.mkdir(exist_ok=True)
LEDGER = json.loads((BASE/'filled_run_evidence.json').read_text())['runs']
LOOKUP = {r['source_rel']:r for r in LEDGER}
SUMMARIES = {}
SUMMARY_HASHES = {}
for path in sorted(ROOT.rglob('run_summary.csv')):
    SUMMARY_HASHES[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for row in csv.DictReader(path.open()):
        rel = str((path.parent/row['source']).relative_to(ROOT))
        assert rel not in SUMMARIES
        SUMMARIES[rel] = row
FILES = sorted(p for part in ['benchmark','ablation'] for p in (ROOT/part).rglob('*.tar.gz'))
NAMES = ['cov_over_time.csv','fuzzer_stats','run-config.jsonl','candidate-events.jsonl',
         'admission-events.jsonl','state-episodes.jsonl','provisional-events.jsonl','repair-events.jsonl','bug-events.jsonl']
CONFIG_KEYS = ['phase','arm','calibration','no_admission','no_refinement','hypothesis','cal_gamma','cal_epsilon',
               'temperature_plateau','temperature_grammar','top_p','max_output_tokens','call_cap','token_cap',
               'fuzzer_commit','rng_seed','start_time_ms','end_time_ms']

def inspect(path):
    rel = str(path.relative_to(ROOT)); old = LOOKUP.get(rel)
    item = {'source_rel':rel,'in_ledger':bool(old),'archive_bytes':path.stat().st_size,
            'archive_mtime_ns':path.stat().st_mtime_ns,'files':{},'errors':[], 'ledger_differences':[], 'summary_differences':[]}
    if old: item.update(arm=old['arm'],target=old['target'])
    else: item.update(arm='D' if '/benchmark/' in str(path) and 'loopfuzz' in path.name else 'unresolved',target=path.parent.name.split('_')[0].replace('results-',''))
    rawfiles = {}
    try:
        with tarfile.open(path,'r|gz') as archive:
            for m in archive:
                name = m.name.rsplit('/',1)[-1]
                if not m.isfile() or name not in NAMES: continue
                if name in rawfiles: item['errors'].append('multiple '+name)
                raw = archive.extractfile(m).read()
                rawfiles[name] = raw
                item['files'][name] = {'member':m.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    except Exception as exc:
        item['errors'].append(type(exc).__name__+': '+str(exc));return item
    events = {}
    for name,raw in rawfiles.items():
        if not name.endswith('.jsonl'): continue
        events[name] = []
        for i,line in enumerate(raw.splitlines(),1):
            if not line.strip():continue
            try: events[name].append(json.loads(line))
            except Exception: item['errors'].append(f'{name}: invalid row {i}')
        item['files'][name]['rows'] = len(events[name])
    stats = {}
    for line in rawfiles.get('fuzzer_stats',b'').decode(errors='replace').splitlines():
        if ':' in line:
            key,val=line.split(':',1);stats[key.strip()]=val.strip()
    item['stat_keys'] = sorted(stats)
    def numeric(key):
        val=stats.get(key)
        try:return float(val) if '.' in val else int(val)
        except (ValueError,TypeError):return None
    for key in ['start_time','last_update','execs_done']:
        item[key]=numeric(key)
    item['numeric']={k:numeric(v) for k,v in [('model_calls','llm_total_calls'),('prompt_tokens','llm_prompt_tokens'),('completion_tokens','llm_completion_tok')]}
    raw=rawfiles.get('cov_over_time.csv')
    if raw:
        points={};duplicates=0
        for row in csv.DictReader(io.StringIO(raw.decode())):
            t,y=float(row['Time']),float(row['b_abs'])
            duplicates+=int(t in points);points[t]=max(points.get(t,-1),y)
        points=sorted(points.items())
        auc=sum((t2-t1)*(y1+y2)/7200 for (t1,y1),(t2,y2) in zip(points,points[1:]))
        item['numeric']['auc_branch_hours']=auc
        item['coverage']={'rows':len(points),'first_unix':points[0][0],'last_unix':points[-1][0],
                          'last_branches':points[-1][1],'duplicate_times':duplicates,
                          'decreases':sum(b[1]<a[1] for a,b in zip(points,points[1:]))}
    c=events.get('candidate-events.jsonl',[]);tr=events.get('admission-events.jsonl',[]);ep=events.get('state-episodes.jsonl',[])
    cids=[e.get('candidate_id') for e in c];tids=[e.get('trial_id') for e in tr];tcids={e.get('candidate_id') for e in tr}
    lat=[float(e['latency_ms']) for e in tr if e.get('latency_ms') is not None]
    first=Counter()
    for e in tr:
        for key in ['p_pass','u_pass','r_pass']:
            if e.get(key) is False: first[key]+=1;break
        else:first['pass_all']+=1
    disposition=dict(Counter(e.get('disposition','missing') for e in tr))
    numeric={'candidates':len(c),'trials':len(tr),'episodes':len(ep),'episode_rewards':sum(e.get('reward',0) for e in ep),
             'trial_latency_ms_mean':statistics.mean(lat) if lat else None,'trial_latency_n':len(lat),
             'unmatched_candidates':len(set(cids)-tcids),'orphan_trials':len(tcids-set(cids)),
             'duplicate_candidate_ids':len(cids)-len(set(cids)),'duplicate_trial_ids':len(tids)-len(set(tids))}
    if ep:
        numeric.update(episode_mutations_min=min(e['mutations'] for e in ep),episode_mutations_max=max(e['mutations'] for e in ep))
    item['numeric'].update(numeric)
    item['dispositions']=disposition;item['first_failed_logged_predicate']=dict(first)
    item['configs']=[{k:e.get(k) for k in CONFIG_KEYS} for e in events.get('run-config.jsonl',[])]
    for n in ['provisional-events.jsonl','repair-events.jsonl','bug-events.jsonl']:
        ev=events.get(n,[])
        item[n]={'rows':len(ev),'keys':sorted({k for e in ev for k in e}), 'kinds':dict(Counter(e.get('kind',e.get('event')) for e in ev))}
    if old:
        for key,val in item['numeric'].items():
            expected=old.get(key)
            if val is None and expected is None:continue
            if isinstance(val,(int,float)) and isinstance(expected,(int,float)) and math.isclose(val,expected,rel_tol=1e-10,abs_tol=1e-6):continue
            if val!=expected:item['ledger_differences'].append({'field':key,'raw':val,'ledger':expected})
        for key,actual in [('dispositions',disposition),('first_failed_logged_predicate',dict(first))]:
            expected=old.get(key,{})
            if Counter(actual)!=Counter(expected):item['ledger_differences'].append({'field':key,'raw':actual,'ledger':expected})
    summary=SUMMARIES.get(rel)
    if summary:
        for field,val in [('b_abs',item.get('coverage',{}).get('last_branches')),('start_time',item['start_time']),('last_update',item['last_update'])]:
            if val is not None and summary.get(field) not in ['',None] and float(summary[field])!=val:
                item['summary_differences'].append({'field':field,'archive':val,'summary':float(summary[field])})
    return item

records=[]
with ThreadPoolExecutor(max_workers=4) as pool:
    fs={pool.submit(inspect,p):p for p in FILES}
    for future in as_completed(fs):
        records.append(future.result())
        if len(records)%50==0 or len(records)==len(FILES): print(f'Raw archives checked: {len(records)}/{len(FILES)}',flush=True)
records.sort(key=lambda x:x['source_rel'])
disk={str(p.relative_to(ROOT)) for p in FILES};summary=set(SUMMARIES);ledger=set(LOOKUP)
signatures=defaultdict(list)
for r in records:
    sig=tuple(r['files'][n]['sha256'] for n in ['cov_over_time.csv','fuzzer_stats'] if n in r['files'])
    if len(sig)==2:signatures[sig].append(r['source_rel'])
counts={}
for a in sorted({r['arm'] for r in records}):
    rr=[r for r in records if r['arm']==a and r['in_ledger']]
    counts[a]={'runs':len(rr),'targets':len({r['target'] for r in rr}),
               'log_presence':{n:sum(n in r['files'] for r in rr) for n in NAMES},
               'raw_totals':{k:sum(r['numeric'].get(k,0) or 0 for r in rr) for k in ['candidates','trials','episodes']}}
result={'scope':'All current benchmark/ablation tar.gz files streamed independently; no extraction to disk.',
        'manuscript_sha256':hashlib.sha256((BASE/'main.revised.tex').read_bytes()).hexdigest(),
        'summary_hashes':SUMMARY_HASHES,'disk_archives':len(disk),'summary_rows':len(summary),'ledger_runs':len(ledger),
        'disk_not_in_ledger':sorted(disk-ledger),'disk_without_summary':sorted(disk-summary),
        'summary_missing_archive':sorted(summary-disk),'summary_not_in_ledger':sorted(summary-ledger),
        'duplicate_numeric_evidence':[v for v in signatures.values() if len(v)>1],
        'archive_parse_errors':[{'source':r['source_rel'],'errors':r['errors']} for r in records if r['errors']],
        'ledger_disagreements':[{'source':r['source_rel'],'differences':r['ledger_differences']} for r in records if r['ledger_differences']],
        'summary_disagreements':[{'source':r['source_rel'],'differences':r['summary_differences']} for r in records if r['summary_differences']],
        'arms':counts,'records':records}
(OUT/'raw_archive_audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ['records','summary_hashes','arms','summary_disagreements']},indent=2))
print('Summary disagreements:',len(result['summary_disagreements']),flush=True)
