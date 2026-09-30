#!/usr/bin/env python3
"""Reconcile source inventory, numerical tables, vector-plot data and compiled PDF.
Fresh summary hashes and archive inventory/size/mtime checks; full archive hashes
are recorded at extraction. Independently recompute statistics and bootstrap CIs.
"""
from pathlib import Path
from collections import defaultdict, Counter
import csv, datetime, gzip, hashlib, json, math, re, statistics, subprocess
import xml.etree.ElementTree as ET
import numpy as np
BASE=Path(__file__).resolve().parent;FIG=BASE/'figures_updated_20260929'
BS=chr(92);ROW=BS*2
load=lambda p:json.loads(p.read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
ledger=load(BASE/'filled_run_evidence_20260929.json');runs=ledger['runs']
manifest=load(BASE/'data_update_manifest_20260929.json');root=Path(manifest['source_root'])
agg=load(BASE/'filled_experiment_data_20260929.json')['aggregate']
mechanisms=load(BASE/'filled_mechanism_data_20260929.json');tex=(BASE/'main.revised.tex').read_text()
checks=Counter()
def check(ok,label):
 if not ok:raise AssertionError(label)
 checks[label.split(':')[0]]+=1
def close(a,b,label):
 check((a is None and b is None) or (a is not None and b is not None and math.isclose(float(a),float(b),rel_tol=1e-10,abs_tol=1e-7)),label)
def table(text,label):
 pos=text.index(BS+'label{'+label+'}');end=text.index(BS+'end{table',pos);rows={}
 for line in text[pos:end].splitlines():
  if ' & ' in line and line.rstrip().endswith(ROW):
   cells=line.rstrip()[:-2].strip().split(' & ');rows[cells[0]]=cells[1:]
 return rows
def csvrows(name):
 with (FIG/name).open() as fp:return list(csv.DictReader(fp))
def pm(stats):
 if stats['mean'] is None:return BS+'missing'
 return f"{stats['mean']:.1f}$"+BS+'pm$'+f"{stats['sd']:.1f}"
names=dict(zip(['lightftp','bftpd','proftpd','pure-ftpd','exim','live555','kamailio','forked-daapd','lighttpd1'],['LightFTP','bftpd','ProFTPD','Pure-FTPd','Exim','Live555','Kamailio','Forked-daapd','Lighttpd1']))
subtrees=['benchmark','ablation/direct','ablation/calibrated','ablation/cal_gamma099','ablation/cal_gamma100']
paths={str(p.relative_to(root)) for sub in subtrees for p in (root/sub).rglob('*.tar.gz')}
check(paths=={r['source_rel'] for r in runs}==set(manifest['archive_sha256']),'source:archive inventory')
summarypaths={str(p.relative_to(root)) for sub in subtrees for p in (root/sub).glob('*/run_summary.csv')}
check(summarypaths==set(manifest['summary_files']),'source:summary inventory')
source_rows={}
for p,h in manifest['summary_files'].items():
 check(sha(root/p)==h==ledger['summary_hashes'][p],'source:summary hash '+p)
 with (root/p).open() as fp:
  for row in csv.DictReader(fp):source_rows[str(Path(p).parent/row['source'])]=row
check(set(source_rows)==paths,'source:summary rows and selected archives')
check(len(runs)==628 and len(agg)==61,'counts:archives and groups')
check(not any('gated_fixed' in p for p in paths),'source:no duplicate D subtree')
groups=defaultdict(list)
for r in runs:
 path=root/r['source_rel'];st=path.stat()
 check(st.st_size==r['archive_bytes'] and st.st_mtime_ns==r['archive_mtime_ns'],'source:archive metadata')
 check(manifest['archive_sha256'][r['source_rel']]==r['archive_sha256'],'source:extraction hash')
 check(all(str(v)==source_rows[r['source_rel']].get(k,'') for k,v in r['summary'].items()),'source:summary row values')
 c=r['coverage'];check(all(b[0]>a[0] for a,b in zip(c,c[1:])),'auc:increasing times')
 close(math.fsum((b[0]-a[0])*(a[1]+b[1])/2 for a,b in zip(c,c[1:])),r['auc_branch_hours'],'auc:recomputed branch hours')
 close(c[-1][1],r['summary']['b_abs'],'endpoint:summary and trajectory')
 groups[r['arm']+'|'+r['target']].append(r)
derived={}
for key,rs in groups.items():
 a=agg[key];d={};check(a['runs_available']==len(rs) and a['runs_nominal']==10,'aggregate:observed n and nominal N')
 getters={'branches':lambda r:float(r['summary']['b_abs']),'ipsm_edges':lambda r:float(r['summary']['edges']),'runtime_min':lambda r:float(r['summary']['runtime_min']),'auc_branch_hours':lambda r:r['auc_branch_hours'],'model_calls':lambda r:r['model_calls'],'prompt_tokens':lambda r:r['prompt_tokens'],'completion_tokens':lambda r:r['completion_tokens']}
 for metric,get in getters.items():
  vals=[get(r) for r in rs if get(r) is not None]
  d[metric]={'n':len(vals),'mean':statistics.mean(vals) if vals else None,'sd':statistics.stdev(vals) if len(vals)>1 else None,'min':min(vals) if vals else None,'max':max(vals) if vals else None}
  for k,v in d[metric].items():close(v,a[metric][k],'aggregate:'+metric+'/'+k)
 for metric in ['candidates','trials','episodes','episode_rewards','unmatched_candidates','orphan_trials']:check(sum(r[metric] for r in rs)==a[metric],'aggregate:'+metric)
 for metric in ['status','exit_code']:check(dict(Counter(r['summary'][metric] for r in rs))==a[metric],'aggregate:'+metric)
 for metric in ['dispositions','first_failed_logged_predicate']:
  totals=Counter()
  for r in rs:totals.update(r[metric])
  check(dict(totals)==a[metric],'aggregate:'+metric)
 derived[key]=d
main=table(tex,'tab:mainresults')
for target,name in names.items():
 check(len(main[name])==5,'main table:five arms')
 for arm,cell in zip('ABCDE',main[name]):
  key=arm+'|'+target;d=derived[key];n=len(groups[key])
  expected=BS+'shortstack{'+pm(d['branches'])+BS+',('+f'n={n})'+ROW+pm(d['auc_branch_hours'])+'}'
  check(cell==expected,'main table:'+key)
appendix=(BASE/'archive_arm_results.updated_20260929.tex').read_text()
appendixrows=[x for x in appendix.splitlines() if re.match(r'^(?:[A-E][1-9]|\$E_\{(?:99|100)\}\$[1-9]) & ',x)]
check(len(appendixrows)==61,'appendix:row count');codes={'completed':'C','exit_137_near_limit':'X','sigabrt':'S','oom_killed':'O'}
for key,rs in groups.items():
 arm,target=key.split('|');aid={'E-gamma099':'$E_{99}$','E-gamma100':'$E_{100}$'}.get(arm,arm)+str(list(names).index(target)+1)
 row=next(x for x in appendixrows if x.startswith(aid+' & '));cells=row[:-2].strip().split(' & ')
 check(cells[1]==str(len(rs)),'appendix:n')
 for cell,m in zip(cells[2:5],['branches','auc_branch_hours','ipsm_edges']):check(cell==pm(derived[key][m]),'appendix:'+m)
 parsed={k:int(v) for k,v in (pair.split(':') for pair in cells[5].split(','))}
 check(parsed=={codes[k]:v for k,v in Counter(r['summary']['status'] for r in rs).items()},'appendix:status')
observed=(BASE/'observed_tables.updated_20260929.tex').read_text()
inv=table(observed,'tab:observed_inventory');ends=table(observed,'tab:observed_endpoints');counts=table(observed,'tab:observed_log_counts');cost=table((BASE/'observed_costs.updated_20260929.tex').read_text(),'tab:observed_costs')
for target,name in names.items():
 rs=groups['D|'+target];a=agg['D|'+target];rt=[float(r['summary']['runtime_min']) for r in rs]
 expected=[str(len(groups[arm+'|'+target])) for arm in 'ABD']+[str(sum(r['summary']['status']=='completed' for r in rs)),str(sum(r['summary']['exit_code']=='137' for r in rs)),f'{min(rt):.0f}--{max(rt):.0f}']
 check(inv[name]==expected,'inventory table:'+target)
 check(ends[name]==[pm(derived[arm+'|'+target][m]) for m in ['branches','ipsm_edges'] for arm in 'AD'],'endpoint table:'+target)
 check(list(map(int,counts[name]))==[a['candidates'],a['trials'],a['dispositions'].get('reject',0),a['dispositions'].get('provisional',0),a['dispositions'].get('durable',0),a['episodes']],'event table:'+target)
 calls=[r['model_calls'] for r in rs];tokens=[(r['prompt_tokens']+r['completion_tokens'])/1000 for r in rs]
 check(cost[name]==[f'{min(calls):.0f}--{max(calls):.0f}',f'{min(tokens):.1f}--{max(tokens):.1f}'],'cost table:'+target)
mt=table(tex,'tab:mechanisms')
for i,arm in enumerate('CDE'):
 rs=[r for r in runs if r['arm']==arm];m=mechanisms[arm]
 for label,key in [('Candidate records','candidates'),('Trial records','trials')]:check(mt[label][i]==f'{sum(r[key] for r in rs):,}','mechanism table:'+key)
 for key in ['candidates','trials','episodes','episode_rewards','unmatched_candidates','orphan_trials']:check(sum(r[key] for r in rs)==m[key],'mechanism aggregate:'+key)
 disp=Counter();failed=Counter()
 for r in rs:disp.update(r['dispositions']);failed.update(r['first_failed_logged_predicate'])
 check(dict(disp)==m['dispositions'] and dict(failed)==m['first_failed_logged_predicate'],'mechanism aggregate:labels')
 check(mt['Reject / durable labels'][i]==f"{disp.get('reject',0):,} / {disp.get('durable',0):,}",'mechanism table:dispositions')
 check(mt['First failed logged $P/U/R$'][i]==' / '.join(f'{failed.get(k,0):,}' for k in ['p_pass','u_pass','r_pass']),'mechanism table:first flags')
 expected=f"{100*disp.get('durable',0)/m['candidates']:.1f}"+BS+f"% ({disp.get('durable',0):,}/{m['candidates']:,})"
 check(mt['Direct durable rate'][i]==expected,'mechanism table:rate')
 lat=[r['trial_latency_ms_mean'] for r in rs if r['trial_latency_ms_mean'] is not None];mean,sd=statistics.mean(lat),statistics.stdev(lat)
 close(mean,m['trial_latency_ms']['mean'],'mechanism aggregate:latency mean');close(sd,m['trial_latency_ms']['sd'],'mechanism aggregate:latency sd')
 check(mt['Trial latency (ms)'][i]==f'{mean:.1f}$'+BS+'pm$'+f'{sd:.1f} ($n={len(lat)}$)','mechanism table:latency')
for label,cells in mt.items():
 if label not in ['Metric','Candidate records','Trial records','Reject / durable labels','First failed logged $P/U/R$','Direct durable rate','Trial latency (ms)']:check(cells[:3]==[BS+'missing']*3,'mechanism table:missing preserved')
print('Source inventory and all empirical table values pass.',flush=True)
# Every vector-figure observation must originate in the same audited ledger.
evidence=json.loads(gzip.decompress((BASE/'vector_figure_evidence_20260929.json.gz').read_bytes()))
check(evidence['ledger_sha256']==sha(BASE/'filled_run_evidence_20260929.json'),'figure evidence:ledger hash')
by_source={r['source_rel']:r for r in runs};core=[r for r in runs if r['arm'] in list('ABCDE')]
check(len(core)==465 and len(evidence['runs'])==465,'counts:main archives')
for r in evidence['runs']:
 for k in ['coverage','episode_data','source_rel','arm','target','archive_sha256','model_calls','prompt_tokens','completion_tokens']:check(r[k]==by_source[r['source_rel']][k],'figure evidence:'+k)
trajectory=defaultdict(list)
for row in csvrows('coverage_trajectory_values.csv'):trajectory[row['arm']+'|'+row['target']].append(row)
for key,rows in trajectory.items():
 rs=groups[key];grid=np.arange(289)/12
 matrix=np.array([np.interp(grid,np.array(r['coverage'])[:,0],np.array(r['coverage'])[:,1],left=np.nan,right=np.nan) for r in rs])
 check(len(rows)==289,'trajectory:grid count')
 for j,row in enumerate(rows):
  vals=matrix[:,j];vals=vals[np.isfinite(vals)];close(row['hour'],grid[j],'trajectory:hour')
  check(int(row['n_observed'])==len(vals) and int(row['n_archives'])==len(rs) and int(row['N_nominal'])==10,'trajectory:denominators')
  if len(vals):
   for field,v in zip(['q25','median','q75'],np.quantile(vals,[.25,.5,.75])):close(row[field],v,'trajectory:'+field)
  else:check(all(row[f]=='' for f in ['q25','median','q75']),'trajectory:unsupported blanks')
for mode in ['token','call']:
 rows=csvrows(mode+'_cost_coverage_values.csv');check(len(rows)==371,'cost figure:observations')
 check(len({x['source_rel'] for x in rows})==371,'cost figure:unique observations')
 for row in rows:
  r=by_source[row['source_rel']]
  close(row['usage'],r['prompt_tokens']+r['completion_tokens'] if mode=='token' else r['model_calls'],'cost figure:usage')
  close(row['branches'],r['summary']['b_abs'],'cost figure:branches');close(row['runtime_min'],r['summary']['runtime_min'],'cost figure:duration')
  check(row['target']==r['target'] and row['arm']==r['arm'],'cost figure:group')
for row in csvrows('candidate_disposition_values.csv'):
 arm=row['arm'];m=mechanisms[arm]
 for k in ['candidates','trials']:check(int(row[k])==m[k],'disposition figure:'+k)
 for k in ['reject','durable']:check(int(row[k])==m['dispositions'].get(k,0),'disposition figure:'+k)
 check(int(row['unmatched'])==m['unmatched_candidates'],'disposition figure:unmatched')
 for k in 'pur':check(int(row[k+'_first_fail'])==m['first_failed_logged_predicate'].get(k+'_pass',0),'disposition figure:first flags')
 check(int(row['pur_all_pass'])==m['first_failed_logged_predicate'].get('pass_all',0),'disposition figure:all pass')
native=load(FIG/'native_endpoints_evidence.json');check(native['source_sha256']==sha(BASE/native['source']),'native figure:source hash');check(len(native['values'])==12,'native figure:12 metric points')
for row in native['values']:
 for k in ['n','mean','sd','min','max']:close(row[k],derived[row['arm']+'|'+row['target']][row['metric']][k],'native figure:'+k)
print('Trajectory points, cost markers, native endpoints, and event figures pass.',flush=True)
# Independently recompute reliability and 2,000 whole-run bootstrap draws.
fields=evidence['episode_fields'];metrics={m['target']:m for m in csvrows('reliability_metrics.csv')}
bins=csvrows('reliability_bins.csv');audits={a['target']:a for a in load(FIG/'episode_audit.json')}
cal=table((FIG/'logged_calibration_table.tex').read_text(),'tab:logged_calibration')
logged=zero=positive=discontinuities=0
for ti,(target,name) in enumerate(names.items()):
 rs=groups['E|'+target];p=[];y=[];baseline=[];cl=[];disc=0;z=0;logcount=0
 for ri,r in enumerate(rs):
  successes=seen=0;prev={};ids=set();previous_time=-math.inf
  for raw in r['episode_data']:
   e=dict(zip(fields,raw));logcount+=1;a,b,prob,reward=e['alpha_before'],e['beta_before'],e['posterior_mean_before'],e['reward']
   check(math.isfinite(prob) and 0<=prob<=1 and a>0 and b>0 and reward in [0,1],'reliability:valid event')
   close(prob,a/(a+b),'reliability:Beta mean');check(reward==int(e['new_code_edges']>0),'reliability:logged reward')
   check(e['episode_id'] not in ids and e['time_ms']>=previous_time,'reliability:unique ordered events')
   ids.add(e['episode_id']);previous_time=e['time_ms']
   close(e['alpha_after'],1+.995*(a-1)+reward,'reliability:alpha update');close(e['beta_after'],1+.995*(b-1)+1-reward,'reliability:beta update')
   state=e['selected_state']
   if state in prev and max(abs(a-prev[state][0]),abs(b-prev[state][1]))>1e-9:disc+=1
   prev[state]=(e['alpha_after'],e['beta_after'])
   if e['mutations']==0:z+=1;continue
   check(e['mutations']>0,'reliability:positive mutations')
   p.append(prob);y.append(reward);baseline.append((1+successes)/(2+seen));cl.append(ri);successes+=reward;seen+=1
 p=np.array(p);y=np.array(y);baseline=np.array(baseline);cl=np.array(cl);idx=np.minimum((10*p).astype(int),9)
 counts=np.array([np.bincount(idx[cl==ri],minlength=10) for ri in range(len(rs))])
 ps=np.array([np.bincount(idx[cl==ri],weights=p[cl==ri],minlength=10) for ri in range(len(rs))])
 ys=np.array([np.bincount(idx[cl==ri],weights=y[cl==ri],minlength=10) for ri in range(len(rs))])
 br=np.array([np.sum((p[cl==ri]-y[cl==ri])**2) for ri in range(len(rs))]);ref=np.array([np.sum((baseline[cl==ri]-y[cl==ri])**2) for ri in range(len(rs))])
 # AP uses decreasing distinct thresholds; all equal scores share a threshold.
 scores=np.unique(p)[::-1];threshold_index=np.searchsorted(-scores,-p)
 tp_counts=np.zeros((len(rs),len(scores)));all_counts=np.zeros_like(tp_counts)
 for ri in range(len(rs)):
  mask=cl==ri;tp_counts[ri]=np.bincount(threshold_index[mask],weights=y[mask],minlength=len(scores));all_counts[ri]=np.bincount(threshold_index[mask],minlength=len(scores))
 def ap(draws):
  positives=draws@tp_counts;total=np.cumsum(draws@all_counts,axis=1);tp=np.cumsum(positives,axis=1)
  precision=np.divide(tp,total,out=np.zeros_like(tp),where=total>0)
  return np.sum(positives*precision,axis=1)/tp[:,-1]
 points={'brier':float(np.mean((p-y)**2)),'brier_prequential':float(np.mean((baseline-y)**2)),'ece_10':float(np.sum(np.abs(ys.sum(axis=0)-ps.sum(axis=0)))/len(y)),'auprc_ap':float(ap(np.ones((1,len(rs))))[0])}
 m=metrics[target]
 for k,v in points.items():close(m[k],v,'reliability metric:'+k)
 check(int(m['n_runs'])==len(rs) and int(m['episodes'])==len(y) and int(m['positive_rewards'])==int(y.sum()),'reliability:counts')
 rng=np.random.default_rng(20260929+ti);draws=rng.multinomial(len(rs),np.ones(len(rs))/len(rs),size=2000)
 bn=draws@counts;by=draws@ys;bp=draws@ps
 boot={'brier':draws@br/bn.sum(axis=1),'brier_prequential':draws@ref/bn.sum(axis=1),'ece_10':np.sum(abs(by-bp),axis=1)/bn.sum(axis=1),'auprc_ap':np.concatenate([ap(chunk) for chunk in np.array_split(draws,20)])}
 for k,vals in boot.items():
  lo,hi=np.quantile(vals[np.isfinite(vals)],[.025,.975]);close(m[k+'_lo'],lo,'bootstrap:'+k+' low');close(m[k+'_hi'],hi,'bootstrap:'+k+' high')
  check(int(m[k+'_valid_bootstraps'])==int(np.isfinite(vals).sum()),'bootstrap:valid samples')
 for j,row in enumerate(x for x in bins if x['target']==target):
  mask=idx==j;n=int(mask.sum());support=int((counts[:,j]>0).sum());check(int(row['episodes'])==n and int(row['contributing_runs'])==support,'reliability bins:counts')
  if n:close(row['mean_prediction'],p[mask].mean(),'reliability bins:prediction');close(row['observed_reward_rate'],y[mask].mean(),'reliability bins:reward')
  else:check(row['mean_prediction']==row['observed_reward_rate']=='','reliability bins:empty')
  if support>=2:
   present=bn[:,j]>0;lo,hi=np.quantile(by[present,j]/bn[present,j],[.025,.975]);close(row['ci_low'],lo,'reliability bins:ci low');close(row['ci_high'],hi,'reliability bins:ci high')
  else:check(row['ci_low']==row['ci_high']=='','reliability bins:unsupported interval')
 check(cal[name][0:2]==[str(len(rs)),f'{len(y):,}'],'calibration table:counts')
 for cell,k in zip(cal[name][2:],['brier','brier_prequential','ece_10','auprc_ap']):
  expected=BS+'shortstack{'+f'{points[k]:.3f}'+ROW+'{'+f'[{float(m[k+"_lo"]):.3f}, {float(m[k+"_hi"]):.3f}]'+'}}';check(cell==expected,'calibration table:'+k)
 check(audits[target]['logged']==logcount and audits[target]['included']==len(y) and audits[target]['zero_mutation_excluded']==z and audits[target].get('posterior_discontinuities',0)==disc,'reliability:audit consistency')
 logged+=logcount;zero+=z;positive+=len(y);discontinuities+=disc
 print('Reliability/bootstrap pass:',target,flush=True)
check((logged,zero,positive,discontinuities)==(31826,6070,25756,3),'counts:episode totals')
selection=load(FIG/'posterior_case_selection.json');posterior=csvrows('posterior_case_values.csv');expected_keys=set()
for item in selection:
 rs=sorted(groups['E|'+item['target']],key=lambda r:(float(r['summary']['b_abs']),r['source_rel']));r=rs[(len(rs)-1)//2];events=[dict(zip(fields,e)) for e in r['episode_data']]
 states=Counter(e['selected_state'] for e in events if e['mutations']>0);states=sorted(states,key=lambda s:(-states[s],s))[:2]
 check(item['source_rel']==r['source_rel'] and item['states']==states,'posterior:selection')
 for e in events:
  if e['selected_state'] in states:expected_keys.add((r['source_rel'],e['episode_id']))
for row in posterior:
 r=by_source[row['source_rel']];e=next(dict(zip(fields,x)) for x in r['episode_data'] if x[0]==int(row['episode_id']))
 for k,v in {'state':e['selected_state'],'hour_episode_end':(e['time_ms']/1000-r['fuzzer_start_time'])/3600,'pre_update_probability':e['posterior_mean_before'],'logged_reward':e['reward'],'mutations':e['mutations']}.items():close(row[k],v,'posterior:'+k)
 if e['frontier_score']>0:close(row['score_multiplier'],e['final_selection_score']/e['frontier_score'],'posterior:score')
 else:check(row['score_multiplier']=='','posterior:undefined score')
check({(r['source_rel'],int(r['episode_id'])) for r in posterior}==expected_keys and len(posterior)==len(expected_keys),'posterior:all selected events')
figures=['native_endpoints','coverage_trajectories','logged_reward_reliability','candidate_dispositions','token_cost_coverage','call_cost_coverage','posterior_cases']
for name in figures:
 check('revision_20260920/figures_updated_20260929/'+name+'.pdf' in tex,'vector:included '+name)
 check(not ET.parse(FIG/(name+'.svg')).findall('.//{http://www.w3.org/2000/svg}image'),'vector:SVG no bitmap')
 images=subprocess.check_output(['pdfimages','-list',str(FIG/(name+'.pdf'))],text=True);check(len(images.strip().splitlines())==2,'vector:PDF no bitmap')
log=(BASE/'main.revised.log').read_text()
for bad in ['! LaTeX Error','Overfull '+BS+'hbox','Float too large','Undefined','undefined citations','undefined references','Missing $']:check(bad not in log,'build:'+bad)
check(not re.search(r'Citation .+ undefined|Reference .+ undefined',log),'build:all references defined')
bbl=(BASE/'main.revised.bbl').read_text();bib=(BASE/'references.verified_20260928.bib').read_text()
cited=set(k.strip() for part in re.findall(r'\\cite\w*\{([^}]+)\}',tex) for k in part.split(','))
bblkeys=set(re.findall(r'\\bibitem(?:\[[^\]]*\])?\{([^}]+)\}',bbl));bibkeys=set(re.findall(r'@\w+\s*\{\s*([^,]+),',bib))
check(cited<=bblkeys<=bibkeys and len(bblkeys)==25,'bibliography:25 resolved entries')
pdftext=subprocess.check_output(['pdftotext','-layout',str(BASE/'main.revised.pdf'),'-'],text=True)
check('References' in pdftext and 'Appendix Appendix' not in pdftext,'PDF:text and appendix label')
images=subprocess.check_output(['pdfimages','-list',str(BASE/'main.revised.pdf')],text=True);check(len(images.strip().splitlines())==2,'PDF:no raster images')
for old in ['native_endpoints_filled.pdf','figures_reflow_20260928','observed_tables.tex','observed_costs.tex','two small gamma sensitivity','other missing target--arm combinations remain omitted']:check(old not in tex,'prose:obsolete reference removed')
check('All 104 benchmark LoopFuzz D summaries are labeled completed' in tex and '52 to 248' in tex,'prose:status and call range')
check('all 45 main target--arm combinations are represented' in tex,'prose:main inventory')
check(sum(any(b[1]<a[1] for a,b in zip(r['coverage'],r['coverage'][1:])) for r in core)==127,'prose:trajectory decreases')
report={'status':'PASS','verified_at':datetime.datetime.now().astimezone().isoformat(),'data_snapshot':'2026-09-29','archives':len(runs),'archive_groups':len(groups),'core_figure_archives':len(core),'main_table_cells':45,'appendix_rows':61,'vector_figures':len(figures),'raster_images':0,'bibliography_entries':len(bblkeys),'cost_observations':371,'reliability_logged':logged,'reliability_zero_mutation_excluded':zero,'reliability_included':positive,'independent_bootstrap_replicates_per_target':2000,'numeric_and_structural_checks':dict(checks),'pages':int(re.search(r'Pages:\s+(\d+)',subprocess.check_output(['pdfinfo',str(BASE/'main.revised.pdf')],text=True)).group(1)),'source_integrity':'Fresh inventory, all 43 summary SHA-256 values, and 628 archive size/mtime checks; archive SHA-256 recorded at extraction.','limitations':['No new experiment execution or vulnerability replay','No imputation for missing runs','Archive observations do not establish matched-horizon causal effects'],'output_sha256':{p.name:sha(p) for p in [BASE/'main.revised.tex',BASE/'main.revised.pdf',BASE/'filled_run_evidence_20260929.json',BASE/'filled_experiment_data_20260929.json',BASE/'filled_mechanism_data_20260929.json',BASE/'vector_figure_evidence_20260929.json.gz']}}
(BASE/'data_update_validation_20260929.json').write_text(json.dumps(report,indent=2)+chr(10))
print(json.dumps({k:v for k,v in report.items() if k not in ['numeric_and_structural_checks','output_sha256']},indent=2));print('Checks:',sum(checks.values()))
