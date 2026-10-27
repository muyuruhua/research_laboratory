from pathlib import Path
import tarfile,json,collections,re,statistics,sys,argparse,hashlib
parser=argparse.ArgumentParser(description='Read exact complete archives; never change input data.')
parser.add_argument('--root',type=Path,default=Path('/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master'))
parser.add_argument('--output',type=Path,default=Path('/tmp/bftpd150457_provisional'))
args=parser.parse_args()
BASE=args.root/'ablation'
OUT=args.output
OUT.mkdir(parents=True,exist_ok=True)

def asnum(s):
 try:return int(s)
 except ValueError:
  try:return float(s)
  except ValueError:return s

def audit(p):
 with tarfile.open(p) as tar:
  names={m.name:m for m in tar.getmembers()}
  prefix='out-bftpd-loopfuzz/'
  errs=[]
  def js(fn):
   if prefix+fn not in names:return []
   vals=[]
   for i,l in enumerate(tar.extractfile(names[prefix+fn]),1):
    try:vals.append(json.loads(l))
    except Exception as e:errs.append([fn,i,str(e)])
   return vals
  stats={}
  for line in tar.extractfile(names[prefix+'fuzzer_stats']).read().decode().splitlines():
   if ':' in line:
    k,v=line.split(':',1);stats[k.strip()]=asnum(v.strip())
  cfg=js('run-config.jsonl');provs=js('provisional-events.jsonl');adm=js('admission-events.jsonl');cand=js('candidate-events.jsonl');exe=js('execution-events.jsonl');lin=js('lineage-events.jsonl');shadow=js('shadow-events.jsonl')
  provgroups=collections.defaultdict(list)
  for x in provs:provgroups[(x.get('campaign_id'),x['candidate_id'],x['queue_entry'])].append(x)
  candgroups=collections.defaultdict(list)
  for x in cand:candgroups[(x.get('campaign_id'),x['candidate_id'])].append(x)
  trials=[x for x in adm if x['event']=='admission_trial']
  dec=[x for x in adm if x['event']=='admission_decision']
  trialgroups=collections.defaultdict(list)
  for x in trials:trialgroups[(x.get('campaign_id'),x['candidate_id'])].append(x)
  ends=[x for x in exe if x['event']=='invocation_end']
  starts={ (x['campaign_id'],x['invocation_id']):x for x in exe if x['event']=='invocation_start'}
  exe_counts=collections.Counter();exe_elapsed=collections.Counter();by_candidate=collections.defaultdict(lambda:collections.Counter());elapsed_candidate=collections.Counter()
  for x in ends:
   cat='llm_ancestry' if x['candidate_id'] else 'ordinary_ancestry'
   kind=x['execution_kind'];exe_counts[(cat,kind)]+=1
   by_candidate[(x['campaign_id'],x['candidate_id'])][kind]+=1
   st=starts.get((x['campaign_id'],x['invocation_id']))
   if st:
    dt=x['monotonic_ms']-st['monotonic_ms'];exe_elapsed[(cat,kind)]+=dt;elapsed_candidate[(x['campaign_id'],x['candidate_id'])]+=dt
  pg=[]
  for key,vals in provgroups.items():
   ad=[x for x in vals if x['kind']=='admit'];cl=[x for x in vals if x['kind']!='admit'];last=vals[-1]
   tr=trialgroups.get(key[:2],[])
   pg.append({'campaign_id':key[0],'candidate_id':key[1],'queue_entry':key[2],'admit_reason':ad[0].get('reason') if ad else None,'events':[x['kind'] for x in vals],'close_reason':cl[-1].get('reason') if cl else None,'descendant_execs':last['descendant_execs'],'descendant_code_gain':last['descendant_code_gain'],'budget_left':last['budget_left'],'age_ms':last['time_ms']-ad[0]['time_ms'] if ad else None,'overdue_ms':last['overdue_ms'],'candidate_trials':len(tr),'trial_dispositions':[x.get('disposition') for x in tr],'trial_g_code':[x.get('g_code_pass') for x in tr],'trial_u_pass':[x.get('u_pass') for x in tr],'ledger_counts':dict(by_candidate[key[:2]]),'ledger_elapsed_ms':elapsed_candidate[key[:2]]})
  gains=[x for x in lin if x['event']=='lineage_gain']
  linked=[]
  for x in gains:
   cid=(x.get('campaign_id'),x['candidate_id']);ts=trialgroups.get(cid,[])
   linked.append({k:x.get(k) for k in ['campaign_id','candidate_id','queue_entry','invocation_id','execution_kind','parent_queue_id','time_ms']}|{'trials':[{'disposition':z.get('disposition'),'native_promoted':z.get('native_promoted'),'g_code_pass':z.get('g_code_pass'),'trial_invocation_id':z.get('trial_invocation_id')} for z in ts]})
  qnames=[n[len(prefix+'queue/'):] for n in names if n.startswith(prefix+'queue/id')]
  queuecov=[x for x in qnames if '+cov' in x]
  end_keys=collections.Counter((x['campaign_id'],x['invocation_id']) for x in ends)
  start_keys=collections.Counter((x['campaign_id'],x['invocation_id']) for x in exe if x['event']=='invocation_start')
  return {'archive':str(p),'archive_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'arm':p.parent.name.split('_ablation_')[1].split('_2026')[0],'replicate':int(re.search(r'_(\d+)\.tar\.gz$',p.name).group(1)), 'json_parse_errors':errs,'file_counts':{'run_config':len(cfg),'provisional':len(provs),'admission':len(adm),'candidate':len(cand),'execution':len(exe),'lineage':len(lin),'shadow':len(shadow)},'config':[{k:x.get(k) for k in ['phase','campaign_id','start_time_ms','end_time_ms','termination_reason','calibration','provisional_enabled','shadow_enabled','salvage_enabled','no_admission','rng_fixed','fuzzer_commit','fuzzer_sha256']} for x in cfg],'stats':stats,'provisional_lifecycles':pg,'provisional_kinds':dict(collections.Counter(x['kind'] for x in provs)),'provisional_reasons':dict(collections.Counter(x.get('reason') for x in provs)),'candidate_duplicate_ids':{str(k):len(v) for k,v in candgroups.items() if len(v)>1},'trial_duplicate_ids':{str(k):len(v) for k,v in trialgroups.items() if len(v)>1},'execution_duplicate_start_ids':sum(v-1 for v in start_keys.values()),'execution_duplicate_end_ids':sum(v-1 for v in end_keys.values()),'execution_unpaired_starts':len(start_keys.keys()-end_keys.keys()),'execution_unpaired_ends':len(end_keys.keys()-start_keys.keys()),'trials':len(trials),'decisions':len(dec),'trial_dispositions':dict(collections.Counter(x.get('disposition') for x in trials)),'trial_disposition_reasons':dict(collections.Counter(x.get('disposition_reason') for x in trials)),'trial_g_code_positive':sum(bool(x.get('g_code_pass')) for x in trials),'trial_provisional_flag':sum(bool(x.get('provisional_queued')) for x in trials),'trial_code_delta_sum':sum(x.get('bitmap_delta',0) for x in trials),'execution_counts':{'/'.join(k):v for k,v in exe_counts.items()},'execution_elapsed_ms':{'/'.join(k):v for k,v in exe_elapsed.items()},'lineage_gain_events':linked,'lineage_other_events':dict(collections.Counter(x['event'] for x in lin if x['event']!='lineage_gain')),'queue_count':len(qnames),'queue_cov_count':len(queuecov),'shadow_events':[{k:v for k,v in x.items() if k not in ['request_first_line','request_path','state_sequence','edge_sequence']} for x in shadow]}

rows=[]
for arm in ['wrapdirect8','wrapgate8','salvage8']:
 for p in sorted((BASE/f'results-bftpd_ablation_{arm}_20261027T150457').glob('out-bftpd-loopfuzz_[123].tar.gz')):
  rows.append(audit(p))
assert len(rows)==9, f'Expected nine complete archives, found {len(rows)}'
OUT.joinpath('audit.json').write_text(json.dumps(rows,indent=2))
summary={}
for arm in ['wrapdirect8','wrapgate8','salvage8']:
 subset=[x for x in rows if x['arm']==arm]
 def counterfield(field):
  c=collections.Counter()
  for x in subset:c.update(x[field])
  return dict(c)
 summary[arm]={'n':len(subset),'trials':sum(x['trials'] for x in subset),'dispositions':counterfield('trial_dispositions'),'provisional_kinds':counterfield('provisional_kinds'),'provisional_reasons':counterfield('provisional_reasons'),'execution_counts':counterfield('execution_counts'),'execution_elapsed_ms':counterfield('execution_elapsed_ms'),'lineage_gain_events':sum(len(x['lineage_gain_events']) for x in subset),'provisional_descendant_execs':sum(z['descendant_execs'] for x in subset for z in x['provisional_lifecycles']),'provisional_descendant_code_gain':sum(z['descendant_code_gain'] for x in subset for z in x['provisional_lifecycles']),'shadow_validations':sum(len(x['shadow_events']) for x in subset),'shadow_positive_candidates':sum(bool(z.get('would_have_found_edges')) for x in subset for z in x['shadow_events']),'shadow_hnb2_invocations':sum(z.get('shadow_new_edges',0) for x in subset for z in x['shadow_events']),'code_gain_events':sum(x['stats'].get('code_gain_events',0) for x in subset),'salvage_attempts':sum(x['stats'].get('salvage_attempted',0) for x in subset),'salvage_successful_admissions':sum(x['stats'].get('salvage_succeeded',0) for x in subset)}
summary['_semantics']={'ancestry':'candidate_id 0 means no tracked LLM candidate ancestry; it can still include initially enriched seeds.','code_gain_events':'native hnb==2 new-edge SAVE EVENTS, not a count of unique source-code branches','shadow_hnb2_invocations':'In local source, shadow_new_edges counts shadow invocations with last_trial_hnb==2. The virgin bitmap is not updated, so the same unseen bitmap edge may count repeatedly. This is not unique edges, source branches, provisional conversion, or durable retention.','provisional':'all observed lifecycles terminate without validation execution because no-executable-M2; zero conversions is structural, not 64-call negative validation evidence.'}
summary['_validation']={'campaign_id_collisions':dict(collections.Counter(x['config'][0]['campaign_id'] for x in rows)),'json_parse_errors':sum(len(x['json_parse_errors']) for x in rows),'candidate_duplicate_keys':sum(len(x['candidate_duplicate_ids']) for x in rows),'trial_duplicate_keys':sum(len(x['trial_duplicate_ids']) for x in rows),'execution_duplicate_start_ids':sum(x['execution_duplicate_start_ids'] for x in rows),'execution_duplicate_end_ids':sum(x['execution_duplicate_end_ids'] for x in rows),'execution_unpaired_starts':sum(x['execution_unpaired_starts'] for x in rows),'execution_unpaired_ends':sum(x['execution_unpaired_ends'] for x in rows)}
OUT.joinpath('summary.json').write_text(json.dumps(summary,indent=2))
for x in rows:
 s=x['stats'];print(x['arm'],x['replicate'],'trials',x['trials'],x['trial_dispositions'],'prov',x['provisional_kinds'],x['provisional_reasons'],'lineage_gain',len(x['lineage_gain_events']),'statsgain',s.get('llm_lineage_edge_gains'),'codegain',s.get('code_gain_events'))
 print(' exec',x['execution_counts'])
 print(' prov',x['provisional_lifecycles'])
 print('duplicate candidates',x['candidate_duplicate_ids'],'trials',x['trial_duplicate_ids'])
