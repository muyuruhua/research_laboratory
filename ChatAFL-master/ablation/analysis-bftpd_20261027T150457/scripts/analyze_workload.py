#!/usr/bin/env python3
"""Read only exact .tar.gz artifacts; never display prompts or credentials."""
import collections as C
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import tarfile

ROOT=Path('/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master')
OUT=Path('/tmp/bftpd150457_workload')
STAMP='20261027T150457'

def dist(items): return dict(C.Counter(items))
def parse_stats(data):
    ret={}
    for line in data.decode().splitlines():
        if ':' in line:
            k,v=line.split(':',1);v=v.strip()
            try: v=float(v) if '.' in v else int(v)
            except ValueError: pass
            ret[k.strip()]=v
    return ret

def union_len(intervals):
    if not intervals:return 0
    intervals=sorted(intervals);a,b=intervals[0];total=0
    for c,d in intervals[1:]:
        if c<=b:b=max(b,d)
        else:total+=b-a;a,b=c,d
    return total+b-a

def summarize(p,arm,run):
    with tarfile.open(p) as t:
        lookup={m.name:m for m in t.getmembers()}
        base='out-bftpd-loopfuzz/'
        def data(name):
            m=lookup.get(base+name)
            return t.extractfile(m).read() if m else b''
        def rows(name):
            b=data(name)
            out=[]
            for i,line in enumerate(b.splitlines(),1):
                if line.strip():
                    try:out.append(json.loads(line))
                    except Exception as e:raise RuntimeError(f'{p}:{name}:{i}: {e}')
            return out
        cfg=rows('run-config.jsonl');stats=parse_stats(data('fuzzer_stats'))
        es=rows('execution-events.jsonl');cs=rows('candidate-events.jsonl')
        ads=rows('admission-events.jsonl');llm=rows('llm-calls.jsonl')
        ls=rows('lineage-events.jsonl');ps=rows('provisional-events.jsonl')
        resets=rows('reset-events.jsonl');qps=rows('queue-checkpoints.jsonl')
        selections=rows('scheduler-selections.jsonl');episodes=rows('state-episodes.jsonl')
        start=next(x for x in cfg if x['phase']=='start');end=next(x for x in cfg if x['phase']=='end')
        starts=[e for e in es if e['event']=='invocation_start']
        ends=[e for e in es if e['event']=='invocation_end']
        refused=[e for e in es if e['event']=='invocation_refused']
        sid={e['invocation_id']:e for e in starts};eid={e['invocation_id']:e for e in ends}
        bykind=C.Counter();byancestry=C.Counter();dur=C.Counter();execdelta=C.Counter();allpercid=C.Counter();mutpercid=C.Counter()
        pairs=[]
        for e in ends:
            a=sid[e['invocation_id']];dt=e['monotonic_ms']-a['monotonic_ms'];pairs.append((a['monotonic_ms'],e['monotonic_ms']))
            cid=e['candidate_id'];anc='llm_lineage' if cid else 'no_tracked_candidate_ancestry'
            bykind[(anc,e['execution_kind'])]+=1;byancestry[anc]+=1
            dur[(anc,e['execution_kind'])]+=dt;execdelta[e['execution_id_after']-e['execution_id_before']]+=1
            if cid:
                allpercid[cid]+=1
                if e['execution_kind']=='mutation':mutpercid[cid]+=1
        gains=C.Counter(e['candidate_id'] for e in ls if e['event']=='lineage_gain')
        trial=[e for e in ads if e['event']=='admission_trial']
        decisions=[e for e in ads if e['event']=='admission_decision']
        adbycid={e['candidate_id']:e for e in trial}
        candidatebreak=[]
        for c in cs:
            cid=c['candidate_id'];ad=adbycid.get(cid,{})
            candidatebreak.append({k:v for k,v in {
                'candidate_id':cid,'source':c.get('source'),'p_pass':c.get('p_pass'),
                'u_pass':ad.get('u_pass'),'g_code_pass':ad.get('g_code_pass'),'g_state_pass':ad.get('g_state_pass'),
                'disposition':ad.get('disposition'),'disposition_reason':ad.get('disposition_reason'),
                'trial_invocation_id':ad.get('trial_invocation_id'),'trial_hnb':ad.get('trial_hnb'),
                'all_invocations':allpercid[cid],'mutation_invocations':mutpercid[cid],
                'lineage_gain_events':gains[cid],
            }.items()}.copy())
        llm_intervals=[(x['time_ms']-x['latency_ms'],x['time_ms']) for x in llm if x.get('status')!='cap-refused']
        firstinv=min(e['time_ms'] for e in starts);lastinv=max(e['time_ms'] for e in ends)
        def llmgroup(a):
            return {'rows':len(a),'statuses':dist(x['status'] for x in a),
                    'prompt_tokens':sum(x.get('prompt_tokens',0) for x in a),
                    'completion_tokens':sum(x.get('completion_tokens',0) for x in a),
                    'latency_sum_ms':sum(x['latency_ms'] for x in a),
                    'latency_union_ms':union_len([(x['time_ms']-x['latency_ms'],x['time_ms']) for x in a]),
                    'unique_seq':len({x['seq'] for x in a})}
        ret={'arm':arm,'run':run,'archive':str(p.relative_to(ROOT)),
            'archive_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
            'campaign_id':start['campaign_id'],
            'effective_config':{k:start.get(k) for k in ('no_admission','admission_mode','provisional_enabled','shadow_enabled','salvage_enabled','calibration','cal_estimator','no_adaptive','rng_fixed','rng_seed','model','max_output_tokens','call_cap','token_cap','llm_total_call_cap','token_cap_enforced','plaintext_wrap_enabled','provisional_budget','provisional_ttl_ms','episode_energy_cap','fuzzer_commit','fuzzer_sha256','target_sha256','seeds_sha256','image_digest')},
            'duration_ms':end['end_time_ms']-start['start_time_ms'],
            'campaign_start_time_ms':start['start_time_ms'],
            'campaign_end_time_ms':end['end_time_ms'],
            'fuzzer_stats_start_time_s':stats.get('start_time'),
            'fuzzer_stats_last_update_s':stats.get('last_update'),
            'fuzzer_stats_span_ms':(stats.get('last_update',0)-stats.get('start_time',0))*1000,
            'pre_first_invocation_ms':firstinv-start['start_time_ms'],
            'execution_span_ms':lastinv-firstinv,
            'starts':len(starts),'ends':len(ends),'refused':len(refused),
            'unique_start_invocations':len(sid),'unique_end_invocations':len(eid),
            'unique_attempt_ids':len({e['attempt_id'] for e in es}),
            'missing_end_ids':sorted(set(sid)-set(eid)),
            'missing_start_ids':sorted(set(eid)-set(sid)),
            'execution_deltas':dict(execdelta),'fuzzer_stats_execs_done':stats.get('execs_done'),
            'invocations_zero_afl_delta':[{k:e[k] for k in ('invocation_id','execution_kind','candidate_id','execution_id_before','execution_id_after','time_ms')} for e in ends if e['execution_id_after']==e['execution_id_before']],
            'executions_by_ancestry':dict(byancestry),
            'executions_by_ancestry_kind':{'/'.join(k):v for k,v in bykind.items()},
            'target_invocation_duration_ms':sum(dur.values()),
            'target_duration_by_ancestry_kind_ms':{'/'.join(k):v for k,v in dur.items()},
            'target_interval_union_ms':union_len(pairs),
            'execution_faults':dist(e['fault'] for e in ends),
            'refused_reasons':dist(e['execution_kind'] for e in refused),
            'reset_events':len(resets),'reset_success':dist(e['success'] for e in resets),
            'llm':llmgroup(llm),
            'llm_before_first_invocation':llmgroup([e for e in llm if e['time_ms']<=firstinv]),
            'llm_after_first_invocation':llmgroup([e for e in llm if e['time_ms']>firstinv]),
            'llm_models':dist((e['model_requested']+' => '+e['model_served']) for e in llm),
            'llm_cumulative_tokens_last':llm[-1]['cum_tokens'] if llm else 0,
            'llm_cumulative_tokens_max':max((x['cum_tokens'] for x in llm),default=0),
            'llm_cumulative_calls_last':llm[-1]['cum_calls'] if llm else 0,
            'scheduler_selections':len(selections),
            'scheduler_selection_reasons':dist(e['reason'] for e in selections),
            'state_episodes':len(episodes),
            'posterior_updated_episodes':sum(e['posterior_updated'] for e in episodes),
            'episode_sampled_theta_values':sorted({e['sampled_theta'] for e in episodes}),
            'llm_archive_req_count':sum(m.name.startswith(base+'llm-archive/') and m.name.endswith('.req') for m in lookup.values()),
            'candidates':len(cs),'unique_candidate_ids':len({e['candidate_id'] for e in cs}),
            'candidate_source':dist(e['source'] for e in cs),
            'admission_trials':len(trial),'decisions':len(decisions),
            'decision_intended_disposition':dist(e.get('intended_disposition') for e in decisions),
            'trial_disposition':dist(e.get('disposition') for e in trial),
            'trial_disposition_reason':dist(e.get('disposition_reason') for e in trial),
            'trial_g_code_pass':sum(e.get('g_code_pass',False) for e in trial),
            'trial_u_pass':sum(e.get('u_pass',False) for e in trial),
            'trial_bitmap_delta_sum':sum(e.get('bitmap_delta',0) for e in trial),
            'lineage_gain_events':len(ls),'unique_productive_candidates':len(gains),
            'provisional_events':len(ps),'provisional_kinds':dist(e['kind'] for e in ps),
            'provisional_reasons':dist(e.get('reason') for e in ps),
            'candidates_with_desc_mutations':sum(mutpercid[c['candidate_id']]>0 for c in cs),
            'llm_mutation_executions_zero_gain_lineages':sum(n for cid,n in mutpercid.items() if gains[cid]==0),
            'queue_checkpoints':len(qps),'llm_queue_checkpoints':sum(bool(e.get('candidate_id')) for e in qps),
            'selected_fuzzer_stats':{k:v for k,v in stats.items() if any(s in k for s in ('admission','provisional','salvage','shadow','llm','code_edges','paths_total','cal_','total_mutation'))},
            'candidate_breakdown':candidatebreak,
        }
        # A nonzero ancestry pin must refer to a candidate in this campaign.
        ret['orphan_lineage_candidate_ids']=sorted(set(allpercid)-{c['candidate_id'] for c in cs})
        return ret

def main():
    global ROOT,OUT
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT,help='ChatAFL-master repository root; raw archives read only')
    parser.add_argument('--output',type=Path,default=OUT,help='Directory for sanitized JSON outputs')
    args=parser.parse_args()
    ROOT=args.root.resolve();OUT=args.output.resolve();OUT.mkdir(parents=True,exist_ok=True)
    runs=[]
    for arm in ('wrapdirect8','wrapgate8','salvage8'):
        for run in range(1,4):
            p=ROOT/'ablation'/f'results-bftpd_ablation_{arm}_{STAMP}'/f'out-bftpd-loopfuzz_{run}.tar.gz'
            runs.append(summarize(p,arm,run))
    (OUT/'workload.json').write_text(json.dumps(runs,indent=2)+'\n')
    for r in runs:
        print(r['arm'],r['run'],'exec',r['ends'],r['executions_by_ancestry'],'gains',r['lineage_gain_events'],'candidates',r['candidates'],'disposition',r['trial_disposition'],'mut-nogain',r['llm_mutation_executions_zero_gain_lineages'],'llm',r['llm'],'prov',r['provisional_kinds'])
    aggregates=[]
    for arm in ('wrapdirect8','wrapgate8','salvage8'):
        rs=[r for r in runs if r['arm']==arm]
        a={'arm':arm,'runs':len(rs)}
        for name in ('ends','candidates','lineage_gain_events','llm_mutation_executions_zero_gain_lineages','pre_first_invocation_ms','target_invocation_duration_ms','duration_ms'):
            v=[r[name] for r in rs];a[name]={'sum':sum(v),'mean':statistics.mean(v),'min':min(v),'max':max(v)}
        for name in ('executions_by_ancestry_kind','trial_disposition','decision_intended_disposition','provisional_kinds'):
            co=C.Counter()
            for r in rs:co.update(r[name])
            a[name]=dict(co)
        a['llm_statuses']=dict(sum((C.Counter(r['llm']['statuses']) for r in rs),C.Counter()))
        a['llm_rows']=sum(r['llm']['rows'] for r in rs)
        a['llm_tokens']=sum(r['llm']['prompt_tokens']+r['llm']['completion_tokens'] for r in rs)
        a['llm_latency_ms']=sum(r['llm']['latency_sum_ms'] for r in rs)
        aggregates.append(a)
    (OUT/'aggregate.json').write_text(json.dumps(aggregates,indent=2)+'\n')

if __name__=='__main__':main()
