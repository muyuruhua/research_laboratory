#!/usr/bin/env python3
"""Reconcile three independent read-only audits; emit tables, manifest and figure."""
import argparse
import collections
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import statistics

ARMS = ('wrapdirect8', 'wrapgate8', 'salvage8')
BATCH = '20261027T150457'


def read(path):
    return json.loads(path.read_text())


def write(path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def count(d, suffix):
    return d.get('llm_lineage/' + suffix, 0)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    root, out = args.root.resolve(), args.output.resolve()
    work = read(out/'data/workload/workload.json')
    prov = read(out/'data/provisional/audit.json')
    cov = read(out/'data/coverage/coverage.json')
    ps = read(out/'data/provisional/summary.json')
    pd = {(r['arm'], r['replicate']): r for r in prov}
    cd = {(r['arm'], r['run']): r for r in cov['runs']}
    assert len(work) == len(prov) == len(cd) == 9
    rows, manifest = [], []
    for w in work:
        a, n = w['arm'], w['run']
        v, c = pd[a,n], cd[a,n]
        archive = root / w['archive']
        sha = digest(archive)
        assert sha == w['archive_sha256'] == v['archive_sha256'] == c['archive_sha256']
        assert w['campaign_id'] == c['campaign_id'] == v['config'][0]['campaign_id']
        assert w['candidates'] == w['unique_candidate_ids'] == v['trials']
        assert w['fuzzer_stats_execs_done'] == c['execs_done'] == int(w['execution_deltas'].get('1',0))
        assert sum(int(k)*n for k,n in w['execution_deltas'].items()) == c['execs_done']
        assert w['starts'] == w['ends'] and not w['missing_end_ids'] and not w['missing_start_ids']
        assert not w['orphan_lineage_candidate_ids'] and not v['json_parse_errors']
        assert not v['candidate_duplicate_ids'] and not v['trial_duplicate_ids']
        assert not v['execution_duplicate_start_ids'] and not v['execution_duplicate_end_ids']
        assert not v['execution_unpaired_starts'] and not v['execution_unpaired_ends']
        assert w['effective_config']['calibration'] is False
        statusfile = archive.parent/'.sample_status'/(archive.name+'.status')
        status = dict(l.split('=',1) for l in statusfile.read_text().splitlines() if '=' in l)
        assert status['status'] == 'completed' and status['exit_code'] == '0'
        starts = w['target_duration_by_ancestry_kind_ms']
        counts = w['executions_by_ancestry_kind']
        life = v['provisional_lifecycles']
        assert all(x['close_reason'] == 'no-executable-M2' and x['descendant_execs'] == 0
                   and x['budget_left'] == 64 for x in life)
        r = dict(arm=a, run=n, campaign_id=w['campaign_id'],
            duration_minutes=w['duration_ms']/60000, pre_first_invocation_minutes=w['pre_first_invocation_ms']/60000,
            afl_executions=c['execs_done'], admitted_invocations=w['ends'],
            shutdown_zero_delta_invocations=int(w['execution_deltas'].get('0',0)),
            candidates=w['candidates'], durable=w['trial_disposition'].get('durable',0),
            provisional=w['trial_disposition'].get('provisional',0), rejected=w['trial_disposition'].get('reject',0),
            llm_descendant_mutations=count(counts,'mutation'), llm_descendant_seed_calibrations=count(counts,'calibration'),
            llm_descendant_invocation_seconds=(count(starts,'mutation')+count(starts,'calibration'))/1000,
            shadow_invocations=count(counts,'shadow'), shadow_invocation_seconds=count(starts,'shadow')/1000,
            llm_trial_invocation_seconds=count(starts,'candidate')/1000,
            llm_related_invocation_seconds=sum(val for k,val in starts.items() if k.startswith('llm_lineage/'))/1000,
            untracked_candidate_ancestry_mutation_invocations=counts.get('no_tracked_candidate_ancestry/mutation',0),
            provisional_serviced_descendant_execs=sum(x['descendant_execs'] for x in life),
            provisional_conversions=v['provisional_kinds'].get('convert',0),
            lineage_gain_events=len(v['lineage_gain_events']),
            native_new_edge_save_events=v['stats']['code_gain_events'],
            shadow_candidates=len(v['shadow_events']), shadow_positive_candidates=sum(bool(x['would_have_found_edges']) for x in v['shadow_events']),
            llm_records=w['llm']['rows'], llm_ok=w['llm']['statuses'].get('ok',0),
            llm_transport_errors=w['llm']['statuses'].get('transport-error',0), llm_api_errors=w['llm']['statuses'].get('api-error',0),
            reported_tokens=w['llm']['prompt_tokens']+w['llm']['completion_tokens'],
            llm_latency_sum_seconds=w['llm']['latency_sum_ms']/1000,
            llm_latency_interval_union_seconds=w['llm']['latency_union_ms']/1000,
            measured_replay_branches_INCOMPLETE=c['terminal_branches'], measured_replay_lines_INCOMPLETE=c['terminal_lines'],
            replay_inputs=c['n_replayed'], replay_missing_gcda=c['session_coverage_missing'],
            replay_missing_gcda_fraction=c['session_coverage_missing_fraction'],
            authenticated_replays_missing_gcda=c['replay_log_login_gcda_cross_tab'].get('authenticated_missing_gcda',0),
            scheduler_selections=w['scheduler_selections'], warmup_selections=w['scheduler_selection_reasons'].get('warmup-eligible',0),
            passive_posterior_updated_episodes=w['posterior_updated_episodes'])
        rows.append(r)
        manifest.append(dict(archive=w['archive'], sha256=sha, bytes=archive.stat().st_size,
            status=status, status_relative_path=str(statusfile.relative_to(root)),
            excluded_incomplete_siblings=[x.name for x in sorted(archive.parent.glob(archive.name+'.incomplete.*'))],
            campaign_id=w['campaign_id'], effective_config=w['effective_config']))
        manifest[-1]['initial_ordered_input_hash_list_sha256'] = c['initial_ordered_input_hash_list_sha256']
        manifest[-1]['initial_input_hash_multiset_sha256'] = c['initial_input_hash_multiset_sha256']
        manifest[-1]['initial_inputs'] = c['initial_queue_checkpoint_count']
    arms = {}
    for a in ARMS:
        rs = [x for x in rows if x['arm']==a]
        total = {k:sum(x[k] for x in rs) for k in rs[0] if k not in ('arm','run','campaign_id')}
        # Fractions and clocks should not be interpreted as additive per-arm effects.
        total.pop('replay_missing_gcda_fraction')
        arms[a] = dict(n=3, totals=total, raw_afl_executions=[x['afl_executions'] for x in rs],
            mean_afl_executions=statistics.mean(x['afl_executions'] for x in rs),
            sd_afl_executions=statistics.stdev(x['afl_executions'] for x in rs),
            replay_missing_gcda_fraction=total['replay_missing_gcda']/total['replay_inputs'],
            shadow_hnb2_positive_invocations=ps[a]['shadow_hnb2_invocations'])
    direct = arms['wrapdirect8']['mean_afl_executions']
    for a in ARMS:
        arms[a]['descriptive_execution_change_vs_direct_pct']=100*(arms[a]['mean_afl_executions']/direct-1)
    reference_sources = ('LoopFuzz/afl-fuzz.c','benchmark/scripts/analysis/coverage_v4.py',
                         'benchmark/subjects/FTP/BFTPD/gcov.patch','run_ablation.sh')
    write(out/'data/manifest.json', dict(batch=BATCH, target='bftpd', canonical_archives=manifest,
        local_source_hashes_for_interpretation_only={n:digest(root/n) for n in reference_sources},
        note='Local source hashes record interpretation context; they do not establish historical source-to-binary identity.'))
    write(out/'data/summary.json', dict(batch=BATCH, arms=arms,
        global_totals={k:sum(x[k] for x in rows) for k in ('afl_executions','admitted_invocations','shutdown_zero_delta_invocations',
            'candidates','provisional','provisional_serviced_descendant_execs','provisional_conversions','replay_inputs','replay_missing_gcda',
            'authenticated_replays_missing_gcda','scheduler_selections','warmup_selections','passive_posterior_updated_episodes',
            'llm_records','llm_ok','llm_transport_errors','llm_api_errors')},
        interpretation=dict(Q1='Allocation mechanism changed; net efficacy unproven.',
            Q2='Zero validation service: not tested successfully.',Q3='Calibration disabled and every scheduler selection in warmup: not tested.'),
        warnings=['Coverage missing is systematic after successful authentication.',
            'All nine recorded initial queue input hash multisets differ despite identical pre-enrichment seeds_sha256; this is more than a queue-order difference.',
            'Each arm has three independent unpaired campaigns; candidates/target calls are not independent experimental replicates.',
            'Admitted invocation duration is wall elapsed in wrapper, not CPU time or full campaign cost.',
            'candidate_id=0 means no tracked LLM candidate ancestry, not absence of LLM enrichment.',
            'calibration execution_kind refers to AFL seed calibration, not the paper Calibration controller.',
            'LLM tokens are recorded usage summed per row; failed requests with no usage can make actual billing larger.',
            'Two API errors have no recoverable HTTP status; do not infer 401.']))
    with (out/'data/per_run.csv').open('w',newline='') as f:
        w = csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    plot(out, rows)
    print(json.dumps(dict(checked_archives=len(rows), complete_statuses=9,
        replay_inputs=sum(x['replay_inputs'] for x in rows), missing_gcda=sum(x['replay_missing_gcda'] for x in rows),
        provisional=sum(x['provisional'] for x in rows), warmup=sum(x['warmup_selections'] for x in rows))))


def plot(out, rows):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    plt.rcParams.update({'font.size':10,'svg.fonttype':'none','axes.spines.top':False,'axes.spines.right':False})
    fig, axes = plt.subplots(2,2,figsize=(13,8.4),constrained_layout=True)
    x=np.arange(len(rows)); labels=[x['arm'].replace('wrap','').replace('8','')+'\n'+str(x['run']) for x in rows]
    specs=[('llm_descendant_mutations','Descendant mutation','#4477AA'),
           ('llm_descendant_seed_calibrations','Descendant seed calibration','#66CCEE'),
           ('shadow_invocations','Shadow audit','#EE7733')]
    bottom=np.zeros(9)
    for field,label,color in specs:
        values=np.array([r[field] for r in rows]); axes[0,0].bar(x,values,bottom=bottom,label=label,color=color);bottom+=values
    axes[0,0].set(ylabel='Admitted target invocations',title='A. Allocation after the original candidate trial',xticks=x,xticklabels=labels)
    axes[0,0].legend(fontsize=8)
    bottom=np.zeros(9)
    for field,label,color in [('llm_trial_invocation_seconds','Original candidate trials','#228833'),
            ('llm_descendant_invocation_seconds','Descendants','#4477AA'),('shadow_invocation_seconds','Shadow audit','#EE7733')]:
        values=np.array([r[field] for r in rows]);axes[0,1].bar(x,values,bottom=bottom,label=label,color=color);bottom+=values
    axes[0,1].set(ylabel='Wrapper elapsed seconds',title='B. Tracked candidate target costs (excludes LLM wait)',xticks=x,xticklabels=labels)
    axes[0,1].legend(fontsize=8)
    axes[1,0].bar([0,1],[4,5],color=['#AA3377','#CCBB44'],label='Admitted')
    axes[1,0].bar([0,1],[0,0],color='#228833',label='Serviced or converted')
    axes[1,0].set(xticks=[0,1],xticklabels=['wrapgate8','salvage8'],ylabel='Provisional entries',ylim=(0,6.5),title='C. All provisional entries closed before validation')
    axes[1,0].text(0,4.15,'4 admitted\n0 serviced\n0 converted',ha='center')
    axes[1,0].text(1,5.15,'5 admitted\n0 serviced\n0 converted',ha='center')
    axes[1,0].text(.5,.35,'All 9: no-executable-M2; full budget 64 remaining',ha='center',fontsize=9)
    missing=np.array([r['replay_missing_gcda_fraction']*100 for r in rows])
    axes[1,1].bar(x,missing,color='#CC3311')
    axes[1,1].axhline(95,color='black',lw=1,ls='--')
    axes[1,1].set(ylabel='Replays without session gcda (%)',ylim=(0,105),title='D. Coverage capture is incomplete (5,035 / 5,300)',xticks=x,xticklabels=labels)
    axes[1,1].text(4,35,'All 5,008 successful-login replays lack gcda.\nTerminal branch counts cannot rank arms.',ha='center',fontsize=10)
    for ax in axes.flat: ax.grid(axis='y',alpha=.2);ax.set_axisbelow(True)
    fig.suptitle('bftpd | batch 20261027T150457 | 3 independent campaigns per arm | 95 min each',fontsize=13)
    (out/'figures').mkdir(exist_ok=True)
    fig.savefig(out/'figures/mechanism_audit.png',dpi=180)
    fig.savefig(out/'figures/mechanism_audit.svg')
    plt.close(fig)


if __name__ == '__main__':
    main()
