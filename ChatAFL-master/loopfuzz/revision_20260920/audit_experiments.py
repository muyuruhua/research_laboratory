#!/usr/bin/env python3
"""Read-only archive audit; writes generated evidence files beside this script.

No credentials, raw prompts, requests, endpoint URLs, or command lines are emitted.
The endpoint summaries include every supplied row, including early terminations.
They are descriptive native endpoints, not estimates for a matched deadline.
"""
import csv
import hashlib
import json
import statistics
import tarfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

OUT = Path(__file__).resolve().parent
PROJECT = OUT.parent.parent
ROOT = PROJECT / 'Key_Experiment' / 'benchmark'
NAMES = {'bftpd': 'bftpd', 'exim': 'Exim', 'forked-daapd': 'Forked-daapd',
         'kamailio': 'Kamailio', 'lightftp': 'LightFTP', 'lighttpd1': 'Lighttpd1',
         'live555': 'Live555', 'proftpd': 'ProFTPD', 'pure-ftpd': 'Pure-FTPd'}
ORDER = ['lightftp', 'bftpd', 'proftpd', 'pure-ftpd', 'exim', 'live555', 'kamailio', 'forked-daapd', 'lighttpd1']
SAFE_CONFIG = ['arm', 'calibration', 'model', 'call_cap', 'token_cap',
               'temperature_plateau', 'temperature_grammar', 'top_p', 'max_output_tokens',
               'no_refinement', 'hypothesis', 'cal_gamma', 'cal_epsilon',
               'provisional_budget', 'provisional_ttl_ms', 'provisional_max_live', 'fuzzer_commit']
LOGS = ['run-config.jsonl', 'candidate-events.jsonl', 'admission-events.jsonl',
        'provisional-events.jsonl', 'state-episodes.jsonl', 'bug-events.jsonl', 'repair-events.jsonl']


def audit_archive(row):
    path = ROOT / row['source_path']
    result = {k: row[k] for k in ['subject', 'fuzzer', 'run', 'source_path']}
    result.update({'files': {}, 'config': {}, 'dispositions': Counter(),
                   'provisional_kinds': Counter(), 'bug_kinds': Counter(),
                   'predicate_failures': Counter(), 'parse_errors': 0,
                   'episode_rewards': 0, 'episode_sampled_theta_nonnegative': 0,
                   'episode_mutation_min': None, 'episode_mutation_max': None,
                   'candidate_ids_without_trial': [], 'trial_ids_without_candidate': []})
    candidates, trials = set(), set()
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            name = member.name.rsplit('/', 1)[-1]
            if name not in LOGS + ['fuzzer_stats'] or not member.isfile():
                continue
            stream = archive.extractfile(member)
            if name == 'fuzzer_stats':
                stats = {}
                for raw in stream:
                    line = raw.decode('utf-8', errors='replace')
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key, value = key.strip(), value.strip()
                        if key.startswith(('llm_', 'cal_', 'provisional_', 'disposition_')) or key in ['start_time', 'last_update', 'execs_done', 'execs_per_sec', 'code_gain_events']:
                            try:
                                stats[key] = float(value) if '.' in value else int(value)
                            except ValueError:
                                pass
                result['stats'] = stats
                continue
            result['files'][name] = {'bytes': member.size, 'rows': 0}
            for raw in stream:
                try:
                    event = json.loads(raw)
                except (ValueError, UnicodeError):
                    result['parse_errors'] += 1
                    continue
                result['files'][name]['rows'] += 1
                if name == 'run-config.jsonl' and not result['config']:
                    result['config'] = {k: event.get(k) for k in SAFE_CONFIG}
                    result['config_keys'] = sorted(event)
                elif name == 'candidate-events.jsonl':
                    candidates.add(event.get('candidate_id'))
                elif name == 'admission-events.jsonl':
                    trials.add(event.get('candidate_id'))
                    result['dispositions'][event.get('disposition', 'missing')] += 1
                    for predicate in ['p_pass', 'u_pass', 'r_pass', 'g_code_pass', 'g_state_pass']:
                        if event.get(predicate) is False:
                            result['predicate_failures'][predicate] += 1
                elif name == 'provisional-events.jsonl':
                    result['provisional_kinds'][event.get('kind', 'missing')] += 1
                elif name == 'state-episodes.jsonl':
                    result['episode_rewards'] += event.get('reward', 0)
                    result['episode_sampled_theta_nonnegative'] += int(event.get('sampled_theta', -1) >= 0)
                    m = event.get('mutations')
                    if m is not None:
                        lo, hi = result['episode_mutation_min'], result['episode_mutation_max']
                        result['episode_mutation_min'] = m if lo is None else min(lo, m)
                        result['episode_mutation_max'] = m if hi is None else max(hi, m)
                elif name == 'bug-events.jsonl':
                    result['bug_kinds'][event.get('kind', 'missing')] += 1
    result['candidate_ids_without_trial'] = sorted(candidates-trials)
    result['trial_ids_without_candidate'] = sorted(trials-candidates)
    return result


def mean_sd(rows, field):
    values = [float(row[field]) for row in rows if row[field] != '']
    return {'n': len(values), 'mean': statistics.mean(values), 'sd': statistics.stdev(values) if len(values)>1 else None}


def fmt(value):
    return '${:.1f} \\pm {:.1f}$'.format(value['mean'], value['sd'])


groups = defaultdict(list)
source_checksums = {}
inventory = []
for source in sorted(ROOT.glob('*/run_summary.csv')):
    source_checksums[str(source.relative_to(PROJECT))] = hashlib.sha256(source.read_bytes()).hexdigest()
    rows = list(csv.DictReader(source.open()))
    manifest = source.parent / '.result_manifest.tsv'
    manifest_rows = list(csv.DictReader(manifest.open(), delimiter='\t')) if manifest.exists() else []
    statuses = list((source.parent / '.sample_status').glob('*.status'))
    archives = list(source.parent.glob('*.tar.gz'))
    for row in rows:
        row['source_path'] = str((source.parent / row['source']).relative_to(ROOT))
        groups[row['subject'], row['fuzzer']].append(row)
    inventory.append({'directory': str(source.parent.relative_to(PROJECT)),
                      'summary_rows': len(rows), 'manifest_rows': len(manifest_rows),
                      'status_files': len(statuses), 'archive_files': len(archives),
                      'unmanifested_archives': sorted({p.name for p in archives}-{r['archive_name'] for r in manifest_rows}),
                      'manifest_missing_archives': sorted({r['archive_name'] for r in manifest_rows}-{p.name for p in archives})})

aggregates=[]
for (target, arm), rows in sorted(groups.items()):
    durations=[int(row['runtime_min']) for row in rows]
    aggregates.append({'target': target, 'arm_label': arm, 'rows': len(rows),
                       'status': dict(Counter(row['status'] for row in rows)),
                       'exit_code': dict(Counter(row['exit_code'] for row in rows)),
                       'runtime_min_range': [min(durations),max(durations)],
                       'native_branch_endpoint': mean_sd(rows,'b_abs'),
                       'native_ipsm_state_edge_endpoint': mean_sd(rows,'edges')})

loop_rows=[row for (target, arm), rows in groups.items() if arm=='loopfuzz' for row in rows]
with ThreadPoolExecutor(max_workers=4) as pool:
    archives=list(pool.map(audit_archive,loop_rows))

mechanism=[]
for target in ORDER:
    runs=[r for r in archives if r['subject']==target]
    rec={'target':target,'runs':len(runs),'files':{},'dispositions':Counter(),
         'provisional_kinds':Counter(),'bug_kinds':Counter(),'predicate_failures':Counter(),
         'episode_rewards':0,'episode_sampled_theta_nonnegative':0,
         'candidate_ids_without_trial':0,'trial_ids_without_candidate':0,'parse_errors':0}
    for name in LOGS:
        rec['files'][name]={'runs_present':sum(name in r['files'] for r in runs),
                            'rows':sum(r['files'].get(name,{}).get('rows',0) for r in runs)}
    for run in runs:
        for field in ['dispositions','provisional_kinds','bug_kinds','predicate_failures']:
            rec[field].update(run[field])
        for field in ['episode_rewards','episode_sampled_theta_nonnegative','parse_errors']:
            rec[field]+=run[field]
        for field in ['candidate_ids_without_trial','trial_ids_without_candidate']:
            rec[field]+=len(run[field])
    rec['episode_mutation_range']=[min(r['episode_mutation_min'] for r in runs if r['episode_mutation_min'] is not None),max(r['episode_mutation_max'] for r in runs if r['episode_mutation_max'] is not None)]
    mechanism.append(rec)

payload={'source_root':str(ROOT),'analysis_policy':'Every supplied summary row is retained; native terminal endpoints at heterogeneous stopping times; exploratory only.',
         'source_checksums_sha256':source_checksums,'inventory':inventory,'aggregates':aggregates,
         'mechanism':mechanism,'archive_audits':archives}
(OUT/'experiment_audit.json').write_text(json.dumps(payload,indent=2)+'\n')

index={(r['target'],r['arm_label']):r for r in aggregates}
tex=[r'% Generated by audit_experiments.py. All native endpoint rows are retained.',
     r'\begin{table*}[t]',r'\centering\small',
     r'\caption{Supplied archive inventory. Completed, SIGABRT, and exit-137 columns refer only to recorded LoopFuzz runs and reproduce the summary labels; exit code 137 is not independent evidence of an out-of-memory failure. Durations are observed fuzzer runtime, in minutes.}',
     r'\label{tab:observed_inventory}',r'\begin{tabular}{lrrrrrl}',r'\toprule',
     r'Target & AFLNet & LoopFuzz & Completed & SIGABRT & Exit 137 & LoopFuzz duration \\',r'\midrule']
for target in ORDER:
    a,d=index[target,'aflnet'],index[target,'loopfuzz']
    tex.append('{} & {} & {} & {} & {} & {} & {}--{} \\\\'.format(NAMES[target],a['rows'],d['rows'],d['status'].get('completed',0),d['status'].get('sigabrt',0),d['exit_code'].get('137',0),*d['runtime_min_range']))
tex += [r'\bottomrule',r'\end{tabular}',r'\end{table*}',
        r'\begin{table*}[t]',r'\centering\small',
        r'\caption{Exploratory native terminal endpoints (mean $\pm$ sample standard deviation), retaining every supplied summary row, including early terminations. These values are not matched-deadline or causal A--E comparisons.}',
        r'\label{tab:observed_endpoints}',r'\begin{tabular}{lrrrr}',r'\toprule',
        r'& \multicolumn{2}{c}{Code branches (\texttt{b\_abs})} & \multicolumn{2}{c}{IPSM state edges} \\',
        r'Target & AFLNet & Recorded LoopFuzz & AFLNet & Recorded LoopFuzz \\',r'\midrule']
for target in ORDER:
    a,d=index[target,'aflnet'],index[target,'loopfuzz']
    tex.append('{} & {} & {} & {} & {} \\\\'.format(NAMES[target],fmt(a['native_branch_endpoint']),fmt(d['native_branch_endpoint']),fmt(a['native_ipsm_state_edge_endpoint']),fmt(d['native_ipsm_state_edge_endpoint'])))
tex += [r'\bottomrule',r'\end{tabular}',r'\end{table*}',
        r'\begin{table*}[t]',r'\centering\small',
        r'\caption{Observed schema-v2 logging counts from all 90 supplied LoopFuzz archives. Reject, provisional, and durable are recorded decision labels, not verified post-execution queue membership.}',
        r'\label{tab:observed_log_counts}',r'\begin{tabular}{lrrrrrr}',r'\toprule',
        r'Target & Candidates & Trials & Reject & Provisional & Durable & Episodes \\',r'\midrule']
for r in mechanism:
    tex.append('{} & {} & {} & {} & {} & {} & {} \\\\'.format(NAMES[r['target']],r['files']['candidate-events.jsonl']['rows'],r['files']['admission-events.jsonl']['rows'],r['dispositions'].get('reject',0),r['dispositions'].get('provisional',0),r['dispositions'].get('durable',0),r['files']['state-episodes.jsonl']['rows']))
tex += [r'\bottomrule',r'\end{tabular}',r'\end{table*}']
(OUT/'observed_tables.tex').write_text('\n'.join(tex)+'\n')
cost_tex=[r'% Generated from the final saved fuzzer_stats snapshots, not provider billing.',
          r'\begin{table}[t]',r'\centering\small',
          r'\caption{Recorded LoopFuzz costs: per-run minimum--maximum across all ten supplied runs per target. Total tokens combine prompt and completion tokens; k denotes 1,000 tokens. Final saved snapshots may omit the last reporting window and are not reconciled provider billing.}',
          r'\label{tab:observed_costs}',r'\begin{tabular}{lrr}',r'\toprule',
          r'Target & Model calls & Total tokens (k) \\',r'\midrule']
for target in ORDER:
    runs=[r for r in archives if r['subject']==target]
    calls=[r['stats']['llm_total_calls'] for r in runs]
    tokens=[(r['stats']['llm_prompt_tokens']+r['stats']['llm_completion_tok'])/1000 for r in runs]
    cost_tex.append('{} & {}--{} & {:.1f}--{:.1f} \\\\'.format(NAMES[target],min(calls),max(calls),min(tokens),max(tokens)))
cost_tex += [r'\bottomrule',r'\end{tabular}',r'\end{table}']
(OUT/'observed_costs.tex').write_text('\n'.join(cost_tex)+'\n')
print(json.dumps({'aggregates':aggregates,'inventory':inventory,'mechanism':mechanism,
                  'configuration_variants':{key:sorted({str(r['config'].get(key)) for r in archives}) for key in SAFE_CONFIG},
                  'output_files':['experiment_audit.json','observed_tables.tex','observed_costs.tex']},indent=2))
