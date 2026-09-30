#!/usr/bin/env python3
"""Regenerate the versioned evidence tables and two data-driven main-text tables.

Reads the audited aggregates and run ledger once. Missing observations remain
blank; LaTeX row endings are emitted explicitly as two backslashes.
"""
from pathlib import Path
import json
import runpy

BASE = Path(__file__).resolve().parent
AGG = json.loads((BASE / 'filled_experiment_data_20260930.json').read_text())['aggregate']
RUNS = json.loads((BASE / 'filled_run_evidence_20260930.json').read_text())['runs']
NAMES = {'lightftp':'LightFTP','bftpd':'bftpd','proftpd':'ProFTPD',
         'pure-ftpd':'Pure-FTPd','exim':'Exim','live555':'Live555',
         'kamailio':'Kamailio','forked-daapd':'Forked-daapd','lighttpd1':'Lighttpd1'}
BS = chr(92)
ROW = BS * 2
MISSING = BS + 'missing'

def observed(arm, target):
    return [r for r in RUNS if r['arm'] == arm and r['target'] == target]

def pm(arm, target, metric):
    item = AGG.get(arm + '|' + target)
    if item is None or item[metric]['mean'] is None:
        return MISSING
    stats = item[metric]
    mean = f"{stats['mean']:.1f}"
    return mean if stats['sd'] is None else mean + '$' + BS + 'pm$' + f"{stats['sd']:.1f}"

def row(*cells):
    return ' & '.join(map(str, cells)) + ' ' + ROW

def begin(caption, label, columns, wide=True):
    env = 'table*' if wide else 'table'
    return [BS+'begin{'+env+'}[!tbp]', BS+'centering'+BS+'small',
            BS+'caption{'+caption+'}', BS+'label{'+label+'}',
            BS+'begin{tabular}{'+columns+'}', BS+'toprule']

def end(wide=True):
    return [BS+'bottomrule', BS+'end{tabular}', BS+'end{'+('table*' if wide else 'table')+'}']

def write(name, lines):
    (BASE/name).write_text(chr(10).join(lines)+chr(10))

lines = ['% Generated from current Key_Experiment archives on 2026-09-30.']
lines += begin(r'Current archive inventory. A and D use benchmark rows; D is counted once because the supplied \texttt{ablation/gated\_fixed} directory duplicates benchmark LoopFuzz. Nominal target is 10 runs per target. Status and exit-code labels are descriptive.', 'tab:observed_inventory', 'lrrrrrl')
lines += [row('Target','AFLNet','ChatAFL','LoopFuzz(D)','Completed(D)','Exit 137(D)','Duration (min)'), BS+'midrule']
for target, name in NAMES.items():
    d = AGG.get('D|'+target)
    duration = [float(r['summary']['runtime_min']) for r in observed('D',target)]
    lines.append(row(name, len(observed('A',target)),len(observed('B',target)),
                     d['runs_available'],d['status'].get('completed',0),d['exit_code'].get('137',0),
                     f'{min(duration):.0f}--{max(duration):.0f}' if duration else MISSING))
lines += end()
lines += begin(r'Exploratory native terminal endpoints from current summary rows (mean $\pm$ sample SD). All available A and D rows are retained; unequal stopping times and source-build uncertainty preclude causal comparisons.', 'tab:observed_endpoints','lrrrr')
lines += [row('',r'\multicolumn{2}{c}{Code branches (\texttt{b\_abs})}',r'\multicolumn{2}{c}{IPSM state edges}'),row('Target','AFLNet','LoopFuzz(D)','AFLNet','LoopFuzz(D)'),BS+'midrule']
for target, name in NAMES.items():
    lines.append(row(name,pm('A',target,'branches'),pm('D',target,'branches'),pm('A',target,'ipsm_edges'),pm('D',target,'ipsm_edges')))
lines += end()
lines += begin('Logged schema-v2 counts in current LoopFuzz D archives. Reject, provisional, and durable are recorded labels, not independently verified queue membership.','tab:observed_log_counts','lrrrrrr')
lines += [row('Target','Candidates','Trials','Reject','Provisional','Durable','Episodes'),BS+'midrule']
for target, name in NAMES.items():
    d = AGG.get('D|'+target)
    lines.append(row(name,d['candidates'],d['trials'],d['dispositions'].get('reject',0),d['dispositions'].get('provisional',0),d['dispositions'].get('durable',0),d['episodes']) if d else row(name,*([MISSING]*6)))
lines += end()
write('observed_tables.updated_20260930.tex',lines)

lines = ['% Generated from current selected benchmark LoopFuzz D archives.']
lines += begin('Recorded LoopFuzz D costs from current benchmark archives: per-run minimum--maximum by target. Total tokens combine prompt and completion counters; k denotes 1,000 tokens.','tab:observed_costs','lrr',False)
lines += [row('Target','Model calls','Total tokens (k)'),BS+'midrule']
for target, name in NAMES.items():
    runs = observed('D',target)
    calls = [r['model_calls'] for r in runs if r['model_calls'] is not None]
    tokens = [(r['prompt_tokens']+r['completion_tokens'])/1000 for r in runs if r['prompt_tokens'] is not None and r['completion_tokens'] is not None]
    lines.append(row(name,f'{min(calls):.0f}--{max(calls):.0f}' if calls else MISSING,
                     f'{min(tokens):.1f}--{max(tokens):.1f}' if tokens else MISSING))
lines += end(False)
write('observed_costs.updated_20260930.tex',lines)
runpy.run_path(str(BASE/'make_appendix_super_20260930.py'),run_name='__main__')
runpy.run_path(str(BASE/'fix_tables_main_20260930.py'),run_name='__main__')
print('Generated inventory, endpoints, events, costs, appendix, main results, and mechanism tables.')

# Keep reviewed caption/cell wording when regenerating this evidence snapshot.
from refine_float_text import apply_edits as apply_float_copy_edits
apply_float_copy_edits()
