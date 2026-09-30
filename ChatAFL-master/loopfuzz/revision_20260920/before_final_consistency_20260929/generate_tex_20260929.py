#!/usr/bin/env python3
from pathlib import Path
import json
from collections import defaultdict

BASE=Path(__file__).resolve().parent
D=json.loads((BASE/'filled_experiment_data_20260929.json').read_text())['aggregate']
NAMES={'lightftp':'LightFTP','bftpd':'bftpd','proftpd':'ProFTPD','pure-ftpd':'Pure-FTPd','exim':'Exim','live555':'Live555','kamailio':'Kamailio','forked-daapd':'Forked-daapd','lighttpd1':'Lighttpd1'}
TARGETS=list(NAMES)
ARM_LABEL={'A':'A','B':'B','C':'C','D':'D','E':'E','E-gamma099':r'$E,\ \gamma=0.99$','E-gamma100':r'$E,\ \gamma=1.0$'}

def a(arm,target): return D.get(f'{arm}|{target}')
def num(x): return '' if x is None else f'{x:.1f}'
def pm(x,key):
 if not x or x[key]['mean'] is None: return r'\missing'
 return f'{x[key]["mean"]:.1f}$\\pm${x[key]["sd"]:.1f}'
def cell(x,key):
 if not x or x[key]['mean'] is None: return r'\missing'
 return rf'\shortstack{{{x[key]["mean"]:.1f}$\pm${x[key]["sd"]:.1f}\,(n={x["runs_available"]})\\{x["auc_branch_hours"]["mean"]:.1f}$\pm${x["auc_branch_hours"]["sd"]:.1f}}}'

# Inventory/endpoints/log counts. Use ordinary Python strings so TeX receives one backslash.
lines=['% Generated from current Key_Experiment archives on 2026-09-29.',r'\begin{table*}[!tbp]',r'\centering\small',r'\caption{Current archive inventory. A and D use benchmark rows; D is counted once because the supplied ablation/gated_fixed directory duplicates benchmark LoopFuzz. Nominal target is 10 runs per target. Status and exit-code labels are descriptive.}',r'\label{tab:observed_inventory}',r'\begin{tabular}{lrrrrrl}',r'\toprule',r'Target & AFLNet & ChatAFL & LoopFuzz(D) & Completed(D) & Exit 137(D) & Duration (min) \\',r'\midrule']
for t in TARGETS:
 d=a('D',t); rr=d['runs_available'] if d else 0; st=d.get('status',{}) if d else {}; ec=d.get('exit_code',{}) if d else {}; dur=''
 if d and d['runs_available']:
  # Runtime range is not in aggregate; derive from evidence ledger.
  runs=[r for r in json.loads((BASE/'filled_run_evidence_20260929.json').read_text())['runs'] if r['arm']=='D' and r['target']==t]
  vals=[float(r['summary']['runtime_min']) for r in runs]
  dur=f'{min(vals):.0f}--{max(vals):.0f}'
 lines.append(f'{NAMES[t]} & {len([r for r in json.loads((BASE/"filled_run_evidence_20260929.json").read_text())["runs"] if r["arm"]=="A" and r["target"]==t])} & {len([r for r in json.loads((BASE/"filled_run_evidence_20260929.json").read_text())["runs"] if r["arm"]=="B" and r["target"]==t])} & {rr} & {st.get("completed",0)} & {ec.get("137",0)} & {dur} \\')
lines += [r'\bottomrule',r'\end{tabular}',r'\end{table*}',r'\begin{table*}[!tbp]',r'\centering\small',r'\caption{Exploratory native terminal endpoints from current summary rows (mean $\pm$ sample SD). All available rows are retained; unequal stopping times and source-build uncertainty preclude causal comparisons.}',r'\label{tab:observed_endpoints}',r'\begin{tabular}{lrrrr}',r'\toprule',r'& \multicolumn{2}{c}{Code branches (\texttt{b\_abs})} & \multicolumn{2}{c}{IPSM state edges} \\',r'Target & AFLNet & LoopFuzz(D) & AFLNet & LoopFuzz(D) \\',r'\midrule']
for t in TARGETS:
 lines.append(f'{NAMES[t]} & {pm(a("A",t),"branches")} & {pm(a("D",t),"branches")} & {pm(a("A",t),"ipsm_edges")} & {pm(a("D",t),"ipsm_edges")} \\')
lines += [r'\bottomrule',r'\end{tabular}',r'\end{table*}',r'\begin{table*}[!tbp]',r'\centering\small',r'\caption{Logged schema-v2 counts in current LoopFuzz D archives. Reject, provisional, and durable are recorded labels, not independently verified queue membership.}',r'\label{tab:observed_log_counts}',r'\begin{tabular}{lrrrrrr}',r'\toprule',r'Target & Candidates & Trials & Reject & Provisional & Durable & Episodes \\',r'\midrule']
for t in TARGETS:
 d=a('D',t)
 if d:
  disp=d['dispositions']; lines.append(f'{NAMES[t]} & {d["candidates"]} & {d["trials"]} & {disp.get("reject",0)} & {disp.get("provisional",0)} & {disp.get("durable",0)} & {d["episodes"]} \\')
 else: lines.append(f'{NAMES[t]} & \\missing & \\missing & \\missing & \\missing & \\missing & \\missing \\')
lines += [r'\bottomrule',r'\end{tabular}',r'\end{table*}']
(BASE/'observed_tables.updated_20260929.tex').write_text('\n'.join(lines)+'\n')

# Costs (range only, as recorded counters permit).
runs=json.loads((BASE/'filled_run_evidence_20260929.json').read_text())['runs']
lines=['% Generated from current selected benchmark LoopFuzz D archives.',r'\begin{table}[!tbp]',r'\centering\small',r'\caption{Recorded LoopFuzz D costs from current benchmark archives: per-run minimum--maximum by target. Total tokens combine prompt and completion counters; k denotes 1,000 tokens.}',r'\label{tab:observed_costs}',r'\begin{tabular}{lrr}',r'\toprule',r'Target & Model calls & Total tokens (k) \\',r'\midrule']
for t in TARGETS:
 rr=[r for r in runs if r['arm']=='D' and r['target']==t]
 calls=[r['model_calls'] for r in rr if r['model_calls'] is not None]; toks=[(r['prompt_tokens']+r['completion_tokens'])/1000 for r in rr if r['prompt_tokens'] is not None and r['completion_tokens'] is not None]
 lines.append(f'{NAMES[t]} & {min(calls):.0f}--{max(calls):.0f} & {min(toks):.1f}--{max(toks):.1f} \\' if calls and toks else f'{NAMES[t]} & \\missing & \\missing \\')
lines += [r'\bottomrule',r'\end{tabular}',r'\end{table}']
(BASE/'observed_costs.updated_20260929.tex').write_text('\n'.join(lines)+'\n')

# Full appendix; one row per observed target-arm combination.
head=['% Generated from current Key_Experiment archives on 2026-09-29.',r'\begingroup',r'\small',r'\setlength{\tabcolsep}{1.6pt}',r'\renewcommand{\arraystretch}{1.0}',r'\noindent Row IDs combine arm and target number. Arms A--E retain their main-text meanings; $E_{99}$ and $E_{100}$ denote sensitivity groups at $\gamma=0.99$ and $\gamma=1.0$.',r'\par\smallskip',r'\noindent\begin{tabularx}{\columnwidth}{@{}YYY@{}}',r'1: LightFTP & 4: Pure-FTPd & 7: Kamailio \\',r'2: bftpd & 5: Exim & 8: Forked-daapd \\',r'3: ProFTPD & 6: Live555 & 9: Lighttpd1 \\',r'\end{tabularx}',r'\par\smallskip',r'\noindent AUC is measured in branch-hours; IPSM denotes state edges. Status labels reproduce the archive; they do not independently identify failure causes. Missing target--arm combinations have no row and are not zero-valued observations.',r'\par\smallskip',r'\captionof{table}{Complete current archive observations (mean $\pm$ sample SD). The nominal target is $N=10$; $n$ is the observed count. AUC integrates each recorded trajectory in branch-hours. Missing target--arm combinations have no row and remain unavailable.}',r'\label{tab:archive_arms}',r'\tablefirsthead{\toprule ID & $n$ & Branches & AUC & IPSM & Status \\\\ \midrule}',r'\tablehead{\multicolumn{6}{l}{Table~\thetable\ (continued)}\\\\ \toprule ID & $n$ & Branches & AUC & IPSM & Status \\\\ \midrule}',r'\tabletail{\bottomrule}',r'\tablelasttail{\bottomrule}',r'\noindent\begin{supertabular}{@{}lrrrrl@{}}']
for arm in ['A','B','C','D','E','E-gamma099','E-gamma100']:
 for ti,t in enumerate(TARGETS,1):
  d=a(arm,t)
  if not d: continue
  status=','.join(f'{k}:{v}' for k,v in d['status'].items())
  al={'E-gamma099':r'$E_{99}$','E-gamma100':r'$E_{100}$'}.get(arm,arm)
  head.append(f'{al}{ti} & {d["runs_available"]} & {pm(d,"branches")} & {pm(d,"auc_branch_hours")} & {pm(d,"ipsm_edges")} & {status} \\\\')
head += [r'\end{supertabular}',r'\endgroup']
(BASE/'archive_arm_results.updated_20260929.tex').write_text('\n'.join(head)+'\n')
print('Generated updated tables:',len(lines),'cost lines,',len(head),'appendix lines')
