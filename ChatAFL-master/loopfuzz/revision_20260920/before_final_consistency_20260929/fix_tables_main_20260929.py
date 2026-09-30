from pathlib import Path
import json
BASE=Path(__file__).resolve().parent
p=BASE/'main.revised.tex';s=p.read_text();D=json.loads((BASE/'filled_experiment_data_20260929.json').read_text())['aggregate'];M=json.loads((BASE/'filled_mechanism_data_20260929.json').read_text())
N={'lightftp':'LightFTP','bftpd':'bftpd','proftpd':'ProFTPD','pure-ftpd':'Pure-FTPd','exim':'Exim','live555':'Live555','kamailio':'Kamailio','forked-daapd':'Forked-daapd','lighttpd1':'Lighttpd1'};T=list(N)
def a(x,t):return D.get(x+'|'+t)
def c(d):
 if not d:return r'\missing'
 return f'\\shortstack{{{d["branches"]["mean"]:.1f}$\\pm${d["branches"]["sd"]:.1f}\\,(n={d["runs_available"]}){"\\\\"}{d["auc_branch_hours"]["mean"]:.1f}$\\pm${d["auc_branch_hours"]["sd"]:.1f}}}'
rb='\\\\'
# f strings cannot include backslash expression; use explicit builder.
def cell(d):
 if not d:return r'\missing'
 return '\\shortstack{'+f'{d["branches"]["mean"]:.1f}$\\pm${d["branches"]["sd"]:.1f}\\,(n={d["runs_available"]})'+rb+f'{d["auc_branch_hours"]["mean"]:.1f}$\\pm${d["auc_branch_hours"]["sd"]:.1f}'+'}'
L=[r'\begin{table*}[!tbp]',r'\centering\small',r'\caption{Archive-derived final code-branch count / branch-coverage AUC (branch-hours). Each cell shows mean $\pm$ sample SD and observed $n$ on the first line, with AUC on the second line. The nominal target is 10 runs; missing target--arm archives remain blank. These descriptive endpoints do not replace matched-horizon causal inference.}',r'\label{tab:mainresults}',r'\begin{tabularx}{\textwidth}{l *{5}{>{\centering\arraybackslash}X}}',r'\toprule',r'Target & A & B & C & D & E '+rb,r'\midrule']
for i,t in enumerate(T):
 L.append(N[t]+' & '+' & '.join(cell(a(x,t)) for x in 'ABCDE')+' '+rb)
 if i<len(T)-1:L.append(r'\addlinespace[3pt]')
L += [r'\bottomrule',r'\end{tabularx}',r'\end{table*}'];block='\n'.join(L)
lab=r'\label{tab:mainresults}'; st=s.rfind(r'\begin{table*}',0,s.index(lab));en=s.index(r'\end{table*}',s.index(lab))+len(r'\end{table*}');s=s[:st]+block+s[en:]
# mechanism table
f=lambda arm,key:M[arm]['dispositions'].get(key,0)
def first(arm):return f'0 / {M[arm]["first_failed_logged_predicate"].get("u_pass",0):,} / 0'
def rate(arm):
 c=M[arm]['candidates'];d=f(arm,'durable');return f'{100*d/c:.1f}\\% ({d:,}/{c:,})'
def lat(arm):
 x=M[arm]['trial_latency_ms'];return f'{x["mean"]:.1f}$\\pm${x["sd"]:.1f} ($n={x["n_runs_with_trials"]}$)'
L=[r'\begin{table*}[!tbp]',r'\centering\footnotesize',r'\caption{Logged mechanism totals across the available C/D/E archives. Candidate and trial IDs are scoped to each archive; disposition labels are not independently verified queue membership. Metrics requiring descendant joins or verified fixed-energy, independent code-branch rewards remain blank; the separate logged-reward diagnostics appear in Table~\ref{tab:logged_calibration}.}',r'\label{tab:mechanisms}',r'\begin{tabularx}{\textwidth}{>{\raggedright\arraybackslash}p{0.19\textwidth} *{3}{>{\centering\arraybackslash}p{0.14\textwidth}} Y}',r'\toprule',r'Metric & C & D & E & Denominator / interpretation '+rb,r'\midrule']
L += [f'Candidate records & {M["C"]["candidates"]:,} & {M["D"]["candidates"]:,} & {M["E"]["candidates"]:,} & Distinct candidate IDs within each archive. '+rb,
f'Trial records & {M["C"]["trials"]:,} & {M["D"]["trials"]:,} & {M["E"]["trials"]:,} & Distinct trial IDs within each archive. '+rb,
f'Reject / durable labels & {f("C","reject"):,} / {f("C","durable"):,} & {f("D","reject"):,} / {f("D","durable"):,} & {f("E","reject"):,} / {f("E","durable"):,} & Logged trial dispositions. '+rb,
f'First failed logged $P/U/R$ & {first("C")} & {first("D")} & {first("E")} & First false field in $P$, then $U$, then $R$ order; trial denominator. '+rb,
f'Direct durable rate & {rate("C")} & {rate("D")} & {rate("E")} & Logged disposition labels / generated candidates. '+rb,
r'State-only provisional rate & \missing & \missing & \missing & All candidates; not enabled for C. '+rb,
r'Provisional conversion / expiration & \missing & \missing & \missing & Provisional admissions, including pending/censored counts. '+rb,
f'Trial latency (ms) & {lat("C")} & {lat("D")} & {lat("E")} & Mean $\\pm$ sample SD of within-run mean \\texttt{{latency\\_ms}}; runs with trials only. '+rb,
r'Promotion latency & \missing & \missing & \missing & Requires verified queue-promotion timestamps. '+rb,
r'Downstream productivity@64 & \missing & \missing & \missing & Later descendants, excluding admission gain. '+rb,
r'Queue size / nonproductive retention & \missing & \missing & \missing & Queue state plus C--D counterfactual. '+rb,
r'Shadow-validation false-negative rate & \missing & \missing & \missing & Random rejected-candidate sample. '+rb,
r'Code-branch gain per episode & \missing & \missing & \missing & Completed equal-energy episodes. '+rb,
r'Brier / ECE / AUPRC & \missing & \missing & \missing & Fixed-energy source-branch reward; separate logged-reward diagnostics in Table~\ref{tab:logged_calibration}. '+rb,
r'Code gain per candidate / 1,000 tokens & \missing & \missing & \missing & Joined gain and complete usage. '+rb]
L += [r'\bottomrule',r'\end{tabularx}',r'\end{table*}'];block='\n'.join(L);lab=r'\label{tab:mechanisms}';st=s.rfind(r'\begin{table*}',0,s.index(lab));en=s.index(r'\end{table*}',s.index(lab))+len(r'\end{table*}');s=s[:st]+block+s[en:]
p.write_text(s)
print('clean table blocks written')
