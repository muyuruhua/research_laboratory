from pathlib import Path
import json,re
BASE=Path(__file__).resolve().parent
p=BASE/'main.revised.tex'; s=p.read_text()
D=json.loads((BASE/'filled_experiment_data_20260929.json').read_text())['aggregate']
NAMES={'lightftp':'LightFTP','bftpd':'bftpd','proftpd':'ProFTPD','pure-ftpd':'Pure-FTPd','exim':'Exim','live555':'Live555','kamailio':'Kamailio','forked-daapd':'Forked-daapd','lighttpd1':'Lighttpd1'}
TARGETS=list(NAMES)
def a(arm,t):return D.get(f'{arm}|{t}')
def cell(d):
 if not d:return r'\missing'
 return rf'\shortstack{{{d["branches"]["mean"]:.1f}$\pm${d["branches"]["sd"]:.1f}\,(n={d["runs_available"]})\\{d["auc_branch_hours"]["mean"]:.1f}$\pm${d["auc_branch_hours"]["sd"]:.1f}}}'
# Paths and generated inputs.
for old,new in [('revision_20260920/figures_reflow_20260928','revision_20260920/figures_updated_20260929'),('revision_20260920/observed_tables.tex','revision_20260920/observed_tables.updated_20260929.tex'),('revision_20260920/observed_costs.tex','revision_20260920/observed_costs.updated_20260929.tex'),('revision_20260920/archive_arm_results.flow_20260928.tex','revision_20260920/archive_arm_results.updated_20260929.tex')]: s=s.replace(old,new)
# Archive inventory paragraph.
s=s.replace('The current extraction contains 94 AFLNet (A), 101 ChatAFL (B), and 108 benchmark LoopFuzz (D) summary rows, alongside 90 direct-admission (C) and 76 calibrated (E) ablation rows. The two sensitivity groups contain 24 rows each. Extra benchmark rows are retained as archive observations without assuming independence; groups with fewer than ten available runs retain a nominal count of ten, while the observed count $n$ remains explicit. Means and sample SDs use observed values only; unavailable runs are left unfilled.', 'The current extraction contains 94 AFLNet (A), 91 ChatAFL (B), 104 benchmark LoopFuzz (D), 90 direct-admission (C), and 86 calibrated (E) summary rows. The sensitivity groups contain 108 rows at $\\gamma=0.99$ and 55 rows at $\\gamma=1.0$. Extra rows are retained as archive observations without assuming independence; the nominal target is ten runs, while the observed count $n$ remains explicit. Means and sample SDs use observed values only; unavailable runs are left unfilled.')
# Remove obsolete discrepancy, replace with current audit statement.
s=s.replace('The independently read trajectory for one D Lighttpd1 archive ends at 2,115 branches, whereas its summary records 2,139. The endpoint/cost tables retain the summary value and the trajectory plot retains the recorded time series; this unresolved source discrepancy is not silently reconciled.', 'All 628 selected archives have trajectory endpoints matching their supplied summary $\\texttt{b\\_abs}$ values; the trajectory and endpoint tables therefore use the same recorded terminal observation.')
# Current mechanism and reliability counts.
s=s.replace('All 28,866 E-archive records pass finite-probability, Beta-mean, binary-reward, episode-ID uniqueness, chronological-order, and within-episode discounted-update checks. Excluding 5,753 zero-execution records leaves 23,113 records from 76 runs.', 'All 31,826 E-archive records pass finite-probability, Beta-mean, binary-reward, episode-ID uniqueness, chronological-order, and within-episode discounted-update checks. Excluding 6,070 zero-mutation records leaves 25,756 positive-mutation records from 86 runs.')
s=s.replace('The supplied C, D, and E archives contain 56,164, 75,631, and 28,866 state-episode records, respectively.', 'The supplied C, D, and E archives contain 56,164, 77,593, and 31,826 state-episode records, respectively.')
s=s.replace('In 121 of the 469 source trajectories, at least one recorded branch count decreases.', 'In 127 of the 465 source trajectories, at least one recorded branch count decreases.')
# Admission mechanism paragraph.
s=s.replace('the event stream contains 1,992 candidate records, 1,991 trial records, 1,968 reject labels, 23 durable labels, and no provisional labels.', 'the event stream contains 2,227 candidate records, 2,226 trial records, 2,203 reject labels, 23 durable labels, and no provisional labels.')
s=s.replace('The corresponding C and E totals are 1,326/1,326 and 726/725 candidates/trials, respectively, with 1,326 direct durable labels for C and 716 rejects plus 9 durable labels for E.', 'The corresponding C and E totals are 1,326/1,326 and 735/734 candidates/trials, respectively, with 1,326 direct durable labels for C and 725 rejects plus 9 durable labels for E.')
# Figure/cost counts and captions.
s=s.replace('from 469 archives.', 'from 465 archives.')
s=s.replace('Missing E--bftpd is omitted.', 'E--bftpd is now present with ten archives; other missing target--arm combinations remain omitted.')
s=s.replace('with one marker per B--E archive (375 observations).', 'with one marker per B--E archive (371 observations).')
s=s.replace('for the same 375 B--E observations', 'for the same 371 B--E observations')
s=s.replace('The candidate denominators are 1,326/1,992/726 for C/D/E; the trial denominators are 1,326/1,991/725.', 'The candidate denominators are 1,326/2,227/735 for C/D/E; the trial denominators are 1,326/2,226/734.')
s=s.replace('D and E each have one unmatched candidate', 'D and E each have one unmatched candidate')
s=s.replace('Calls range from 52 to 248 per run in D.', 'Calls range over the per-target intervals reported in Table~\\ref{tab:observed_costs}; the saved counter is not an enforced campaign ceiling.')
# Main results table.
label='\\label{tab:mainresults}'
start=s.rfind('\\begin{table*}',0,s.index(label)); end=s.index('\\end{table*}',s.index(label))+len('\\end{table*}')
rows=[r'\\begin{table*}[!tbp]',r'\\centering\\small',r'\\caption{Archive-derived final code-branch count / branch-coverage AUC (branch-hours). Each cell shows mean $\\pm$ sample SD and observed $n$ on the first line, with AUC on the second line. The nominal target is 10 runs; missing target--arm archives remain blank. These descriptive endpoints do not replace matched-horizon causal inference.}',r'\\label{tab:mainresults}',r'\\begin{tabularx}{\\textwidth}{l *{5}{>{\\centering\\arraybackslash}X}}',r'\\toprule',r'Target & A & B & C & D & E \\\\',r'\\midrule']
for i,t in enumerate(TARGETS):
 rows.append(f'{NAMES[t]} & {cell(a("A",t))} & {cell(a("B",t))} & {cell(a("C",t))} & {cell(a("D",t))} & {cell(a("E",t))} \\\\')
 if i<len(TARGETS)-1: rows.append(r'\\addlinespace[3pt]')
rows += [r'\\bottomrule',r'\\end{tabularx}',r'\\end{table*}']
# Convert escaped command construction to actual TeX backslashes: rows above intentionally use raw double in source only where needed.
block='\n'.join(rows).replace('\\\\begin','\\begin').replace('\\\\centering','\\centering').replace('\\\\small','\\small').replace('\\\\caption','\\caption').replace('\\\\label','\\label').replace('\\\\end','\\end').replace('\\\\toprule','\\toprule').replace('\\\\midrule','\\midrule').replace('\\\\bottomrule','\\bottomrule').replace('\\\\addlinespace','\\addlinespace').replace('\\\\begin{tabularx','\\begin{tabularx')
s=s[:start]+block+s[end:]
# Mechanism table.
label='\\label{tab:mechanisms}'; start=s.rfind('\\begin{table*}',0,s.index(label)); end=s.index('\\end{table*}',s.index(label))+len('\\end{table*}')
M=json.loads((BASE/'filled_mechanism_data_20260929.json').read_text())
def fmt_rate(arm):
 m=M[arm]; c=m['candidates']; d=m['dispositions'].get('durable',0); return f'{100*d/c:.1f}\\% ({d:,}/{c:,})'
def first(arm):
 m=M[arm]; f=m['first_failed_logged_predicate']; return f'0 / {f.get("u_pass",0):,} / 0'
def latency(arm):
 x=M[arm]['trial_latency_ms']; return f'{x["mean"]:.1f}$\\pm${x["sd"]:.1f} ($n={x["n_runs_with_trials"]}$)'
mb=[r'\\begin{table*}[!tbp]',r'\\centering\\footnotesize',r'\\caption{Logged mechanism totals across the available C/D/E archives. Candidate and trial IDs are scoped to each archive; disposition labels are not independently verified queue membership. Metrics requiring descendant joins or verified fixed-energy, independent code-branch rewards remain blank; the separate logged-reward diagnostics appear in Table~\\ref{tab:logged_calibration}.}',r'\\label{tab:mechanisms}',r'\\begin{tabularx}{\\textwidth}{>{\\raggedright\\arraybackslash}p{0.19\\textwidth} *{3}{>{\\centering\\arraybackslash}p{0.14\\textwidth}} Y}',r'\\toprule',r'Metric & C & D & E & Denominator / interpretation \\\\',r'\\midrule']
for line in [
 f'Candidate records & {M["C"]["candidates"]:,} & {M["D"]["candidates"]:,} & {M["E"]["candidates"]:,} & Distinct candidate IDs within each archive. \\\\\\',
 f'Trial records & {M["C"]["trials"]:,} & {M["D"]["trials"]:,} & {M["E"]["trials"]:,} & Distinct trial IDs within each archive. \\\\\\',
 f'Reject / durable labels & {M["C"]["dispositions"].get("reject",0):,} / {M["C"]["dispositions"].get("durable",0):,} & {M["D"]["dispositions"].get("reject",0):,} / {M["D"]["dispositions"].get("durable",0):,} & {M["E"]["dispositions"].get("reject",0):,} / {M["E"]["dispositions"].get("durable",0):,} & Logged trial dispositions. \\\\\\',
 f'First failed logged $P/U/R$ & {first("C")} & {first("D")} & {first("E")} & First false field in $P$, then $U$, then $R$ order; trial denominator. \\\\\\',
 f'Direct durable rate & {fmt_rate("C")} & {fmt_rate("D")} & {fmt_rate("E")} & Logged disposition labels / generated candidates. \\\\\\',
 r'State-only provisional rate & \missing & \missing & \missing & All candidates; not enabled for C. \\\\',
 r'Provisional conversion / expiration & \missing & \missing & \missing & Provisional admissions, including pending/censored counts. \\\\',
 f'Trial latency (ms) & {latency("C")} & {latency("D")} & {latency("E")} & Mean $\\pm$ sample SD of within-run mean \\texttt{{latency\\_ms}}; runs with trials only. \\\\\\',
 r'Promotion latency & \missing & \missing & \missing & Requires verified queue-promotion timestamps. \\\\',
 r'Downstream productivity@64 & \missing & \missing & \missing & Later descendants, excluding admission gain. \\\\',
 r'Queue size / nonproductive retention & \missing & \missing & \missing & Queue state plus C--D counterfactual. \\\\',
 r'Shadow-validation false-negative rate & \missing & \missing & \missing & Random rejected-candidate sample. \\\\',
 r'Code-branch gain per episode & \missing & \missing & \missing & Completed equal-energy episodes. \\\\',
 r'Brier / ECE / AUPRC & \missing & \missing & \missing & Fixed-energy source-branch reward; separate logged-reward diagnostics in Table~\ref{tab:logged_calibration}. \\\\',
 r'Code gain per candidate / 1,000 tokens & \missing & \missing & \missing & Joined gain and complete usage. \\\\']:
 mb.append(line)
mb += [r'\\bottomrule',r'\\end{tabularx}',r'\\end{table*}']
mb='\n'.join(mb)
for x in ['begin','centering','footnotesize','caption','label','end','toprule','midrule','bottomrule','end{tabularx}']:
 mb=mb.replace('\\\\'+x,'\\'+x)
s=s[:start]+mb+s[end:]
# Avoid stale table paths after replacements and fix body path forms.
s=s.replace('\\input{revision_20260920/figures_updated_20260929/logged_calibration_table.tex}', '\\input{revision_20260920/figures_updated_20260929/logged_calibration_table.tex}')
p.write_text(s)
print('patched main.revised.tex')
