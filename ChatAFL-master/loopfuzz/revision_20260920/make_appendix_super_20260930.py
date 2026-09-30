from pathlib import Path
import json
BASE=Path(__file__).resolve().parent
D=json.loads((BASE/'filled_experiment_data_20260930.json').read_text())['aggregate']
T=['lightftp','bftpd','proftpd','pure-ftpd','exim','live555','kamailio','forked-daapd','lighttpd1'];N=dict(zip(T,['LightFTP','bftpd','ProFTPD','Pure-FTPd','Exim','Live555','Kamailio','Forked-daapd','Lighttpd1']))
def d(a,t):return D.get(a+'|'+t)
def pm(x,k):return r'\missing' if not x else f'{x[k]["mean"]:.1f}$\\pm${x[k]["sd"]:.1f}'
def status(x):
 m={'completed':'C','exit_137_near_limit':'X','sigabrt':'S','oom_killed':'O'}
 return ','.join(f'{m.get(k,k)}:{v}' for k,v in x['status'].items())
L=['% Generated from current Key_Experiment archives on 2026-09-30.',r'\begingroup',r'\small',r'\setlength{\tabcolsep}{1.6pt}',r'\renewcommand{\arraystretch}{1.0}',r'\noindent Row IDs combine arm and target number. Arms A--E retain their main-text meanings; $E_{99}$ and $E_{100}$ denote sensitivity groups at $\gamma=0.99$ and $\gamma=1.0$.',r'\par\smallskip',r'\noindent\begin{tabularx}{\columnwidth}{@{}YYY@{}}',r'1: LightFTP & 4: Pure-FTPd & 7: Kamailio \\',r'2: bftpd & 5: Exim & 8: Forked-daapd \\',r'3: ProFTPD & 6: Live555 & 9: Lighttpd1 \\',r'\end{tabularx}',r'\par\smallskip',r'\noindent AUC is measured in branch-hours; IPSM denotes state edges. Status codes reproduce the archive: C=completed, X=exit\_137\_near\_limit, S=sigabrt, O=oom\_killed; they do not independently identify failure causes. Missing target--arm combinations have no row and are not zero-valued observations.',r'\par\smallskip',r'\captionof{table}{Complete current archive observations (mean $\pm$ sample SD). The nominal target is $N=10$; $n$ is the observed count. AUC integrates each recorded trajectory in branch-hours. Missing target--arm combinations have no row and remain unavailable.}',r'\label{tab:archive_arms}',r'\tablefirsthead{\toprule ID & $n$ & Branches & AUC & IPSM & Status \\ \midrule}',r'\tablehead{\multicolumn{6}{l}{Table~\thetable\ (continued)}\\ \toprule ID & $n$ & Branches & AUC & IPSM & Status \\ \midrule}',r'\tabletail{\bottomrule}',r'\tablelasttail{\bottomrule}',r'\noindent\begin{supertabular}{@{}lrrrrl@{}}']
rb='\\\\'
for a in ['A','B','C','D','E','E-gamma099','E-gamma100']:
 for i,t in enumerate(T,1):
  x=d(a,t)
  if x:
   aid={'E-gamma099':r'$E_{99}$','E-gamma100':r'$E_{100}$'}.get(a,a)
   L.append(f'{aid}{i} & {x["runs_available"]} & {pm(x,"branches")} & {pm(x,"auc_branch_hours")} & {pm(x,"ipsm_edges")} & {status(x)} {rb}')
L += [r'\end{supertabular}',r'\endgroup']
(BASE/'archive_arm_results.updated_20260930.tex').write_text('\n'.join(L)+'\n')
print('appendix rows',sum(1 for x in L if ' & ' in x and x[0] in 'ABCDE$'))
