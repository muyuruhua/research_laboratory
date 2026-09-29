#!/usr/bin/env python3
"""Reflow the same 60 archive rows into a readable table across portrait columns."""
from pathlib import Path
import re
BASE=Path(__file__).resolve().parent
source=(BASE/'archive_arm_results.layout_20260928.tex').read_text()
rows=[line for line in source.splitlines() if re.match(r'[ABCDE](?:,| &)',line)]
assert len(rows)==60
names=['LightFTP','bftpd','ProFTPD','Pure-FTPd','Exim','Live555','Kamailio','Forked-daapd','Lighttpd1']
arm_code={a:a for a in 'ABCDE'}|{r'E, $\gamma=.99$':r'E_{99}',r'E, $\gamma=1$':r'E_{100}'}
caption=re.search(r'\\caption\{(.*?)\}\\label',source).group(1)
# Group and target identifiers preserve unambiguous row identity in every column.
parts=[r'% Same observations as archive_arm_results.layout_20260928.tex; no rounding changes.',
       r'\begingroup',r'\small',r'\setlength{\tabcolsep}{1.6pt}',r'\renewcommand{\arraystretch}{1.05}',
       r'\noindent Row IDs combine the arm and target number. Arms A--E retain their main-text meanings; $E_{99}$ and $E_{100}$ denote the E sensitivity groups at $\gamma=0.99$ and $\gamma=1.0$. Target numbers are:',
       r'\par\smallskip',r'\noindent\begin{tabularx}{\columnwidth}{@{}YYY@{}}',
       r'1: LightFTP & 4: Pure-FTPd & 7: Kamailio \\',
       r'2: bftpd & 5: Exim & 8: Forked-daapd \\',
       r'3: ProFTPD & 6: Live555 & 9: Lighttpd1 \\',r'\end{tabularx}',r'\par\smallskip',
       r'\noindent AUC is measured in branch-hours; IPSM denotes state edges. Status labels reproduce the archive: C = \texttt{completed}; X = \texttt{exit\_137\_near\_limit}; S = \texttt{sigabrt}; O = \texttt{oom\_killed}. Missing target--arm combinations have no row and are not zero-valued observations.',r'\par\smallskip',
       r'\captionof{table}{'+caption+r'}\label{tab:archive_arms}',
       r'\tablefirsthead{\toprule ID & $n$ & Branches & AUC & IPSM & Status \\ \midrule}',
       r'\tablehead{\multicolumn{6}{l}{Table~\thetable\ (continued)}\\ \toprule ID & $n$ & Branches & AUC & IPSM & Status \\ \midrule}',
       r'\tabletail{\bottomrule}',r'\tablelasttail{\bottomrule}',
       r'\noindent\begin{supertabular}{@{}lrrrrl@{}}']
for row in rows:
    arm,target,count,*values=[c.strip() for c in row.removesuffix(r'\\').split(' & ')]
    identifier=f"${arm_code[arm]}{names.index(target)+1}$"
    values=[v.replace(r' $\pm$ ',r'$\pm$').replace(', ', ',') for v in values]
    parts.append(' & '.join([identifier,count,*values])+r' \\')
parts += [r'\end{supertabular}',r'\endgroup','']
(BASE/'archive_arm_results.flow_20260928.tex').write_text('\n'.join(parts))
print('Wrote 60 rows, nominal 9pt, no scaling or omitted observations.')
