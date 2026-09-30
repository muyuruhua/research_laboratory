from pathlib import Path
import shutil,json,hashlib
R=Path('/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/loopfuzz/revision_20260920');B=R/'figure2_balanced_layout';B.mkdir(exist_ok=True);(B/'before').mkdir(exist_ok=True)
for name in ['main.revised.tex','main.revised.pdf','main.revised.aux','main.revised.bbl']:
 dst=B/'before'/name
 if not dst.exists():shutil.copy2(R/name,dst)
s=(R/'main.revised.tex').read_text();k=s.index(r'\label{fig:architecture}');a=s.rfind(r'\begin{figure*}',0,k);b=s.index(r'\end{figure*}',k)+len(r'\end{figure*}');old=s[a:b]
assert '(llm) at (0,0)' in old,'Inspect the changed figure before reapplying.'
new=r'''\begin{figure*}[!tbp]
\centering
\begin{tikzpicture}[
  font=\fontsize{9}{11}\selectfont,
  box/.style={draw=black!75,line width=0.6pt,rounded corners=2pt,
    align=center,text width=23mm,minimum width=26mm,
    minimum height=13mm,inner sep=3pt},
  flow/.style={-{Latex[length=2.5mm,width=1.7mm]},
    draw=black!85,line width=0.85pt,rounded corners=2pt,
    shorten <=1pt,shorten >=1pt},
  failure/.style={flow,dashed},
  failbranch/.style={draw=black!70,line width=0.7pt,dashed},
  condition/.style={font=\fontsize{8.5}{10}\selectfont,
    text=black,fill=white,inner sep=1.2pt,align=center}]
\node[box,fill=blue!5] (llm) at (0,3.4) {LLM\\proposal};
\node[box] (p) at (4.4,3.4) {Structural\\check $P$};
\node[box] (trial) at (8.8,3.4) {Bounded trial\\check $U,R$};
\node[box,fill=blue!5] (gain) at (13.2,3.4) {Separate\\$\gcode,\gstate$};
\node[box,fill=black!4] (rej) at (0,0) {Reject / expire\\retain evidence};
\node[box,fill=orange!12] (prov) at (4.4,0) {Provisional\\queue};
\node[box,fill=orange!5] (validation) at (8.8,0) {Descendant\\validation};
\node[box,fill=blue!8] (dur) at (13.2,0) {Durable\\queue};

\draw[flow] (llm.east)--(p.west);
\draw[flow] (p.east)--node[condition,above] (p_ok) {pass}(trial.west);
\draw[flow] (trial.east)--node[condition,above] (ur_ok) {pass}(gain.west);
\draw[flow] (gain.south)--node[condition,right] (code_gate) {$\gcode$}(dur.north);
\draw[flow] (gain.south)--node[condition,below,pos=.45] (state_gate) {$\gstate$ only}(prov.north);
\draw[flow] (prov.east)--(validation.west);
\draw[flow] (validation.east)--node[condition,below] (promotion) {Validated\\code gain}(dur.west);

\coordinate (reject_join) at (0,1.4);
\draw[failbranch] (p.south)--node[condition,above,pos=.35] (p_fail) {$\neg P$}(reject_join);
\draw[failbranch] (trial.south)--node[condition,above,pos=.33] (ur_fail) {$\neg U\lor\neg R$}(reject_join);
\draw[failbranch] (gain.south)--node[condition,above,pos=.36] (no_gain) {Neither gain}(reject_join);
\fill[black!75] (reject_join) circle[radius=1.1pt];
\draw[failure] (reject_join)--(rej.north);
\draw[failure] (validation.south)--(8.8,-1.5)--
  node[condition,above] (expiry) {Budget exhausted}(0,-1.5)--(rej.south);
\end{tikzpicture}
\caption{Evidence-gated admission with provisional and durable queues.}
\label{fig:architecture}
\end{figure*}'''
(R/'main.revised.tex').write_text(s[:a]+new+s[b:]);assert (R/'main.revised.tex').read_text().replace(new,'<FIG2>',1)==s.replace(old,'<FIG2>',1)
(B/'figure2.before.block.tex').write_text(old+'\n');(B/'figure2.after.block.tex').write_text(new+'\n')
prefix=r'''\documentclass[tikz,border=5pt]{standalone}
\usepackage{amsmath,amssymb,txfonts}
\usetikzlibrary{arrows.meta,positioning,fit,calc}
\newcommand{\gcode}{G_{\mathrm{code}}}
\newcommand{\gstate}{G_{\mathrm{state}}}
\begin{document}
'''
boxes=['llm','p','trial','gain','rej','prov','validation','dur'];labels=['p_ok','ur_ok','code_gate','state_gate','promotion','p_fail','ur_fail','no_gain','expiry']
for version,block in [('before',old),('after',new)]:
 pic=block[block.index(r'\begin{tikzpicture}'):block.index(r'\end{tikzpicture}')]
 names=boxes+labels if version=='after' else [x for x in boxes if x!='validation']+labels
 for name in names:
  for corner,short in [('south west','sw'),('north east','ne')]:pic+='\n'+r'\path ('+name+'.'+corner+r');\pgfgetlastxy{\figx}{\figy}\typeout{FIG2|'+name+'|'+short+r'|\figx|\figy}'
 (B/f'figure2_{version}.tex').write_text(prefix+pic+'\n'+r'\end{tikzpicture}'+'\n'+r'\end{document}'+'\n')
manifest={'scope':'Figure 2 only; balanced two-row four-column layout','box_names':boxes,'label_names':labels,'expected_arrowheads':9,'main_font_pt':9,'condition_font_pt':8.5,'new_node_basis':'The existing bounded descendant-validation stage required for provisional-to-durable promotion.','requirements_sha256':hashlib.sha256(Path('/home/ckt/Documents/000_2026_test_dev/C_two_papers/first_paper.md').read_bytes()).hexdigest()}
(B/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
shutil.copy2(Path(__file__),B/'rebalance_figure2.py')
print('Replaced only Figure 2 with an aligned 2 x 4 layout.')
