from pathlib import Path
import json,hashlib
B=Path(__file__).resolve().parent;R=B.parent;P=R/'main.revised.tex'
s=P.read_text();label=s.index(r'\label{fig:architecture}');a=s.rfind(r'\begin{figure*}',0,label);b=s.index(r'\end{figure*}',label)+len(r'\end{figure*}')
old=s[a:b]
new=r'''\begin{figure*}[!tbp]
\centering
\begin{tikzpicture}[
  font=\fontsize{9}{11}\selectfont,
  box/.style={draw=black!75,line width=0.6pt,rounded corners=2pt,
    align=center,text width=21mm,minimum width=24mm,
    minimum height=13mm,inner sep=3pt},
  queue/.style={box,text width=27mm,minimum width=30mm,
    minimum height=15mm},
  flow/.style={-{Latex[length=2.5mm,width=1.7mm]},
    draw=black!85,line width=0.85pt,rounded corners=2pt,
    shorten <=1pt,shorten >=1pt},
  failure/.style={flow,dashed},
  condition/.style={font=\fontsize{8.5}{10}\selectfont,
    text=black,fill=white,inner sep=1.2pt,align=center}]
\node[box,fill=blue!5] (llm) at (0,0) {LLM proposal};
\node[box] (p) at (3.4,0) {Structural\\check $P$};
\node[box] (trial) at (6.8,0) {Bounded trial\\check $U,R$};
\node[box,fill=blue!5] (gain) at (10.2,0) {Separate\\$\gcode,\gstate$};
\node[queue,fill=blue!8] (dur) at (14,1.5) {Durable queue\\code evidence};
\node[queue,fill=orange!12] (prov) at (14,-1.5) {Provisional queue\\bounded validation};
\node[queue,fill=black!4] (rej) at (6.8,-2.8) {Reject / expire\\retain evidence};

\draw[flow] (llm.east)--(p.west);
\draw[flow] (p.east)--node[condition,above] (p_ok) {pass}(trial.west);
\draw[flow] (trial.east)--node[condition,above] (ur_ok) {pass}(gain.west);
\draw[flow] (gain.north)|-node[condition,above,pos=.7] (code_gate) {$\gcode$}(dur.west);
\draw[flow] (gain.south)|-node[condition,above,pos=.7] (state_gate) {$\gstate$ only}(prov.west);
\draw[flow] (prov.north)--node[condition,right] (promotion) {Validated\\code gain}(dur.south);

\draw[failure] (p.south)|-node[condition,left,pos=.25] (p_fail) {$\neg P$}(rej.west);
\draw[failure] (trial.south)--node[condition,right] (ur_fail) {$\neg U\lor\neg R$}(rej.north);
\draw[failure] (gain.south west)|-(rej.east);
\node[condition,anchor=west] (no_gain) at (9.12,-2.05) {Neither gain};
\draw[failure] (prov.south)--(14,-4.3)--
  node[condition,above] (expiry) {Budget exhausted}(6.8,-4.3)--(rej.south);
\end{tikzpicture}
\caption{Evidence-gated admission with provisional and durable queues.}
\label{fig:architecture}
\end{figure*}'''
assert 'text width=26mm' in old,'Figure already changed; inspect before reapplying.'
P.write_text(s[:a]+new+s[b:])
assert P.read_text().replace(new,'<FIGURE2>',1)==s.replace(old,'<FIGURE2>',1)
(B/'figure2_before.tex.txt').write_text(old+'\n');(B/'figure2_after.tex.txt').write_text(new+'\n')
preamble=r'''\documentclass[tikz,border=5pt]{standalone}
\usepackage{amsmath,amssymb,txfonts}
\usetikzlibrary{arrows.meta,positioning,fit,calc}
\newcommand{\gcode}{G_{\mathrm{code}}}
\newcommand{\gstate}{G_{\mathrm{state}}}
\begin{document}
'''
boxes=['llm','p','trial','gain','dur','prov','rej'];labels=['p_ok','ur_ok','code_gate','state_gate','promotion','p_fail','ur_fail','no_gain','expiry']
for version,block in [('before',old),('after',new)]:
 pic=block[block.index(r'\begin{tikzpicture}'):block.index(r'\end{tikzpicture}')]
 measure=[]
 for name in boxes+(labels if version=='after' else []):
  for corner in ['south west','north east']:
   short='sw' if corner=='south west' else 'ne'
   measure.append(r'\path ('+name+'.'+corner+r');\pgfgetlastxy{\figx}{\figy}\typeout{FIG2|'+name+'|'+short+r'|\figx|\figy}')
 (B/f'figure2_{version}.tex').write_text(preamble+pic+'\n'+'\n'.join(measure)+'\n'+r'\end{tikzpicture}'+'\n'+r'\end{document}'+'\n')
manifest={'scope':'Only Figure 2 layout and concise node/arrow labels','figure_label':'fig:architecture','unchanged_caption':True,'unchanged_text_outside_figure':True,'box_names':boxes,'label_names':labels,'arrow_count':10,'main_font_pt':9,'condition_font_pt':8.5,'arrowhead_length_mm':2.5,'arrowhead_width_mm':1.7,'line_width_pt':0.85,'requirements_sha256':hashlib.sha256(Path('/home/ckt/Documents/000_2026_test_dev/C_two_papers/first_paper.md').read_bytes()).hexdigest()}
(B/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Updated Figure 2 only; preserved every other character in the manuscript.')
