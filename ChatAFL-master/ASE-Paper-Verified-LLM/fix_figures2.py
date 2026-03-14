import re

with open('main.tex', 'r') as f:
    text = f.read()

# remove old figs
p1 = r"\\begin\{figure\*\}\[htbp\]\s*\\centering\s*\\includegraphics\[width=\\textwidth\]\{figures/state_coverage\.pdf\}\s*.*?\\end\{figure\*\}"
text = re.sub(p1, "", text, flags=re.DOTALL)

p2 = r"\\begin\{figure\*\}\[htbp\]\s*\\centering\s*\\includegraphics\[width=\\textwidth\]\{figures/edge_coverage\.pdf\}\s*.*?\\end\{figure\*\}"
text = re.sub(p2, "", text, flags=re.DOTALL)

# condense new lines
text = re.sub(r"\n{3,}", "\n\n", text)

figs = r"""\begin{figure*}[t]
\centering
\includegraphics[width=\textwidth]{figures/state_coverage.pdf}
\vspace{-2mm}
\caption{Fuzzing campaign trajectories over 24 hours. The top panels show IPSM-edge discovery (reflecting semantic plateau escape), while the bottom panels show code-edge coverage. Plotted dynamics correspond to the completed normalized comparison suite.}
\label{fig:trajectories}
\vspace{2mm}
\includegraphics[width=\textwidth]{figures/edge_coveragimport re

with open('main.tex =
with oppla    text = f.read()

# remove oti
# remove old figs\n"p1 = r"\\begin\{latext = re.sub(p1, "", text, flags=re.DOTALL)

p2 = r"\\begin\{figure\*\}\[htbp\]\s*\\centering\s*\\includegraphics\[width=\\textwidth\]\{figure t
p2 = r"\\begin\{figure\*\}\[htbp\]\s*\\cenef{text = re.sub(p2, "", text, flags=re.DOTALL)

# condense new lines
text = re.sub(r"\n{3,}", "\n\n", text)

figs = r"""\begin{figure*}[t]
\centain.tex', 'w') as f:
    f.write(text)
