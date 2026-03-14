
vim fix_figures.py
import re

def main():
    with open('main.tex', 'r') as f:
        text = f.read()

    text = re.sub(r"\\begin\{figure\*\}\[htbp\].*?figures/state_coverage\.pdf.*?\\end\{figure\*\}", "", text, flags=re.DOTALL)
    text = re.sub(r"\\begin\{figure\*\}\[htbp\].*?figures/edge_coverage\.pdf.*?\\end\{figure\*\}", "", text, flags=re.DOTALL)

    text = re.sub(r"\n{3,}", "\n\n", text)

    figs = r"""\begin{figure*}[t]
\centering
\includegraphics[width=\textwidth]{figures/state_coverage.pdf}
\vspace{-2mm}
\caption{Fuzzing campaign trajectories over 24 hours. The top panels show IPSM-edge discovery (reflecting semantic plateau escape), while the bottom panels show code-edge coverage. Plotted dynamics correspond to the completed normalized comparison suite.}
\label{fig:trajectories}
\vspace{2mm}
\includegraphics[width=\textwidth]{figures/edge_coverage.pdf}
\end{figure*}
"""

    text = text.replace(r"\section{Results}", r"\section{Results}" + "\n\n" + figs)

    with open('main.tex', 'w') as f:
        f.write(text)

if __name__ == "__main__":
    main()
^[
:wq

n3 fix_figures.py && pdflatex -interaction=nonstopmode main.tex

