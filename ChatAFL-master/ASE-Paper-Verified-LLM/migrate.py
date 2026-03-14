import re
with open('main.tex', 'r') as f: text = f.read()
p1 = r'\begin{figure\*}\[htbp\].*?figures/state_coverage\.pdf.*?\end{figure\*}'
text = re.sub(p1, '', text, flags=re.DOTALL)
p2 = r'\begin{figure\*}\[htbp\].*?figures/edge_coverage\.pdf.*?\end{figure\*}'
text = re.sub(p2, '', text, flags=re.DOTALL)
text = re.sub(r'
{3,}', '

', text)
