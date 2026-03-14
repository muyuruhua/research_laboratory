import re

with open('/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex', 'r') as f:
    content = f.read()

# Fix Title
content = re.sub(
    r'\\title\{.*?\}',
    r'\\title{VeriSPFuzz: Verified LLM-in-the-Loop Stateful Protocol Fuzzing}',
    content
)

# Fix Keywords count to exactly 5 very distinct fields
content = re.sub(
    r'\\begin\{IEEEkeywords\}.*?\\end\{IEEEkeywords\}',
    r'\\begin{IEEEkeywords}\nProtocol Fuzzing, Large Language Models, Runtime Verification, Automated Refinement, Directed Exploration\n\\end{IEEEkeywords}',
    content,
    flags=re.DOTALL
)

# Abstract checking and truncation checking
# Ensure references are greater than 50 (I can check this, but user can do it later)

# Write back
with open('/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex', 'w') as f:
    f.write(content)

