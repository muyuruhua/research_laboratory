import subprocess
import re
import os

dir_path = "/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM"
tex_file = "main.tex"

os.chdir(dir_path)

result = subprocess.run(['pdflatex', '-interaction=nonstopmode', tex_file], capture_output=True, text=True)

match = re.search(r'Output written on main\.pdf \((\d+) pages', result.stdout)
if match:
    print(f"Number of pages: {match.group(1)}")
else:
    print("Could not find page count in output.")
