#!/usr/bin/env python3
"""Check independent abstract/body acronym scopes and terminology-only edits."""
from pathlib import Path
import re,json,hashlib,subprocess,ast
BASE=Path(__file__).resolve().parent
s=(BASE/'main.revised.tex').read_text();bs=chr(92)
d=json.loads((BASE/'acronym_consistency_validation.json').read_text());backup=BASE/d['backup']
abstract=s.split(bs+'begin{abstract}',1)[1].split(bs+'end{abstract}',1)[0]
body=s[s.index(bs+'section{Introduction}'):]
body=re.sub(r'\\input\{([^}]+)\}',lambda m:(BASE.parent/m.group(1)).read_text(),body)

def check_term(text,definition,acronym,full_pattern):
    assert text.count(definition)==1,(acronym,'definition count')
    marker=text.index(definition)+definition.index('('+acronym+')')+1
    first=re.search(r'\b'+re.escape(acronym.rstrip('s'))+r's?\b',text)
    assert first and first.start()==marker,(acronym,'use precedes definition')
    tail=text[text.index(definition)+len(definition):]
    assert not re.search(full_pattern,tail,re.I),(acronym,'repeated expansion')

for scope in [abstract,body]:
    check_term(scope,'large language models (LLMs)','LLMs',r'\blarge language models?\b')
    check_term(scope,'inferred protocol state machine (IPSM)','IPSM',r'\binferred protocol state machines?\b')
for definition,acronym,pattern in [
    ('sample standard deviation (SD)','SD',r'\bstandard deviations?\b'),
    ('area under the code-branch coverage curve (AUC)','AUC',r'area under the code-branch coverage curve'),
    ('Brier score (BS)','BS',r'\bBrier(?: score)?\b'),
    ('Expected calibration error (ECE)','ECE',r'\bexpected calibration error\b'),
    ('area under the precision--recall curve (AUPRC)','AUPRC',r'area under the precision(?:--|-)recall curve'),
    ('non-interpolated average precision (AP)','AP',r'\baverage precision\b'),
    ('confidence intervals (CIs)','CIs',r'\bconfidence intervals?\b')]:
    check_term(body,definition,acronym,pattern)

old=(backup/'main.revised.tex').read_text()
assert re.findall(r'\d+(?:[.,]\d+)*',old)==re.findall(r'\d+(?:[.,]\d+)*',s),'Numeric literals changed'
assert re.findall(r'\$[^$]*\$',old)==re.findall(r'\$[^$]*\$',s),'Inline mathematics changed'
assert re.findall(r'\\cite\w*\{[^}]+\}',old)==re.findall(r'\\cite\w*\{[^}]+\}',s),'Citations changed'
for env in ['equation','align','algorithm']:
    pattern=r'\\begin\{'+env+r'\}.*?\\end\{'+env+r'\}'
    assert re.findall(pattern,old,re.S)==re.findall(pattern,s,re.S),env+' changed'
cal='figures_updated_20260929/logged_calibration_table.tex'
rows=lambda t:[line for line in t.splitlines() if ' & ' in line and not line.startswith('Target &')]
assert rows((backup/cal).read_text())==rows((BASE/cal).read_text()),'Calibration values changed'
# Retain the explicit prohibition, not a use of U(s) to denote productivity.
assert all('utility is never denoted $U(s)$.' in line for line in s.splitlines() if 'U(s)' in line)
assert bs+'gcode' in s and bs+'gstate' in s
assert 150<=len(abstract.split())<=200
assert len(re.findall(r"[A-Za-z0-9]+(?:'[A-Za-z0-9]+)?",abstract))<=200
assert len(s.split(bs+'begin{keyword}',1)[1].split(bs+'end{keyword}',1)[0].split(bs+'sep'))<=5
for f in ['plot_updated_figures_20260929.py','fix_tables_main_20260929.py']:
    ast.parse((BASE/f).read_text())
assert 'BS / ECE / AUPRC &' in (BASE/'fix_tables_main_20260929.py').read_text()
assert 'non-interpolated AP.' in (BASE/'plot_updated_figures_20260929.py').read_text()
log=(BASE/'main.revised.log').read_text()
for bad in ['! LaTeX Error','! Undefined','Fatal error','Overfull '+bs+'hbox','Float too large','undefined citations','undefined references']:
    assert bad not in log,bad
assert not re.search(r'(?:Citation|Reference) .+ undefined',log)
text=(BASE/'main.revised.txt').read_text()
assert text.count('large language models (LLMs)')==2
assert len(re.findall(r'inferred protocol state\s+machine \(IPSM\)',text))==2
info=subprocess.check_output(['pdfinfo',str(BASE/'main.revised.pdf')],text=True)
d.update(status='PASS',normalized_terms=['LLM/LLMs','IPSM','SD/SDs','AUC','BS','ECE','AUPRC','AP','CI/CIs'],independent_scopes_verified=True,repeated_expansions_after_definition=0,numerical_literals_unchanged=True,formulae_unchanged=True,citations_unchanged=True,calibration_table_data_unchanged=True,script_syntax_valid=True,pdf_pages=int(re.search(r'Pages:\s+(\d+)',info).group(1)),build_errors=0,undefined_references=0,manuscript_sha256=hashlib.sha256((BASE/'main.revised.tex').read_bytes()).hexdigest(),pdf_sha256=hashlib.sha256((BASE/'main.revised.pdf').read_bytes()).hexdigest())
(BASE/'acronym_consistency_validation.json').write_text(json.dumps(d,ensure_ascii=False,indent=2)+chr(10))
print(json.dumps({k:v for k,v in d.items() if k not in ['main_edits','source_requirement_sha256','manuscript_sha256','pdf_sha256']},ensure_ascii=False,indent=2))
