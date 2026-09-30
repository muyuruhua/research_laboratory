from pathlib import Path
import re,json,hashlib,subprocess,ast,collections,difflib,importlib.util
B=Path(__file__).resolve().parent.parent;A=B/'evidence_scope_20260930';BK=A/'before';s=(B/'main.revised.tex').read_text();o=(BK/'main.revised.tex').read_text();manifest=json.loads((A/'manifest.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args):return subprocess.check_output(args,cwd=B,text=True,stderr=subprocess.PIPE)
def floats(t):return {re.search(r'\\label\{([^}]+)\}',m[0])[1]:m[0] for m in re.finditer(r'\\begin\{(table\*?|figure\*?)\}.*?\\end\{\1\}',t,re.S)}
def rows(t):return [[v.strip() for v in l.rstrip()[:-2].split(' & ')] for l in t.splitlines() if ' & ' in l and l.rstrip().endswith('\\\\')]
a=floats(o);b=floats(s);assert set(a)-set(b)=={'tab:repair'} and not(set(b)-set(a))
for key in set(a)&set(b):
 if key!='tab:mechanisms':assert rows(a[key])==rows(b[key]),('Retained data changed',key)
oldrows={r[0]:r for r in rows(a['tab:mechanisms'])};newrows=rows(b['tab:mechanisms']);assert len(rows(a['tab:mechanisms']))-len(newrows)==5
for r in newrows:
 key='Code-branch gain per episode' if r[0]=='Recorded code-edge gain / episode' else r[0]
 assert oldrows[key][1:4]==r[1:4],key
assert r'\label{tab:repair}' not in s
inputs=[]
for name in re.findall(r'\\input\{([^{}]+)\}',s):
 p=B.parent/name
 if not p.suffix:p=p.with_suffix('.tex')
 inputs.append(p)
body=s.split(r'\begin{document}',1)[1]+'\n'+'\n'.join(p.read_text() for p in inputs)
assert r'\missing' not in body
assert not re.search(r'blanks indicate|Blank numeric cells|unfilled causal results|only strictly comparable',body)
for name,digest in manifest['protected_files'].items():assert sha(B/name)==digest,name
requirements=Path('/home/ckt/Documents/000_2026_test_dev/C_two_papers/first_paper.md');assert sha(requirements)==manifest['requirements_sha256']
# All substantive mathematics and author information are unchanged.
for env in ['equation','equation*','align','align*','keyword','tikzpicture']:
 pat=r'\\begin\{'+re.escape(env)+r'\}.*?\\end\{'+re.escape(env)+r'\}'
 assert re.findall(pat,s,re.S)==re.findall(pat,o,re.S),env
assert re.findall(r'\\\[.*?\\\]',s,re.S)==re.findall(r'\\\[.*?\\\]',o,re.S)
assert s[s.index(r'\author'):s.index(r'\begin{abstract}')]==o[o.index(r'\author'):o.index(r'\begin{abstract}')]
abstract=re.search(r'\\begin\{abstract\}(.*?)\\end\{abstract\}',s,re.S)[1].strip();assert 150<=len(abstract.split())<=200
keywords=re.search(r'\\begin\{keyword\}(.*?)\\end\{keyword\}',s,re.S)[1];assert len(keywords.split(r'\sep'))<=5
# Existing numeric discrepancy is corrected only against the saved evidence summary.
m=json.loads((B/'filled_mechanism_data_20260930.json').read_text());assert (m['E']['candidates'],m['E']['trials'],m['E']['dispositions']['reject'])==(746,745,736)
assert '746/745 candidates/trials' in s and 'E has 736 rejections' in s
assert '735/734 candidates/trials' not in s and 'E has 725 rejections' not in s
scope_assertions=['integrated controller design and a retrospective boundary analysis','Productivity calibration is an exploratory scheduling component','optional feature without quantitative evaluation','no reduction in queue pollution or improvement in downstream productivity or cost efficiency is claimed','Missing validation is not a measured null effect','The four replay cases do not meet that benchmark requirement','Recorded code-edge gain / episode']
for x in scope_assertions:assert x in s,x
assert (B/'main.revised.bbl').read_bytes()==(BK/'main.revised.bbl').read_bytes(),'Bibliography changed'
# Verify every current citation and figure/table reference has a live PDF target.
info=run(['pdfinfo','main.revised.pdf']);pages=int(re.search(r'^Pages:\s*(\d+)',info,re.M)[1])
oldinfo=run(['pdfinfo',str(BK/'main.revised.pdf')]);oldpages=int(re.search(r'^Pages:\s*(\d+)',oldinfo,re.M)[1])
labels={};aux=(B/'main.revised.aux').read_text()
for line in aux.splitlines():
 x=re.match(r'^\\newlabel\{([^{}]+)\}\{\{(.*?)\}\{(\d+)\}.*\{([^{}]+)\}\{\}\}$',line)
 if x:labels[x[1]]={'number':x[2],'page':int(x[3]),'destination':x[4]}
dests={}
for line in run(['pdfinfo','-dests','main.revised.pdf']).splitlines():
 x=re.match(r'\s*(\d+)\s+\[\s*XYZ\s+(-?\d+)\s+(-?\d+)\s+null\s*\]\s+"([^"]+)"',line)
 if x:dests[x[4]]={'page':int(x[1]),'x':int(x[2]),'y':int(x[3])}
inspector=ast.parse((B/'verify_reference_links_20260930.py').read_text())
ps=next(ast.literal_eval(x.value) for x in inspector.body if isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ps' for t in x.targets))
(A/'inspect_links.ps').write_text(ps);annotations=run(['gs','-q','-dNODISPLAY','-dBATCH','-dNOSAFER','-f',str(A/'inspect_links.ps')]);(A/'pdf_links.txt').write_text(annotations)
links=[]
for line in annotations.splitlines():
 if line.startswith('EXTERNAL\t'):continue
 assert line.startswith('INTERNAL\t'),line
 _,page,dest,rect=line.split('\t',3);assert dest in dests
 xy=list(map(float,re.findall(r'-?\d+(?:\.\d+)?',rect)));assert len(xy)==4 and xy[2]>xy[0] and xy[3]>xy[1]
 links.append({'page':int(page),'destination':dest})
counts=collections.Counter(x['destination'] for x in links)
get_cites=lambda t:[key.strip() for g in re.findall(r'\\cite(?:\[[^]]*\])?\{([^{}]+)\}',t) for key in g.split(',')]
assert get_cites(s)==get_cites(o)
cites=get_cites(body);bibkeys=set(re.findall(r'\\bibcite\{([^{}]+)\}',aux));assert len(bibkeys)==51 and set(cites)==bibkeys
for key,n in collections.Counter(cites).items():assert counts['cite.'+key]>=n,(key,n)
refkeys=re.findall(r'\\(?:ref|figref)\{([^{}]+)\}',body)+[x[1] for x in re.findall(r'\\namedref\{([^{}]+)\}\{([^{}]+)\}',body)]
for key,n in collections.Counter(refkeys).items():
 assert key in labels,key
 entry=labels[key];assert entry['page']==dests[entry['destination']]['page'];assert counts[entry['destination']]>=n,(key,n)
fl={k:v for k,v in labels.items() if k.startswith(('fig:','tab:'))};assert len(fl)==28
assert len([k for k in fl if k.startswith('tab:')])==19
assert len([k for k in fl if k.startswith('fig:')])==9
assert labels['tab:cve']['number']=='16' and labels['tab:cveresults']['number']=='17' and labels['tab:threats']['number']=='18'
for key,entry in fl.items():assert entry['page']==dests[entry['destination']]['page'],key
log=(B/'main.revised.log').read_text(errors='replace');bad=[l for l in log.splitlines() if re.search(r'Overfull|undefined|destination with the same identifier|^!|LaTeX Warning:',l)];assert not bad,bad
assert not re.search(r'^\s*\d+\s+\d+\s+',run(['pdfimages','-list','main.revised.pdf']),re.M)
sp=importlib.util.spec_from_file_location('refine',B/'refine_float_text.py');mod=importlib.util.module_from_spec(sp);sp.loader.exec_module(mod)
mainhash=sha(B/'main.revised.tex');assert mod.apply_edits()==[] and mainhash==sha(B/'main.revised.tex')
report={'status':'PASS','removed_table14_rows':5,'removed_empty_cells':26,'removed_float':'tab:repair','tables':19,'figures':9,'abstract_words':len(abstract.split()),'keywords':len(keywords.split(r'\sep')),'retained_numeric_table_cells_unchanged':True,'equations_authors_and_vector_figures_unchanged':True,'narrative_counts_corrected_from_existing_summary':manifest['narrative_count_correction'],'references':len(bibkeys),'citation_uses':len(cites),'internal_links':len(links),'figure_table_destinations':len(fl),'pages_before':oldpages,'pages_after':pages,'raster_images':0,'underfull_notices':len(re.findall('Underfull',log)),'overfull_or_undefined_errors':bad,'postprocessor_idempotent':True,'scope':'Integrated controller design and retrospective boundary analysis; calibration exploratory; repair unquantified; no completed causal or controlled rediscovery claim','scope_assertions':scope_assertions,'protected_files':manifest['protected_files'],'requirements_sha256':sha(requirements),'tex_sha256':sha(B/'main.revised.tex'),'pdf_sha256':sha(B/'main.revised.pdf'),'float_pages':fl}
(A/'validation.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
(A/'changes.diff').write_text(''.join(difflib.unified_diff(o.splitlines(True),s.splitlines(True),fromfile='before/main.revised.tex',tofile='main.revised.tex')))
run(['pdftotext','-layout','main.revised.pdf',str(A/'main.revised.txt')])
print(json.dumps({k:v for k,v in report.items() if k not in ['scope_assertions','protected_files','float_pages']},indent=2))
