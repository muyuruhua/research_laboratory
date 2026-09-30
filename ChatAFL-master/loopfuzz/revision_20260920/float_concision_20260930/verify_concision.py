#!/usr/bin/env python3
from pathlib import Path
import ast,collections,difflib,hashlib,importlib.util,json,re,shutil,subprocess,tempfile
B=Path(__file__).resolve().parent.parent;A=B/'float_concision_20260930';BK=A/'before'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args):return subprocess.check_output(args,cwd=B,text=True,stderr=subprocess.PIPE)
spec=importlib.util.spec_from_file_location('refine',B/'refine_float_text.py');refine=importlib.util.module_from_spec(spec);spec.loader.exec_module(refine)
files=['main.revised.tex','observed_tables.updated_20260930.tex','observed_costs.updated_20260930.tex','figures_updated_20260930/logged_calibration_table.tex','archive_arm_results.updated_20260930.tex']
old={f:(BK/f).read_text() for f in files};new={f:(B/f).read_text() for f in files}
def blocks(text):
 return {re.search(r'\\label\{([^}]+)\}',m[0])[1]:m[0] for m in re.finditer(r'\\begin\{(table\*?|figure\*?)\}.*?\\end\{\1\}',text,re.S)}
def rows(t):return [[v.strip() for v in l.rstrip()[:-2].split(' & ')] for l in t.splitlines() if ' & ' in l and l.rstrip().endswith('\\\\')]
def words(t):
 t=re.sub(r'\\(?:namedref)\{[^}]+\}\{[^}]+\}','reference',t)
 t=re.sub(r'\\(?:cite|ref|figref)\{[^}]+\}','reference',t)
 t=re.sub(r'\\[A-Za-z]+\*?', '',t)
 return re.findall(r'[A-Za-z0-9]+(?:[-/][A-Za-z0-9]+)*',t)
oldblocks={};newblocks={};captions=[];cellchanges=[]
for f in files:
 ob,nb=blocks(old[f]),blocks(new[f]);oldblocks.update(ob);newblocks.update(nb)
 labs=re.findall(r'\\label\{((?:tab|fig):[^}]+)\}',new[f])
 assert labs==re.findall(r'\\label\{((?:tab|fig):[^}]+)\}',old[f]),f
 for lab in labs:
  a,z=refine.caption_span(old[f],lab);x=old[f][a:z]
  a,z=refine.caption_span(new[f],lab);y=new[f][a:z]
  captions.append({'file':f,'label':lab,'before':x,'after':y,'before_words':len(words(x)),'after_words':len(words(y)),'changed':x!=y})
  if lab.startswith('tab:') and lab!='tab:archive_arms':
   rr,ss=rows(ob[lab]),rows(nb[lab]);assert len(rr)==len(ss),lab
   for i,(r,s) in enumerate(zip(rr,ss)):
    assert len(r)==len(s),(lab,i)
    for col,(a,b) in enumerate(zip(r,s)):
     if a!=b:cellchanges.append({'label':lab,'row':r[0],'column':col,'before':a,'after':b,'before_words':len(words(a)),'after_words':len(words(b))})
assert len(captions)==29 and sum(c['label'].startswith('tab:') for c in captions)==20
for lab in ['tab:observed_inventory','tab:observed_endpoints','tab:observed_log_counts','tab:observed_costs','tab:logged_calibration','tab:mainresults']:
 a=rows(oldblocks[lab]);b=rows(newblocks[lab]);assert len(a)==len(b)
 for r,s in zip(a,b):
  if r[0] not in ['','Target']:
   assert r==s,('Numeric table row changed',lab,r[0])
assert rows(old['archive_arm_results.updated_20260930.tex'])==rows(new['archive_arm_results.updated_20260930.tex'])
for r,s in zip(rows(oldblocks['tab:mechanisms'])[1:],rows(newblocks['tab:mechanisms'])[1:]):assert r[1:4]==s[1:4],r[0]
for r,s in zip(rows(oldblocks['tab:targets'])[1:],rows(newblocks['tab:targets'])[1:]):assert r[:4]==s[:4],r[0]
assert {f:t.count(r'\missing') for f,t in old.items()}=={f:t.count(r'\missing') for f,t in new.items()}
for f,digest in json.loads((A/'protected_hashes.json').read_text()).items():assert sha(B/f)==digest,f
requirements=Path('/home/ckt/Documents/000_2026_test_dev/C_two_papers/first_paper.md')
assert sha(requirements)==sha(BK/'requirements/first_paper.md')
s=new['main.revised.tex'];o=old['main.revised.tex']
for env in ['abstract','keyword','equation','equation*','align','align*','tikzpicture']:
 pattern=r'\\begin\{'+re.escape(env)+r'\}.*?\\end\{'+re.escape(env)+r'\}'
 a=re.findall(pattern,o,re.S);b=re.findall(pattern,s,re.S)
 if env!='tikzpicture':assert a==b,env
 else:assert a[:1]==b[:1],'Architecture changed'
assert o[:o.index(r'\begin{abstract}')]==s[:s.index(r'\begin{abstract}')],'Preamble or authors changed'
assert re.findall(r'\\\[.*?\\\]',o,re.S)==re.findall(r'\\\[.*?\\\]',s,re.S)
assert (B/'references.expanded.bib').read_bytes()==(BK/'references.expanded.bib').read_bytes(),'Bibliography source changed'
# Preserve case-specific old table evidence without mixing denominators.
security=s[s.index(r'\section{Vulnerability Replay'):s.index(r'\section{Threats',s.index(r'\section{Vulnerability Replay'))]
required=['60,006','65,568','65,535','512','172/233','0/242','121 and 112','61 non-reproducing','9 teardown','1/1 seed','1/1 fuzzer-crash','3/3 batch-crash','0/3','728-byte','82/88','all 88','6 do not','3/3 repeats for each of three','8/9','1/1 persistence','278-byte','$-10$','102/253','0/253','193 of 253','3/4, 19/20, 19/20, and 50/51','2^{31}','77 and 176','36/77 and 66/176','-2147483648','-954437177','151/253','148-byte','5/5','3/3','48-message','1/1','0/5','27.2','28.4','not rediscovery','no arm-level recall']
for token in required:assert token in security,('Replay evidence missing',token)
# Verify zero-change second application and restoring copy edits from before snapshot.
source_names=files+['vulnerability_section_20260929.tex']
state={f:sha(B/f) for f in source_names}
assert refine.apply_edits()==[]
assert state=={f:sha(B/f) for f in source_names}
with tempfile.TemporaryDirectory(prefix='float_concision_',dir=A) as tmp:
 t=Path(tmp)
 for f in files:
  (t/f).parent.mkdir(parents=True,exist_ok=True);shutil.copy2(BK/f,t/f)
 for f in ['refine_float_text.py','concise_float_text.json']:shutil.copy2(B/f,t/f)
 shutil.copy2(BK/'vulnerability_section_20260929.tex',t/'vulnerability_section_20260929.tex')
 subprocess.run(['python3',str(t/'refine_float_text.py')],check=True,capture_output=True)
 for f in files:assert (t/f).read_bytes()==(B/f).read_bytes(),('Round-trip copy edit',f)
 # Unexpected input is rejected before any file write.
 q=t/'main.revised.tex';q.write_text(q.read_text().replace('Motivating hypotheses and current evidence.','Unexpected externally revised caption.',1))
 pre={f:sha(t/f) for f in source_names}
 test=subprocess.run(['python3',str(t/'refine_float_text.py')],capture_output=True,text=True)
 assert test.returncode!=0 and 'review required' in test.stderr
 assert pre=={f:sha(t/f) for f in source_names}
# PDF navigation: use existing read-only Ghostscript inspector, not obsolete assertions.
info=run(['pdfinfo','main.revised.pdf']);pages=int(re.search(r'^Pages:\s*(\d+)',info,re.M)[1])
oldinfo=run(['pdfinfo',str(BK/'main.revised.pdf')]);oldpages=int(re.search(r'^Pages:\s*(\d+)',oldinfo,re.M)[1])
aux=(B/'main.revised.aux').read_text();labels={}
for line in aux.splitlines():
 m=re.match(r'^\\newlabel\{([^{}]+)\}\{\{(.*?)\}\{(\d+)\}.*\{([^{}]+)\}\{\}\}$',line)
 if m:labels[m[1]]={'number':m[2],'page':int(m[3]),'destination':m[4]}
dests={}
for line in run(['pdfinfo','-dests','main.revised.pdf']).splitlines():
 m=re.match(r'\s*(\d+)\s+\[\s*XYZ\s+(-?\d+)\s+(-?\d+)\s+null\s*\]\s+"([^"]+)"',line)
 if m:dests[m[4]]={'page':int(m[1]),'x':int(m[2]),'y':int(m[3])}
inspector=ast.parse((B/'verify_reference_links_20260930.py').read_text())
ps=next(ast.literal_eval(x.value) for x in inspector.body if isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ps' for t in x.targets))
(A/'inspect_links.ps').write_text(ps)
annotations=run(['gs','-q','-dNODISPLAY','-dBATCH','-dNOSAFER','-f',str(A/'inspect_links.ps')]);(A/'pdf_links.txt').write_text(annotations)
links=[]
for line in annotations.splitlines():
 if line.startswith('EXTERNAL\t'):continue
 assert line.startswith('INTERNAL\t'),line
 _,page,dest,rect=line.split('\t',3);assert dest in dests,(page,dest)
 xy=list(map(float,re.findall(r'-?\d+(?:\.\d+)?',rect)));assert len(xy)==4 and xy[2]>xy[0] and xy[3]>xy[1]
 links.append({'page':int(page),'destination':dest})
counts=collections.Counter(x['destination'] for x in links)
body='\n'.join(new.values()).split(r'\begin{document}',1)[1]
cites=[k.strip() for g in re.findall(r'\\cite(?:\[[^]]*\])?\{([^{}]+)\}',body) for k in g.split(',')]
oldcites=[k.strip() for g in re.findall(r'\\cite(?:\[[^]]*\])?\{([^{}]+)\}','\n'.join(old.values()).split(r'\begin{document}',1)[1]) for k in g.split(',')]
assert cites==oldcites
bibkeys=set(re.findall(r'\\bibcite\{([^{}]+)\}',aux));assert len(bibkeys)==51 and set(cites)==bibkeys
for key,n in collections.Counter(cites).items():assert counts['cite.'+key]>=n,(key,n)
refkeys=re.findall(r'\\(?:ref|figref)\{([^{}]+)\}',body)+[m[1] for m in re.findall(r'\\namedref\{([^{}]+)\}\{([^{}]+)\}',body)]
for key,n in collections.Counter(refkeys).items():
 assert key in labels;entry=labels[key]
 assert entry['page']==dests[entry['destination']]['page'] and counts[entry['destination']]>=n,(key,n)
fl={k:v for k,v in labels.items() if k.startswith(('fig:','tab:'))};assert len(fl)==29
for k,v in fl.items():assert dests[v['destination']]['page']==v['page'],k
log=(B/'main.revised.log').read_text(errors='replace')
bad=[l for l in log.splitlines() if re.search(r'Overfull|undefined|destination with the same identifier|^!|LaTeX Warning:',l)]
assert not bad,bad
images=run(['pdfimages','-list','main.revised.pdf']);assert not re.search(r'^\s*\d+\s+\d+\s+',images,re.M)
report={'status':'PASS','scope':'Caption/cell concision and preservation checks; not experimental-data reanalysis','tables':20,'figures':9,'captions_changed':sum(x['changed'] for x in captions),'caption_words_before':sum(x['before_words'] for x in captions),'caption_words_after':sum(x['after_words'] for x in captions),'max_caption_words_after':max(x['after_words'] for x in captions),'table_cells_changed':len(cellchanges),'tables_with_cell_changes':len(set(x['label'] for x in cellchanges)),'changed_cell_words_before':sum(x['before_words'] for x in cellchanges),'changed_cell_words_after':sum(x['after_words'] for x in cellchanges),'max_changed_cell_words_before':max(x['before_words'] for x in cellchanges),'max_changed_cell_words_after':max(x['after_words'] for x in cellchanges),'pages_before':oldpages,'pages_after':pages,'references':len(bibkeys),'citation_uses':len(cites),'internal_links':len(links),'float_destinations':len(fl),'raster_images':0,'underfull_notices':len(re.findall('Underfull',log)),'overfull_or_undefined_errors':bad,'protected_vector_pdfs':7,'bibliography_unchanged':True,'author_abstract_keywords_equations_unchanged':True,'numeric_results_and_missingness_preserved':True,'security_evidence_checks':len(required),'regeneration_roundtrip_and_review_guard':'PASS','first_paper_sha256':sha(requirements),'tex_sha256':sha(B/'main.revised.tex'),'pdf_sha256':sha(B/'main.revised.pdf'),'float_pages':fl,'captions':captions,'cells':cellchanges,'known_preexisting_issue':'RQ2 prose reports E=735 candidates /734 trials /725 rejections; mechanism table reports 746/745/736. Values predate this edit and require source verification; not silently reconciled.'}
(A/'validation.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
(A/'changes.diff').write_text(''.join(''.join(difflib.unified_diff(old[f].splitlines(True),new[f].splitlines(True),fromfile='before/'+f,tofile=f)) for f in files))
run(['pdftotext','-layout','main.revised.pdf',str(A/'main.revised.txt')])
print(json.dumps({k:v for k,v in report.items() if k not in ['captions','cells','float_pages']},indent=2))
