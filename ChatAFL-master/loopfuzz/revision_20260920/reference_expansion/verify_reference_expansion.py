#!/usr/bin/env python3
"""Validate actual citations, metadata provenance, protected content and PDF links."""
from pathlib import Path
from collections import Counter
import ast,difflib,hashlib,html,json,re,subprocess,tempfile,xml.etree.ElementTree as ET
B=Path(__file__).resolve().parent;ROOT=B.parent

def run(args):return subprocess.check_output(args,cwd=ROOT,text=True,stderr=subprocess.PIPE)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def envs(s,name):return re.findall(r'\\begin\{'+re.escape(name)+r'\}.*?\\end\{'+re.escape(name)+r'\}',s,re.S)
def refs(s):return [k.strip() for group in re.findall(r'\\cite\w*\*?(?:\[[^]]*\])*\{([^{}]+)\}',s) for k in group.split(',')]
def parse_bib(s):
 entries={}
 for m in re.finditer(r'@\w+\s*\{([^,]+),',s):
  start=m.end();depth=1;i=start
  while depth:
   if s[i]=='{' and s[i-1]!='\\':depth+=1
   elif s[i]=='}' and s[i-1]!='\\':depth-=1
   i+=1
  fields={};entry=s[start:i-1]
  for f in re.finditer(r'(?m)^\s*(\w+)\s*=\s*\{',entry):
   p=f.end();j=p;level=1
   while level:
    if entry[j]=='{' and entry[j-1]!='\\':level+=1
    elif entry[j]=='}' and entry[j-1]!='\\':level-=1
    j+=1
   fields[f[1]]=entry[p:j-1]
  assert m[1] not in entries,m[1];entries[m[1]]=fields
 return entries
tex=(ROOT/'main.revised.tex').read_text();old=(ROOT/'before_reference_expansion/main.revised.tex').read_text()
body=tex.split(r'\begin{document}',1)[1]
inputs=[]
for name in re.findall(r'\\input\{([^{}]+)\}',tex):
 p=ROOT.parent/name;p=p if p.suffix else p.with_suffix('.tex');body+='\n'+p.read_text();inputs.append(p)
assert r'\nocite' not in body
cites=refs(body);bib=parse_bib((ROOT/'references.expanded.bib').read_text());oldbib=parse_bib((ROOT/'before_reference_expansion/references.verified_20260928.bib').read_text())
assert len(set(cites))>=50 and set(cites)==set(bib),(len(set(cites)),set(cites)^set(bib))
assert all(bib[k]==v for k,v in oldbib.items()),'original bibliography altered'
dois=[v['doi'].lower().strip() for v in bib.values() if v.get('doi')];assert len(dois)==len(set(dois))
titles=[re.sub(r'[^a-z0-9]','',v['title'].lower()) for v in bib.values()];assert len(titles)==len(set(titles))
manifest=json.loads((B/'manifest.json').read_text());assert {x['key'] for x in manifest['sources']}==set(bib)-set(oldbib)
for item in manifest['sources']:
 assert (ROOT/item['cache']).is_file() and item['verification'] and item['cited_in']
 assert int(bib[item['key']]['year'])==item['year']
 assert item['year']<=2026
 if item.get('doi'):assert bib[item['key']]['doi'].lower()==item['doi'].lower()
requirements=Path('/home/ckt/Documents/000_2026_test_dev/C_two_papers/first_paper.md')
assert sha(requirements)==manifest['requirements_sha256']
# Protect existing experimental floats, equations, algorithms, abstract and keywords.
protected_blocks={}
for name in ['abstract','keyword','table','table*','equation','align','algorithm']:
 assert envs(tex,name)==envs(old,name),name
 protected_blocks[name]=len(envs(tex,name))
def normalize_figure(s):return s.replace(r'\begin{figure*}[p]',r'\begin{figure*}[!tbp]').replace('width=0.97\\textwidth','width=\\textwidth')
for name in ['figure','figure*']:
 assert [normalize_figure(x) for x in envs(tex,name)]==envs(old,name),name
 protected_blocks[name]=len(envs(tex,name))
assert re.findall(r'\\caption\{.*?\}',tex)==re.findall(r'\\caption\{.*?\}',old)
prior=json.loads((ROOT/'reference_links_changes_20260930.json').read_text())
unchanged=[];prior_link_only=[]
def canonical(s):return re.sub(r'\\namedref\{(Figures?|Tables?)\}\{([^{}]+)\}',lambda m:m[1]+r'~\ref{'+m[2]+'}',s)
for name,digest in prior['protected_files'].items():
 p=ROOT/name
 if sha(p)==digest:unchanged.append(name)
 else:
  assert name=='vulnerability_section_20260929.tex',name
  before=(ROOT/'before_reference_links_20260930'/name).read_text()
  assert canonical(p.read_text())==before,name
  prior_link_only.append(name)
abstract=envs(tex,'abstract')[0];abstract_words=len(re.findall(r"[A-Za-z0-9]+(?:[-'][A-Za-z0-9]+)*",re.sub(r'\\(?:begin|end)\{abstract\}','',abstract)))
assert 150<=abstract_words<=200
kw=envs(tex,'keyword')[0];keyword_count=kw.count(r'\sep')+1;assert keyword_count<=5
aux=(ROOT/'main.revised.aux').read_text();bbl=(ROOT/'main.revised.bbl').read_text()
compiled=set(re.findall(r'\\bibcite\{([^{}]+)\}',aux));items=set(re.findall(r'\\bibitem(?:\[[^]]*\])?\{([^{}]+)\}',bbl))
assert compiled==set(cites)==items
info=run(['pdfinfo','main.revised.pdf']);pages=int(re.search(r'^Pages:\s*(\d+)',info,re.M)[1])
dest_text=run(['pdfinfo','-dests','main.revised.pdf']);(B/'pdf_destinations.txt').write_text(dest_text)
destinations={}
for line in dest_text.splitlines():
 m=re.match(r'\s*(\d+)\s+\[\s*XYZ\s+(-?\d+)\s+(-?\d+)\s+null\s*\]\s+"([^"]+)"',line)
 if m:destinations[m[4]]={'page':int(m[1]),'x':int(m[2]),'y':int(m[3])}
# Reuse the read-only Ghostscript annotation reader, without running the old fixed-count validator.
reader=ast.parse((ROOT/'verify_reference_links_20260930.py').read_text())
ps=next(ast.literal_eval(n.value) for n in reader.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ps' for t in n.targets))
with tempfile.TemporaryDirectory(prefix='reference_expansion_links_') as temp:
 p=Path(temp)/'inspect.ps';p.write_text(ps)
 annotations=run(['gs','-q','-dNODISPLAY','-dBATCH','-dNOSAFER','-f',str(p)])
(B/'pdf_annotations.txt').write_text(annotations)
links=[]
for line in annotations.splitlines():
 if line.startswith('EXTERNAL\t'):continue
 assert line.startswith('INTERNAL\t'),line
 _,page,dest,rect=line.split('\t',3);assert dest in destinations,dest
 xy=list(map(float,re.findall(r'-?\d+(?:\.\d+)?',rect)))
 assert len(xy)==4 and xy[2]>xy[0] and xy[3]>xy[1]
 assert 1<=destinations[dest]['page']<=pages and 0<=destinations[dest]['y']<=842
 links.append({'source_page':int(page),'destination':dest,'rect':xy,'target':destinations[dest]})
counts=Counter(x['destination'] for x in links)
for key,n in Counter(cites).items():assert counts['cite.'+key]>=n,(key,n,counts['cite.'+key])
assert len({tuple(destinations['cite.'+k].values()) for k in compiled})==len(compiled)
labels={}
for line in aux.splitlines():
 m=re.match(r'^\\newlabel\{([^{}]+)\}\{\{(.*?)\}\{(\d+)\}.*\{([^{}]+)\}\{\}\}$',line)
 if m:labels[m[1]]={'number':m[2],'page':int(m[3]),'destination':m[4]}
refkeys=re.findall(r'\\(?:ref|figref)\{([^{}]+)\}',body)+[m[1] for m in re.findall(r'\\namedref\{([^{}]+)\}\{([^{}]+)\}',body)]
for key,n in Counter(refkeys).items():
 assert key in labels,key
 dest=labels[key]['destination'];assert counts[dest]>=n,(key,n)
 assert labels[key]['page']==destinations[dest]['page'],key
floatlabels={k:v for k,v in labels.items() if k.startswith(('fig:','tab:'))};assert len(floatlabels)==29
assert not re.search(r'^\s*\d+\s+\d+\s+',run(['pdfimages','-list','main.revised.pdf']),re.M)
log=(ROOT/'main.revised.log').read_text(errors='replace')
critical=[l for l in log.splitlines() if any(x in l for x in ['Overfull','undefined','destination with the same identifier','! LaTeX Error','! Package'])]
assert not critical,critical
warnings=[l for l in log.splitlines() if 'Warning:' in l]
assert all(re.match(r'LaTeX Warning: Text page \d+ contains only floats\.',l) for l in warnings),warnings
pdftext=run(['pdftotext','-layout','main.revised.pdf','-']);(ROOT/'main.revised.txt').write_text(pdftext)
assert not re.search(r'\[(?:\?,?\s*)+\]',pdftext)
# Text coordinates establish page occupancy; graphics remain vector and unchanged.
xml=run(['pdftotext','-bbox-layout','main.revised.pdf','-'])
xml_controls=re.findall(r'[\x00-\x08\x0b\x0c\x0e-\x1f]',xml)
xml=re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]','',xml)
doc=ET.fromstring(xml);ns={'x':'http://www.w3.org/1999/xhtml'}
layout=[]
for i,page in enumerate(doc.findall('.//x:page',ns),1):
 words=[w for w in page.findall('.//x:word',ns) if float(w.attrib['yMax'])<798]
 boxes=[tuple(float(w.attrib[k]) for k in ['xMin','yMin','xMax','yMax']) for w in words]
 layout.append({'page':i,'word_count':len(words),'top':round(min(x[1] for x in boxes),2),'bottom':round(max(x[3] for x in boxes),2)})
assert len(layout)==pages and all(x['word_count']>25 for x in layout)
years=Counter(int(v['year']) for v in bib.values())
report={'status':'PASS','bibliography_entries':len(bib),'actual_distinct_citations':len(compiled),'new_references':len(manifest['sources']),'years':dict(sorted(years.items())),'references_2022_2026':sum(v for k,v in years.items() if 2022<=k<=2026),'recent_new_references_2022_2026':sum(2022<=x['year']<=2026 for x in manifest['sources']),'pages':pages,'internal_link_annotations':len(links),'citation_link_annotations':sum(v for k,v in counts.items() if k.startswith('cite.')),'distinct_linked_bibliography_entries':len(compiled),'figure_table_destinations':len(floatlabels),'figure_table_link_annotations':sum(v for k,v in counts.items() if k.startswith(('figure.','table.'))),'protected_blocks':protected_blocks,'protected_files_byte_identical':len(unchanged),'preexisting_link_only_file':prior_link_only,'abstract_words':abstract_words,'keyword_count':keyword_count,'raster_images':0,'undefined_citations_or_references':0,'duplicate_dois':0,'duplicate_titles':0,'overfull_boxes':0,'nonfatal_layout_notices':warnings,'layout':layout,'bbox_xml_controls_removed':len(xml_controls),'first_paper_sha256':sha(requirements),'tex_sha256':sha(ROOT/'main.revised.tex'),'pdf_sha256':sha(ROOT/'main.revised.pdf'),'examples':{k:labels[k]|destinations[labels[k]['destination']] for k in ['fig:reliability','tab:logged_calibration']},'links':links}
(B/'validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
(B/'manuscript.diff').write_text(''.join(difflib.unified_diff(old.splitlines(True),tex.splitlines(True),fromfile='before_reference_expansion/main.revised.tex',tofile='main.revised.tex')))
print(json.dumps({k:v for k,v in report.items() if k not in ('links','layout')},ensure_ascii=False,indent=2))
print('FLOAT_ONLY_PAGE_CONTENT',[(n,[k for k,v in floatlabels.items() if v['page']==n]) for n in sorted({int(re.search(r'page (\d+)',l)[1]) for l in warnings})])
print('PAGE_EXTENTS',layout)
