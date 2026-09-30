from pathlib import Path
import ast,re,json,hashlib,shutil
R=Path(__file__).resolve().parent.parent; A=Path(__file__).resolve().parent
parser=next(n for n in ast.parse((R/'reference_expansion/verify_reference_expansion.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='parse_bib')
exec(compile(ast.Module(body=[parser],type_ignores=[]),'parser','exec'))
bib=parse_bib((R/'references.expanded.bib').read_text())
(A/'before').mkdir(exist_ok=True);(A/'sources').mkdir(exist_ok=True)
files=[R/'main.revised.tex',R/'references.expanded.bib',R/'main.revised.pdf']
tex=(R/'main.revised.tex').read_text()
for name in re.findall(r'\\input\{([^{}]+)\}',tex):
 p=R.parent/name
 if not p.suffix:p=p.with_suffix('.tex')
 files.append(p)
files.append(Path('/home/ckt/Documents/000_2026_test_dev/C_two_papers/first_paper.md'))
manifest={}
for p in files:
 q=A/'before'/p.name
 if not q.exists():shutil.copy2(p,q)
 manifest[str(p)]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'backup':str(q.relative_to(A))}
(A/'snapshot.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
(A/'bibliography.json').write_text(json.dumps(bib,ensure_ascii=False,indent=2)+'\n')
occ=[]
for p in files:
 if p.suffix!='.tex':continue
 s=p.read_text()
 for m in re.finditer(r'\\cite\w*\*?(?:\[[^]]*\])*\{([^{}]+)\}',s):
  left=s.rfind('\n\n',0,m.start())+2;right=s.find('\n\n',m.end());right=right if right>=0 else len(s)
  para=s[left:right]
  if '&' in para:
   left=s.rfind('\n',0,m.start())+1;right=s.find('\n',m.end());para=s[left:right]
  occ.append({'id':f'C{len(occ)+1:03}','source':p.name,'line':s[:m.start()].count('\n')+1,'keys':[k.strip() for k in m[1].split(',')],'context':para})
assert set(k for c in occ for k in c['keys'])==set(bib)
(A/'occurrences.before.json').write_text(json.dumps(occ,ensure_ascii=False,indent=2)+'\n')
print('references',len(bib),'citation groups',len(occ),'reference uses',sum(len(c['keys']) for c in occ))
for c in occ:print(c['id'],c['line'],','.join(c['keys']))
