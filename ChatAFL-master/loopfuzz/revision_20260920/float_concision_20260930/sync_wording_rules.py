from pathlib import Path
import json,re,difflib,shutil,importlib.util
B=Path(__file__).resolve().parent.parent
A=B/'float_concision_20260930'; BK=A/'before'
for name in ['refine_float_text.py','concise_float_text.json','vulnerability_section_20260929.tex']:
 p=BK/name
 if not p.exists():shutil.copy2(B/name,p)
sp=importlib.util.spec_from_file_location('previous_refiner',BK/'refine_float_text.py')
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
legacy=json.loads((BK/'concise_float_text.json').read_text())
legacy_by={x['label']:x for x in legacy['floats']}
files=['main.revised.tex','observed_tables.updated_20260930.tex','observed_costs.updated_20260930.tex','figures_updated_20260930/logged_calibration_table.tex','archive_arm_results.updated_20260930.tex']
spec={'backup':'float_concision_20260930/before','snapshot':'2026-09-30','rule':'Concise captions and table cells. Preserve measured values, denominators, missingness, uncertainty, references, and independent code/IPSM semantics. Unknown text requires review.','floats':[],'prose_edits':[]}
def unique(items):return list(dict.fromkeys(items))
def rows(text):
 return [[cell.strip() for cell in x.rstrip()[:-2].split(' & ')] for x in text.splitlines() if ' & ' in x and x.rstrip().endswith('\\\\')]
def scrub(text):
 text=re.sub(r'\\begin\{(table\*?|figure\*?)\}.*?\\end\{\1\}',lambda mm:'FLOAT '+re.search(r'\\label\{([^}]+)\}',mm[0])[1],text,flags=re.S)
 return text
for f in files:
 before=(BK/f).read_text();after=(B/f).read_text()
 for lab in re.findall(r'\\label\{((?:fig|tab):[^}]+)\}',after):
  a,z=m.caption_span(before,lab);oldcap=before[a:z]
  a,z=m.caption_span(after,lab);newcap=after[a:z]
  prior=legacy_by.get(lab,{})
  capold=unique([oldcap,*prior.get('caption',{}).values()])
  item={'file':f,'label':lab,'caption':{'old':oldcap,'new':newcap,'accepted':capold},'cells':[]}
  if lab!='tab:archive_arms':
   a,z=m.block_span(before,lab);bb=before[a:z]
   a,z=m.block_span(after,lab);ab=after[a:z]
   br,ar=rows(bb),rows(ab)
   assert len(br)==len(ar),(lab,len(br),len(ar))
   for oldrow,newrow in zip(br,ar):
    assert len(oldrow)==len(newrow),(lab,oldrow,newrow)
    for col,(old,new) in enumerate(zip(oldrow,newrow)):
     accepted=[old];row_names=[oldrow[0],newrow[0]]
     for priorcell in prior.get('cells',[]):
      aliases=prior.get('row_aliases',{})
      pname=priorcell['row'];pnew=aliases.get(pname,pname)
      if (pname in row_names or pnew in row_names) and priorcell['column']==col:
       accepted.extend([priorcell['old'],priorcell['new']]);row_names.extend([pname,pnew])
     if old!=new or any(x!=new for x in accepted):
      item['cells'].append({'row':oldrow[0],'row_names':unique(row_names),'column':col,'old':old,'new':new,'accepted':unique(accepted)})
   # TikZ labels are presentation text; keep coordinates and arrows untouched.
   if lab=='fig:posterior':
    clean=lambda s:[l for l in s.splitlines() if not l.startswith('\\caption{')]
    bl,al=clean(bb),clean(ab);replacements=[]
    for tag,i,j,k,l in difflib.SequenceMatcher(a=bl,b=al,autojunk=False).get_opcodes():
     if tag!='equal':
      assert tag=='replace' and j-i==l-k,(tag,lab)
      for old,new in zip(bl[i:j],al[k:l]):
       replacements.append({'old':old,'new':new})
    if replacements:item['block_edits']=replacements
  spec['floats'].append(item)
 if f=='main.revised.tex':
  oldlines=scrub(before).splitlines(True);newlines=scrub(after).splitlines(True)
  for tag,i,j,k,l in difflib.SequenceMatcher(a=oldlines,b=newlines,autojunk=False).get_opcodes():
   if tag=='equal':continue
   old=''.join(oldlines[i:j]);new=''.join(newlines[k:l])
   assert tag=='replace' and old.strip() and new.strip() and 'FLOAT ' not in old+new
   spec['prose_edits'].append({'file':f,'old':old.rstrip('\n'),'new':new.rstrip('\n')})
 elif f=='archive_arm_results.updated_20260930.tex':
  for old,new in zip(before.splitlines(),after.splitlines()):
   if old!=new and not old.startswith('\\captionof'):
    spec['prose_edits'].append({'file':f,'old':old,'new':new})
(B/'concise_float_text.json').write_text(json.dumps(spec,indent=2,ensure_ascii=False)+'\n')
# Retain strict review guards while accepting known previous-generation wording.
p=B/'refine_float_text.py';t=(BK/'refine_float_text.py').read_text()
t=t.replace("assert old in [cap['old'],cap['new']],", "assert old in [cap['old'],cap['new'],*cap.get('accepted',[])],")
t=t.replace("names={edit['row'],item.get('row_aliases',{}).get(edit['row'],edit['row'])}","names={edit['row'],*edit.get('row_names',[]),item.get('row_aliases',{}).get(edit['row'],edit['row'])}")
t=t.replace("assert cells[col] in [edit['old'],edit['new']],", "assert cells[col] in [edit['old'],edit['new'],*edit.get('accepted',[])],")
anchor="        pending[name]=text\n    for edit in spec.get('prose_edits',[]):"
replacement="""        for edit in item.get('block_edits',[]):
            a,z=block_span(text,item['label']);block=text[a:z]
            if edit['new'] not in block:
                assert block.count(edit['old'])==1,('Missing block anchor',item['label'])
                block=block.replace(edit['old'],edit['new'],1)
            text=text[:a]+block+text[z:]
        pending[name]=text
    for edit in spec.get('prose_edits',[]):"""
assert anchor in t;t=t.replace(anchor,replacement,1)
t=t.replace("if any(line.startswith(name+' & ') for name in names)","if ' & ' in line and line.split(' & ',1)[0].strip() in names")
t=t.replace("line.rstrip()[:-2].strip().split(' & ')","[cell.strip() for cell in line.rstrip()[:-2].split(' & ')]")
p.write_text(t)
print(json.dumps({'floats':len(spec['floats']),'guarded_cell_rules':sum(len(x['cells']) for x in spec['floats']),'prose_rules':len(spec['prose_edits'])}))
