"""Read current BibTeX and independently compare existing primary-source metadata."""
from pathlib import Path
import ast, re, json, html, unicodedata, hashlib
ROOT=Path(__file__).resolve().parent.parent
OUT=Path(__file__).resolve().parent
# Reuse the existing brace-aware parser without executing its manuscript validator.
tree=ast.parse((ROOT/'reference_expansion/verify_reference_expansion.py').read_text())
node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='parse_bib')
exec(compile(ast.Module(body=[node],type_ignores=[]),'parser','exec'))
bib=parse_bib((ROOT/'references.expanded.bib').read_text())

def text(s):
 s=html.unescape(re.sub('<[^>]*>','',s or ''))
 s=re.sub(r'\\["\'`^~=.]\s*\{?([A-Za-z])\}?',r'\1',s)
 s=re.sub(r'\\(?:[A-Za-z]+|.)',lambda m: '&' if m[0]==r'\&' else '',s)
 s=unicodedata.normalize('NFKD',s)
 return re.sub('[^a-z0-9]','',s.lower())

def find_records(d):
 if isinstance(d,dict):
  if d.get('DOI') and d.get('title') and (d.get('author') or d.get('container-title')): yield d
  else:
   for key in ['response','message','items']:
    if key in d: yield from find_records(d[key])
 elif isinstance(d,list):
  for x in d: yield from find_records(x)

def author_match(b,c):
 raw=b.split(',')
 if len(raw)==2: fam,given=raw[0],raw[1]
 else:
  words=b.split(); fam=words[-1]; given=' '.join(words[:-1])
 cf,cg=c.get('family',''),c.get('given','')
 exact=text(fam)==text(cf) and text(given)==text(cg)
 initials=lambda x: ''.join(w[0] for w in re.findall('[A-Za-z]+',unicodedata.normalize('NFKD',x)))
 return exact or (text(fam)==text(cf) and text(initials(given))==text(initials(cg)))

records={}
paths=list((ROOT/'reference_audit_20260928').glob('*.json'))+list((ROOT/'reference_expansion/crossref').glob('*.json'))
for p in paths:
 try: d=json.loads(p.read_text())
 except (ValueError,UnicodeError): continue
 for m in find_records(d):
  doi=m['DOI'].lower()
  if doi not in records or len(m)>len(records[doi][1]): records[doi]=(p,m)
rows=[]
for key,b in bib.items():
 if not b.get('doi'): continue
 doi=b['doi'].lower(); found=records.get(doi)
 if not found:
  rows.append({'key':key,'missing_cache':True});continue
 p,m=found
 ct=': '.join(m.get('title',[])+m.get('subtitle',[]))
 ba=re.split(r'\s+and\s+',b['author']); ca=m.get('author',[])
 fields={k:(b.get(k),m.get(v)) for k,v in [('volume','volume'),('number','issue'),('pages','page')]}
 row={'key':key,'cache':str(p.relative_to(ROOT)),'title_ok':text(b['title'])==text(ct),'bib_title':b['title'],'source_title':ct,
 'author_ok':len(ba)==len(ca) and all(author_match(x,y) for x,y in zip(ba,ca)), 'bib_authors':ba,'source_authors':ca,
 'bib_venue':b.get('journal',b.get('booktitle')),'source_venue':m.get('container-title'),
 'bib_year':b.get('year'),'dates':{k:m[k] for k in ['published-print','published-online','issued'] if k in m},
 'fields':fields,'field_discrepancies':{k:v for k,v in fields.items() if all(v) and text(v[0])!=text(v[1])}}
 rows.append(row)
(OUT/'cached_metadata_comparison.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2))
print('Entries',len(bib),'DOI',len(rows),'no DOI',len(bib)-len(rows))
for row in rows:
 if not row.get('title_ok') or not row.get('author_ok') or row.get('field_discrepancies') or row.get('missing_cache'):
  print(json.dumps({k:v for k,v in row.items() if k!='source_authors'},ensure_ascii=False))
  if not row.get('author_ok'): print('Source authors',[(a.get('given'),a.get('family')) for a in row.get('source_authors',[])])
print('No DOI keys:',[k for k,b in bib.items() if not b.get('doi')])
