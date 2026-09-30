from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
from urllib.parse import quote,urljoin
from datetime import datetime,timezone
import requests,json,re,html,hashlib,subprocess,shutil,unicodedata
A=Path(__file__).resolve().parent;R=A.parent
bib=json.loads((A/'bibliography.json').read_text())
manual=json.loads((A/'manual_sources.json').read_text()) if (A/'manual_sources.json').exists() else {}
records={}
def walk(d):
 if isinstance(d,dict):
  if d.get('DOI') and d.get('title'):yield d
  else:
   for k in ['response','message','items']:
    if k in d:yield from walk(d[k])
 elif isinstance(d,list):
  for i in d:yield from walk(i)
for p in list((R/'reference_audit_20260928').glob('*.json'))+list((R/'reference_expansion/crossref').glob('*.json')):
 try:d=json.loads(p.read_text())
 except ValueError:continue
 for m in walk(d):
  doi=m['DOI'].lower()
  if doi not in records or len(m)>len(records[doi]):records[doi]=m
primary=json.loads((R/'reference_expansion/primary_sources.json').read_text())
def pdf_links(s,url):
 result=[]
 for tag in re.findall(r'<meta\b[^>]*>',s,re.I):
  if 'citation_pdf_url' in tag:
   c=re.search(r'content=[\"\x27]([^\"\x27]+)',tag,re.I)
   if c:result.append(urljoin(url,html.unescape(c[1])))
 result.extend(urljoin(url,html.unescape(u)) for u in re.findall(r'href=[\"\x27]([^\"\x27]+\.pdf(?:\?[^\"\x27]*)?)[\"\x27]',s,re.I) if not any(t in u.lower() for t in ['slides','presentation','appendix','poster','supplement']))
 return list(dict.fromkeys(result))
def fetch(item):
 key,b=item;out=A/'sources'/key;out.mkdir(exist_ok=True)
 manifest=out/'retrieval.json'
 if manifest.exists():
  prev=json.loads(manifest.read_text())
  if prev.get('status')=='fulltext_downloaded':return prev
 previous=json.loads(manifest.read_text()) if manifest.exists() else {}
 result={'key':key,'title':b['title'],'status':'unavailable','attempts':[],'retrieved_utc':datetime.now(timezone.utc).isoformat()}
 result['attempts']=previous.get('attempts',[])
 attempted={x['url'] for x in result['attempts']}
 sess=requests.Session();sess.headers['User-Agent']='Mozilla/5.0 (academic reference verification)'
 candidates=list(manual.get(key,[]))
 if key=='chatafl':
  p=R/'reference_audit_20260928/chatafl_official.pdf'
  if p.exists():candidates.append('local:'+str(p))
 url=b.get('url') or primary.get(key,{}).get('url')
 if url:
  page=R/'reference_reality_audit_20260930/official'/f'{key}.html'
  if not page.exists():page=R/'reference_expansion/primary'/f'{key}.html'
  if page.exists():candidates+=pdf_links(page.read_text(),url)
 doi=b.get('doi','').lower();m=records.get(doi,{})
 for x in m.get('link',[]):
  u=x.get('URL','')
  if 'pdf' in u.lower():candidates.append(u.replace('http://','https://'))
 u=m.get('resource',{}).get('primary',{}).get('URL','')
 if u and ('pdf' in u.lower()):candidates.append(u)
 if doi.startswith('10.1145/'):candidates.append('https://dl.acm.org/doi/pdf/'+doi)
 if doi.startswith('10.1007/'):candidates.append('https://link.springer.com/content/pdf/'+doi+'.pdf')
 # Download and identity-check actual PDF content, never a paywall page.
 def attempt(u):
  if u in attempted:return False
  attempted.add(u)
  try:
   if u.startswith('local:'):data=Path(u[6:]).read_bytes();status=200;final=u
   else:
    resp=sess.get(u,timeout=(5,10));status=resp.status_code;final=resp.url;data=resp.content
   result['attempts'].append({'url':u,'status':status,'final_url':final,'bytes':len(data)})
   if status!=200 or not data.lstrip().startswith(b'%PDF'):return False
   pdf=out/'paper.pdf';pdf.write_bytes(data)
   textfile=out/'paper.txt'
   subprocess.run(['pdftotext','-layout',str(pdf),str(textfile)],check=True,capture_output=True,timeout=20)
   text=textfile.read_text(errors='replace');first=' '.join(text.split('\f')[:3]).lower()
   tokens=set(re.findall(r'[a-z]{3,}',html.unescape(re.sub(r'\\[a-z]+|[{}]','',b['title'].lower()))))
   found=sum(t in first for t in tokens)/max(1,len(tokens))
   normalize=lambda v: re.sub('[^a-z0-9]','',unicodedata.normalize('NFKD',html.unescape(v)).lower())
   exact=normalize(b['title']) in normalize(first)
   if not exact:
    result['attempts'][-1]['identity_title_token_overlap']=round(found,2);return False
   result.update(status='fulltext_downloaded',source=final,pdf=str(pdf.relative_to(R)),text=str(textfile.relative_to(R)),pages=len(text.rstrip('\f\n ').split('\f')),characters=len(text),sha256=hashlib.sha256(data).hexdigest(),title_token_overlap=found)
   return True
  except Exception as ex:result['attempts'].append({'url':u,'error':str(ex)[:200]});return False
 for u in list(dict.fromkeys(candidates))[:4]:
  if attempt(u):break
 if result['status']!='fulltext_downloaded' and doi and not previous:
  endpoint='https://api.openalex.org/works/https://doi.org/'+quote(doi,safe='/')
  try:
   resp=sess.get(endpoint,timeout=(5,15));result['attempts'].append({'url':endpoint,'status':resp.status_code})
   if resp.status_code==200:
    oa=resp.json();(out/'openalex.json').write_text(json.dumps(oa,ensure_ascii=False,indent=2))
    urls=[x['pdf_url'] for x in oa.get('locations',[]) if x and x.get('pdf_url')]
    for u in list(dict.fromkeys(urls))[:5]:
     if u not in candidates and attempt(u):break
  except Exception as ex:result['attempts'].append({'url':endpoint,'error':str(ex)[:150]})
 manifest.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 return result
with ThreadPoolExecutor(max_workers=5) as pool:
 for f in as_completed([pool.submit(fetch,x) for x in bib.items()]):
  r=f.result();print(r['key'],r['status'],r.get('pages'),r.get('source',''),flush=True)
rows=[json.loads(p.read_text()) for p in sorted((A/'sources').glob('*/retrieval.json'))]
(A/'retrieval_manifest.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n')
print('TOTAL',len(rows),'FULLTEXT',sum(x['status']=='fulltext_downloaded' for x in rows),flush=True)
