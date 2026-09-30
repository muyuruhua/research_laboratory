from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
from urllib.parse import urljoin,quote
from bs4 import BeautifulSoup
import requests,json,re
A=Path(__file__).resolve().parent
sources={'boehme':'https://mboehme.github.io/','softwarelab':'https://www.software-lab.org/publications.html','hexhive':'https://hexhive.epfl.ch/publications/','lingming':'https://lingming.cs.illinois.edu/publications.html','cadar':'https://srg.doc.ic.ac.uk/publications/','suman':'https://www.cs.columbia.edu/~suman/','arxiv_state':'https://arxiv.org/search/?query=StateAFL&searchtype=all','arxiv_tscheduler':'https://arxiv.org/search/?query=T-Scheduler&searchtype=all','semantic':'https://api.semanticscholar.org/graph/v1/paper/DOI:10.1007/s10664-022-10233-3?fields=title,openAccessPdf,url'}
def fetch(item):
 k,url=item
 try:
  r=requests.get(url,timeout=(5,20));(A/'search'/f'author_{k}.html').write_text(r.text)
  soup=BeautifulSoup(r.text,'html.parser');items=[]
  for a in soup.find_all('a',href=True):
   u=urljoin(url,a['href']);label=a.get_text(' ',strip=True);parent=a.parent.get_text(' ',strip=True)
   if '.pdf' in u or 'arxiv.org/abs/' in u:
    ctx=parent if len(parent)>30 else a.parent.parent.get_text(' ',strip=True)
    if any(t in ctx.lower() for t in ['fuzz','protocol','bandit','calibrat']):items.append({'url':u,'context':ctx[:450]})
  return {'key':k,'status':r.status_code,'bytes':len(r.content),'items':items,'other':soup.get_text(' ',strip=True)[:300] if not items else ''}
 except Exception as e:return {'key':k,'error':str(e)}
with ThreadPoolExecutor(max_workers=5) as ex:
 for f in as_completed([ex.submit(fetch,x) for x in sources.items()]):
  r=f.result();(A/'search'/('author_'+r['key']+'.json')).write_text(json.dumps(r,ensure_ascii=False,indent=2));print(json.dumps(r,ensure_ascii=False),flush=True)
