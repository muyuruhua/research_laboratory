from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
from urllib.parse import quote,urljoin
from bs4 import BeautifulSoup
import requests,json,re,time
A=Path(__file__).resolve().parent
bib=json.loads((A/'bibliography.json').read_text())
manual={'benchmarkproperties':['https://mboehme.github.io/paper/TOSEM25-bench.pdf'],'reliability_benchmarking_2022':['https://mboehme.github.io/paper/ICSE22.pdf'],'snapfuzz2022':['https://srg.doc.ic.ac.uk/files/papers/snapfuzz-issta-22.pdf'],'gramatron_effective_grammar_aware_2021':['https://hexhive.epfl.ch/publications/files/21ISSTA.pdf'],'magma2020':['https://hexhive.epfl.ch/publications/files/21SIGMETRICS.pdf'],'fuzz4all_universal_fuzzing_large_2024':['https://www.software-lab.org/publications/icse2024_Fuzz4All.pdf']}
def norm(s):return re.sub('[^a-z0-9]','',s.lower())
missing=[(k,b) for k,b in bib.items() if json.loads((A/'sources'/k/'retrieval.json').read_text()).get('status')!='fulltext_downloaded']
def fetch(item):
 k,b=item;result={'key':k,'urls':[],'arxiv_matches':[]};title=re.sub(r'\\[a-zA-Z]+|[{}]','',b['title'])
 doi=b.get('doi')
 if doi:
  u='https://api.semanticscholar.org/graph/v1/paper/DOI:'+doi+'?fields=title,openAccessPdf,externalIds,url'
  try:
   r=requests.get(u,timeout=(5,15));result['semantic_status']=r.status_code
   if r.status_code==200:
    d=r.json();(A/'search'/f'semantic_{k}.json').write_text(json.dumps(d,ensure_ascii=False,indent=2))
    if norm(d.get('title',''))==norm(title):
     if d.get('openAccessPdf',{}).get('url'):result['urls'].append(d['openAccessPdf']['url'])
     ar=d.get('externalIds',{}).get('ArXiv')
     if ar:result['urls'].append('https://arxiv.org/pdf/'+ar)
  except Exception as e:result['semantic_error']=str(e)[:150]
 if k not in ['brier1950','thompson1933','benjamini1995','kaplan1958','mann1947','cliff1993','efron1979']:
  query=title.split(':')[0] if ':' in title else title
  u='https://arxiv.org/search/?query='+quote(query)+'&searchtype=all&abstracts=show&order=-announced_date_first&size=50'
  try:
   r=requests.get(u,timeout=(5,20));result['arxiv_status']=r.status_code
   (A/'search'/f'arxiv_{k}.html').write_text(r.text)
   soup=BeautifulSoup(r.text,'html.parser')
   for item in soup.select('li.arxiv-result'):
    t=item.select_one('p.title');t=t.get_text(' ',strip=True) if t else ''
    tok=set(re.findall('[a-z]{3,}',title.lower()));overlap=sum(w in t.lower() for w in tok)/max(1,len(tok))
    if overlap<.78:continue
    for a in item.select('p.list-title a'):
     href=a.get('href','')
     if '/abs/' in href or '/pdf/' in href:
      pdf=href.replace('/abs/','/pdf/');pdf=urljoin('https://arxiv.org',pdf)
      result['urls'].append(pdf);result['arxiv_matches'].append({'title':t,'pdf':pdf})
  except Exception as e:result['arxiv_error']=str(e)[:150]
 (A/'search'/f'discovery_{k}.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
 return result
with ThreadPoolExecutor(max_workers=4) as ex:
 for f in as_completed([ex.submit(fetch,x) for x in missing]):
  r=f.result();manual.setdefault(r['key'],[]).extend(r['urls']);print(json.dumps(r,ensure_ascii=False),flush=True)
(A/'manual_sources.json').write_text(json.dumps(manual,ensure_ascii=False,indent=2))
