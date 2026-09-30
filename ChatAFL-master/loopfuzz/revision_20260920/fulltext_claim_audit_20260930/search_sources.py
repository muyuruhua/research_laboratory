from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
from urllib.parse import quote,parse_qs,urlparse
import requests,xml.etree.ElementTree as ET,re,json,html,base64
A=Path(__file__).resolve().parent
bib=json.loads((A/'bibliography.json').read_text());(A/'search').mkdir(exist_ok=True)
missing=[]
for k,b in bib.items():
 p=A/'sources'/k/'retrieval.json'
 if not p.exists() or json.loads(p.read_text()).get('status')!='fulltext_downloaded':missing.append((k,b))
missing.append(('tscheduler_identity',{'title':'T-Scheduler Thompson sampling fuzzing'}))
def one(item):
 key,b=item;title=re.sub(r'\\[a-zA-Z]+|[{}]','',b['title']);query='"'+title+'" pdf' if key!='tscheduler_identity' else '"T-Scheduler" fuzzing'
 url='https://www.bing.com/search?format=rss&q='+quote(query)
 result={'key':key,'query':query,'source':url,'items':[]}
 try:
  r=requests.get(url,timeout=(5,15),headers={'User-Agent':'Mozilla/5.0'})
  (A/'search'/f'{key}.rss').write_text(r.text)
  for i in ET.fromstring(r.content).findall('.//item'):
   result['items'].append({'title':i.findtext('title'),'url':i.findtext('link'),'description':i.findtext('description')})
 except Exception as e:result['error']=str(e)
 (A/'search'/f'{key}.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
 return result
with ThreadPoolExecutor(max_workers=4) as pool:
 for f in as_completed([pool.submit(one,x) for x in missing]):
  r=f.result();print(r['key'],json.dumps(r['items'][:5],ensure_ascii=False),r.get('error',''),flush=True)
