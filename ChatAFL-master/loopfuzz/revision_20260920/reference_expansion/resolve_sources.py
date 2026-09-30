from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
from html.parser import HTMLParser
import urllib.request,urllib.parse,json,re,time
B=Path(__file__).resolve().parent
class Anchors(HTMLParser):
 def __init__(self):super().__init__();self.href=None;self.text=[];self.links=[]
 def handle_starttag(self,tag,attrs):
  if tag=='a':self.href=dict(attrs).get('href');self.text=[]
 def handle_data(self,s):
  if self.href:self.text.append(s)
 def handle_endtag(self,tag):
  if tag=='a' and self.href:self.links.append((self.href,' '.join(self.text)));self.href=None

def fetch(year):
 url=f'https://www.usenix.org/conference/usenixsecurity{str(year)[-2:]}/technical-sessions';p=B/'primary'/f'usenix{year}_sessions.html'
 if p.exists():s=p.read_text()
 else:
  with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'}),timeout=35) as r:s=r.read().decode()
  p.write_text(s)
 h=Anchors();h.feed(s)
 words=['environmental','non-textual','mutation analysis','fuzztruction','miner:']
 found=[(urllib.parse.urljoin(url,u),re.sub(r'\s+',' ',t).strip()) for u,t in h.links if any(w in t.lower() for w in words)]
 print('SESSION_MATCHES',year,json.dumps(found,ensure_ascii=False),flush=True)
 return found
matches=[]
with ThreadPoolExecutor(max_workers=2) as ex:
 for f in as_completed([ex.submit(fetch,y) for y in [2023,2025]]):
  try:matches+=f.result()
  except Exception as e:print('SESSION_ERROR',str(e),flush=True)
(B/'usenix_matched_urls.json').write_text(json.dumps(matches,ensure_ascii=False,indent=2))
wrong=B/'crossref'/'whitefox2024.json'
if wrong.exists():
 obj=json.loads(wrong.read_text());m=obj['response']['message']
 if isinstance(m,dict) and 'items' not in m and 'WhiteFox' not in str(m.get('title')):
  (B/'rejected').mkdir(exist_ok=True);(B/'rejected'/'whitefox_unmatched_doi.json').write_text(wrong.read_text())
url='https://api.crossref.org/works?'+urllib.parse.urlencode({'query.title':'WhiteFox White-Box Compiler Fuzzing Empowered by Large Language Models','rows':3})
with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'ManuscriptReferenceAudit/1.0'}),timeout=25) as r:data=json.load(r)
wrong.write_text(json.dumps({'endpoint':url,'response':data},ensure_ascii=False,indent=2)+'\n')
for m in data['message']['items']:print('WHITEFOX',json.dumps({k:m.get(k) for k in ['DOI','title','subtitle','container-title','published','page','volume','issue','abstract']},ensure_ascii=False),flush=True)
