from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
import urllib.request,json,re
B=Path(__file__).resolve().parent
class Text(HTMLParser):
 def __init__(self): super().__init__();self.parts=[]
 def handle_data(self,s): self.parts.append(s)
urls={
'g2fuzz2025':'https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-kunpeng',
'miner2023':'https://www.usenix.org/conference/usenixsecurity23/presentation/lyu',
'mutationassessment2023':'https://www.usenix.org/conference/usenixsecurity23/presentation/gorz',
'fuzztruction2023':'https://www.usenix.org/conference/usenixsecurity23/presentation/bars'}
old=json.loads((B/'primary_sources.json').read_text())
def get(item):
 key,url=item
 req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0 ManuscriptReferenceAudit/1.0'})
 with urllib.request.urlopen(req,timeout=35) as r: raw=r.read().decode(errors='replace')
 parser=Text();parser.feed(raw);txt='\n'.join(parser.parts)
 assert '@inproceedings' in txt,(key,'missing official BibTeX')
 start=txt.index('@inproceedings');opening=txt.index('{',start);depth=0
 for i in range(opening,len(txt)):
  if txt[i]=='{' and txt[i-1]!='\\':depth+=1
  elif txt[i]=='}' and txt[i-1]!='\\':
   depth-=1
   if depth==0:bib=txt[start:i+1];break
 for ext,content in [('html',raw),('txt',txt),('bib',bib+'\n')]: (B/'primary'/f'{key}.{ext}').write_text(content)
 return key,{'url':url,'title':re.findall(r'<title>(.*?)</title>',raw,re.S)[:1],'bibtex':bib}
with ThreadPoolExecutor(max_workers=4) as ex:
 for f in as_completed([ex.submit(get,x) for x in urls.items()]):
  try:
   key,row=f.result();old[key]=row;print(key,json.dumps(row,ensure_ascii=False),flush=True)
  except Exception as e: print('FETCH FAILED',str(e),flush=True)
(B/'primary_sources.json').write_text(json.dumps(old,ensure_ascii=False,indent=2)+'\n')
for ext in ['html','txt','bib']:
 p=B/'primary'/('elfuzz2025.'+ext)
 if p.exists():
  (B/'rejected').mkdir(exist_ok=True)
  p.rename(B/'rejected'/('elfuzz_unmatched_author_page.'+ext))
old.pop('elfuzz2025',None)
(B/'primary_sources.json').write_text(json.dumps(old,ensure_ascii=False,indent=2)+'\n')
