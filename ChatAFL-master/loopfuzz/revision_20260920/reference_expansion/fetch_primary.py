from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
import urllib.request,urllib.parse,json,time,re,html
from html.parser import HTMLParser
B=Path(__file__).resolve().parent;(B/'primary').mkdir(exist_ok=True)
class Text(HTMLParser):
 def __init__(self):super().__init__();self.data=[]
 def handle_data(self,s):self.data.append(s)
urls={
'blueman2025':'https://www.usenix.org/conference/usenixsecurity25/presentation/kao',
'g2fuzz2025':'https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-zhijie',
'elfuzz2025':'https://www.usenix.org/conference/usenixsecurity25/presentation/meng',
'miner2023':'https://www.usenix.org/conference/usenixsecurity23/presentation/lyu',
'fishfuzz2023':'https://www.usenix.org/conference/usenixsecurity23/presentation/zheng',
'mutationassessment2023':'https://www.usenix.org/conference/usenixsecurity23/presentation/schloegel',
'fuzztruction2023':'https://www.usenix.org/conference/usenixsecurity23/presentation/berg',
'protocolguard2026':'https://www.ndss-symposium.org/ndss-paper/protocolguard-detecting-protocol-non-compliance-bugs-via-llm-guided-static-analysis-and-dynamic-verification/',
'bsfuzzer2026':'https://www.ndss-symposium.org/ndss-paper/bsfuzzer-context-aware-semantic-fuzzing-for-ble-logic-flaw-detection/',
'mercuriuzz2026':'https://www.ndss-symposium.org/ndss-paper/identifying-logical-vulnerabilities-in-quic-implementations/',
'distfuzz2025':'https://www.ndss-symposium.org/ndss-paper/blackbox-fuzzing-of-distributed-systems-with-multi-dimensional-inputs-and-symmetry-based-feedback-pruning/'
}
def fetch(item):
 key,url=item;p=B/'primary'/(key+'.html')
 try:
  if p.exists():raw=p.read_text()
  else:
   req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0 ManuscriptReferenceAudit/1.0'})
   with urllib.request.urlopen(req,timeout=25) as r:raw=r.read().decode(errors='replace')
   p.write_text(raw)
  parser=Text();parser.feed(raw);text='\n'.join(parser.data);(B/'primary'/(key+'.txt')).write_text(text)
  bib='';start=text.find('@inproceedings')
  if start>=0:
   opening=text.index('{',start);depth=0
   for i in range(opening,len(text)):
    if text[i]=='{' and (i==0 or text[i-1]!='\\'):depth+=1
    elif text[i]=='}' and (i==0 or text[i-1]!='\\'):
     depth-=1
     if depth==0:bib=text[start:i+1];break
   (B/'primary'/(key+'.bib')).write_text(bib+'\n')
  return key,{'url':url,'title':re.findall(r'<title>(.*?)</title>',raw,re.S)[:1],'bibtex':bib,'text_length':len(text)}
 except Exception as e:return key,{'url':url,'error':str(e)}
results={}
with ThreadPoolExecutor(max_workers=3) as ex:
 for f in as_completed([ex.submit(fetch,x) for x in urls.items()]):
  key,row=f.result();results[key]=row;print(key,json.dumps(row,ensure_ascii=False),flush=True)
(B/'primary_sources.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n')
dois={'whitefox2024':'10.1145/3689780','wingmuzz2025':'10.1109/ASE63991.2025.00212','hybridllm2026':'10.1109/TSE.2026.3694408','hgfuzzer2026':'10.1145/3841476','greenbenchmark2023':'10.1145/3597926.3598144'}
for key,doi in dois.items():
 p=B/'crossref'/(key+'.json');url='https://api.crossref.org/works/'+urllib.parse.quote(doi,safe='')
 try:
  if p.exists():saved=json.loads(p.read_text());data=saved['response']
  else:
   for attempt in range(2):
    try:
     with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'ManuscriptReferenceAudit/1.0'}),timeout=20) as r:data=json.load(r)
     break
    except urllib.error.HTTPError as e:
     if e.code==429 and attempt==0:time.sleep(3);continue
     raise
   p.write_text(json.dumps({'endpoint':url,'response':data},ensure_ascii=False,indent=2)+'\n')
  m=data['message'];print('DOI',key,json.dumps({k:m.get(k) for k in ['DOI','title','container-title','published','published-print','volume','issue','page','abstract']},ensure_ascii=False),flush=True)
 except Exception as e:print('DOI',key,'ERROR',str(e),flush=True)
 time.sleep(1)
