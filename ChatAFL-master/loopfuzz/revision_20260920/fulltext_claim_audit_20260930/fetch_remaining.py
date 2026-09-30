import requests,json,re,subprocess,hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
a=Path(__file__).resolve().parent
urls={'thompson1933':['https://www.stat.purdue.edu/~pillow/readingGroup/Thompson1933.pdf','https://web.stanford.edu/~bvr/pubs/TS_Tutorial.pdf'],'efron1979':['https://projecteuclid.org/download/pdf_1/euclid.aos/1176344552','https://efron.ckirby.su.domains/papers/1979BootstrapMethods.pdf'],'benjamini1995':['https://errorstatistics.com/wp-content/uploads/2019/01/benjamini-and-hochberg-searchable-fdr.pdf'],'kaplan1958':['https://www.math.wustl.edu/~sawyer/handouts/kaplanmeier.pdf'],'davis2006pr':['https://pages.cs.wisc.edu/~richm/articles/davisgoadrichcamera2.pdf'],'brier1950':['https://library.oarcloud.noaa.gov/noaa_documents.lib/Digitization/meteorological_journals/monthly_weather_review/1950/mwr-078-01-0001.pdf'],'tscheduler2024':['https://arxiv.org/pdf/2312.04749'],'cliff1993':['https://downloads.regulations.gov/ITA-2025-0004-0014/attachment_1.pdf']}
# Candidates are never promoted automatically; verify title, author, and full contents afterwards.
def f(item):
 k,us=item;out=a/'sources'/k;out.mkdir(exist_ok=True)
 for i,u in enumerate(us):
  try:
   r=requests.get(u,timeout=(10,30));d={'url':u,'status':r.status_code,'bytes':len(r.content)}
   if r.status_code==200 and r.content.startswith(b'%PDF'):
    p=out/f'candidate{i}.pdf';p.write_bytes(r.content);subprocess.run(['pdftotext','-layout',str(p),str(p.with_suffix('.txt'))],check=True,capture_output=True)
    d.update(file=str(p),sha256=hashlib.sha256(r.content).hexdigest());print(k,d,flush=True)
   else:print(k,d,flush=True)
   (out/f'candidate{i}.json').write_text(json.dumps(d,indent=2))
  except Exception as e:print(k,str(e)[:100],flush=True)
with ThreadPoolExecutor(max_workers=4) as ex:list(ex.map(f,urls.items()))
for q in ['NSFuzz','SSGFuzz','WingMuzz']:
 r=requests.get('https://api.github.com/search/repositories',params={'q':q,'per_page':5},timeout=20)
 (a/'search'/f'github_{q}.json').write_text(r.text)
 print('REPO',q,[(x['full_name'],x['default_branch']) for x in r.json().get('items',[])],flush=True)
