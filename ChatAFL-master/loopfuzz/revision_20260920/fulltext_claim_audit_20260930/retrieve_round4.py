import json,requests,subprocess,hashlib,re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
a=Path(__file__).resolve().parent
urls={'brier1950':['https://journals.ametsoc.org/downloadpdf/view/journals/mwre/78/1/1520-0493_1950_078_0001_vofeit_2_0_co_2.pdf'],'kaplan1958':['https://web.stanford.edu/~lutian/coursepdf/KMpaper.pdf'],'thompson1933':['https://www.cs.princeton.edu/courses/archive/spring18/cos598B/papers/Thompson1933.pdf'],'efron1979':['https://www.stat.cmu.edu/~ryantibs/advmethods/notes/efron1979.pdf'],'davis2006pr':['https://pages.cs.wisc.edu/~jdavis/davisgoadrichcamera2.pdf?download=1','https://www.biostat.wisc.edu/~page/rocpr.pdf']}
def f(item):
 k,us=item;out=a/'sources'/k
 for i,u in enumerate(us):
  try:
   r=requests.get(u,timeout=(10,25));d={'url':u,'status':r.status_code,'bytes':len(r.content)}
   if r.status_code==200 and r.content.startswith(b'%PDF'):
    p=out/f'round4_{i}.pdf';p.write_bytes(r.content);subprocess.run(['pdftotext','-layout',str(p),str(p.with_suffix('.txt'))],check=True,capture_output=True);d['file']=str(p);d['sha256']=hashlib.sha256(r.content).hexdigest()
   (out/f'round4_{i}.json').write_text(json.dumps(d,indent=2));print(k,d,flush=True)
  except Exception as e:print(k,str(e)[:100],flush=True)
with ThreadPoolExecutor(max_workers=4) as ex:list(ex.map(f,urls.items()))
for repo in ['flysoar/SSGFuzz','nuwaLab/wingmuzz','jack-tz/nsfuzz-llm']:
 r=requests.get('https://api.github.com/repos/'+repo+'/git/trees/main?recursive=1',timeout=25);(a/'search'/('tree_'+repo.replace('/','_')+'.json')).write_text(r.text)
 if r.status_code==200:print('FILES',repo,[x['path'] for x in r.json().get('tree',[]) if x['path'].lower().endswith(('.pdf','.md'))][:30],flush=True)
 r=requests.get('https://raw.githubusercontent.com/'+repo+'/main/README.md',timeout=20);(a/'search'/('readme_'+repo.replace('/','_')+'.md')).write_text(r.text);print('README',repo,r.text[:7000],flush=True)
