from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import ast,re,json,hashlib,requests
ROOT=Path(__file__).resolve().parent.parent; OUT=Path(__file__).resolve().parent
parser=next(n for n in ast.parse((ROOT/'reference_expansion/verify_reference_expansion.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='parse_bib')
exec(compile(ast.Module(body=[parser],type_ignores=[]),'parser','exec'))
bib=parse_bib((ROOT/'references.expanded.bib').read_text())
urls={k:v['url'] for k,v in bib.items() if not v.get('doi')}
urls['protocolguard2026']=json.loads((ROOT/'reference_expansion/primary_sources.json').read_text())['protocolguard2026']['url']
urls['efron1979']='https://projecteuclid.org/journals/annals-of-statistics/volume-7/issue-1/Bootstrap-Methods-Another-Look-at-the-Jackknife/10.1214/aos/1176344552.full'
(OUT/'official').mkdir(exist_ok=True)
def fetch(item):
 key,url=item; meta={'key':key,'url':url,'retrieved_utc':datetime.now(timezone.utc).isoformat()}
 try:
  r=requests.get(url,timeout=(10,30)); meta.update(status=r.status_code,final_url=r.url)
  if r.status_code==200:
   p=OUT/'official'/f'{key}.html';p.write_bytes(r.content)
   meta.update(file=str(p.relative_to(ROOT)),sha256=hashlib.sha256(r.content).hexdigest(),bytes=len(r.content))
 except Exception as e:meta['error']=str(e)
 return meta
rows=[]
with ThreadPoolExecutor(max_workers=4) as pool:
 for future in as_completed([pool.submit(fetch,i) for i in urls.items()]):
  row=future.result();rows.append(row);print(json.dumps(row),flush=True)
(OUT/'live_official_manifest.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2))
