"""Build selected references from cached publisher/Crossref metadata, never guesses."""
from pathlib import Path
import json,re,html,hashlib
B=Path(__file__).resolve().parent;ROOT=B.parent
selected={
'aflnet5years2025':'10.1109/tse.2025.3535925',
'nyxnet2022':'10.1145/3492321.3519591',
'snapfuzz2022':'10.1145/3533767.3534376',
'fuzztructionnet2024':'10.1145/3658644.3690274',
'fox2024':'10.1145/3658644.3670362',
'prophetfuzz2024':'10.1145/3658644.3690231',
'whitefox2024':'10.1145/3689736',
'fuzzgpt2024':'10.1145/3597503.3623343',
'formatfuzzer':'10.1145/3628157',
'fuzzbench2021':'10.1145/3468264.3473932',
'benchmarkproperties':'10.1145/3732936',
'stateinspector2022':'10.1145/3548606.3559365',
'wingmuzz2025':'10.1109/ase63991.2025.00212',
'hybridllm2026':'10.1109/tse.2026.3694408',
'hgfuzzer2026':'10.1145/3841476',
'greenbenchmark2023':'10.1145/3597926.3598144',
'protocolguard2026':'10.14722/ndss.2026.240521',
'bsfuzzer2026':'10.14722/ndss.2026.240094',
'mercuriuzz2026':'10.14722/ndss.2026.231777',
'distfuzz2025':'10.14722/ndss.2025.241912'}
def clean(x):return re.sub(r'\s+', ' ',html.unescape(re.sub(r'<[^>]+>','',x))).strip().replace(' :',':')
def latex(x):
 x=clean(x)
 for a,b in [('&',r'\&'),('%',r'\%'),('#',r'\#'),('_',r'\_')]:x=x.replace(a,b)
 return x
entries=[];records=[]
for key,doi in selected.items():
 p=B/'crossref'/f'{key}.json';d=json.loads(p.read_text());message=d['response']['message']
 items=message.get('items',[message]);matches=[m for m in items if m.get('DOI','').lower()==doi]
 assert len(matches)==1,(key,'DOI mismatch')
 m=matches[0];title=': '.join(m.get('title',[])+m.get('subtitle',[]));title=clean(title)
 assert m.get('author') and title and m.get('container-title'),key
 year=(m.get('published-print') or m.get('published'))['date-parts'][0][0]
 assert year<=2026
 kind='article' if m['type']=='journal-article' else 'inproceedings'
 authors=' and '.join(latex(a.get('family',''))+', '+latex(a.get('given','')) for a in m['author'])
 fields={'author':authors,'title':'{'+latex(title)+'}',('journal' if kind=='article' else 'booktitle'):latex(m['container-title'][0]),'year':str(year)}
 for src,dst in [('volume','volume'),('issue','number'),('page','pages')]:
  if m.get(src):fields[dst]=latex(m[src]).replace('-','--') if src=='page' else latex(m[src])
 if key=='hgfuzzer2026':fields['note']='Advance online publication, August 22, 2026'
 fields['doi']=doi
 entries.append('@'+kind+'{'+key+',\n'+',\n'.join('  '+k+' = {'+v+'}' for k,v in fields.items())+'\n}\n')
 records.append({'key':key,'title':title,'year':year,'venue':clean(m['container-title'][0]),'doi':doi,'source':d['endpoint'],'cache':str(p.relative_to(ROOT)),'verification':'Publisher-deposited Crossref metadata; exact DOI matched','claim_evidence':'Study scope from verified title; abstract used where present; no imported efficacy estimates','abstract':clean(m.get('abstract',''))})
primary=json.loads((B/'primary_sources.json').read_text())
for key in ['blueman2025','fishfuzz2023','miner2023','mutationassessment2023','fuzztruction2023','g2fuzz2025']:
 p=B/'primary'/f'{key}.bib'
 if key=='g2fuzz2025' and not p.exists():continue
 bib=p.read_text();bib=re.sub(r'@inproceedings\s*\{[^,]+,','@inproceedings{'+key+',',bib,count=1)
 bib=re.sub(r'\n\s*\n','\n',bib).replace('\t','  ')
 entries.append(bib)
 title=html.unescape(re.sub(r' \| USENIX$','',primary[key]['title'][0]));year=int(re.search(r'year\s*=\s*\{(\d{4})\}',bib).group(1))
 records.append({'key':key,'title':title,'year':year,'venue':'USENIX Security','source':primary[key]['url'],'cache':str(p.relative_to(ROOT)),'verification':'Official conference abstract and BibTeX','claim_evidence':'Official conference abstract'})
original=(ROOT/'before_reference_expansion/references.verified_20260928.bib').read_text()
output=original.rstrip()+'\n\n% Additional publications verified against official metadata.\n\n'+'\n'.join(entries)
keys=re.findall(r'@\w+\s*\{([^,]+),',output);assert len(keys)==len(set(keys)) and len(keys)>=50
(ROOT/'references.expanded.bib').write_text(output)
manifest=json.loads((B/'manifest.json').read_text());manifest['sources']=records;manifest['selected_new_references']=len(records);manifest['total_bibliography_entries']=len(keys);manifest['metadata_cutoff']='2026-09-29';manifest['excluded']=[{'candidate':'ELFuzz','reason':'Guessed author URL resolved to unrelated GradEscape; excluded.'},{'candidate':'WhiteFox DOI 10.1145/3689780','reason':'Resolved to Rustlantis; replaced with verified WhiteFox DOI 10.1145/3689736.'},{'candidate':'ChatHTTPFuzz','reason':'Publication venue differed from initial candidate description; not included.'},{'candidate':'Morest','reason':'Search returned an industry-practice paper; not included.'},{'candidate':'Evaluating Synthetic Bugs','reason':'Correct record is ASIACCS 2021, not alleged CCS 2022; not included.'}]
(B/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'original':25,'added':len(records),'total':len(keys),'selected_keys':[r['key'] for r in records]},ensure_ascii=False))
