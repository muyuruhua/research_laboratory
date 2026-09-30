from pathlib import Path
import urllib.request,urllib.parse,json,time,re,html
B=Path(__file__).resolve().parent
D=B/'crossref';D.mkdir(exist_ok=True)
queries={
'aflnet5years2025':'AFLNet Five Years Later On Coverage-Guided Protocol Fuzzing',
'nyxnet2022':'Nyx-Net Network Fuzzing with Incremental Snapshots',
'snapfuzz2022':'SnapFuzz High-Efficiency and Fidelity Fuzzing of Network Applications',
'fuzztructionnet2024':'No Peer no Cry Network Application Fuzzing via Fault Injection',
'chathttpfuzz2025':'ChatHTTPFuzz Large Language Model-Assisted IoT HTTP Fuzzing',
'fox2024':'FOX Coverage-guided Fuzzing as Online Stochastic Control',
'prophetfuzz2024':'ProphetFuzz Fully Automated Prediction and Fuzzing of High-Risk Option Combinations with Only Documentation via Large Language Model',
'whitefox2024':'WhiteFox White-Box Compiler Fuzzing Empowered by Large Language Models',
'fuzzgpt2024':'Large Language Models are Edge-Case Generators Crafting Unusual Programs for Fuzzing Deep Learning Libraries',
'morest2022':'Morest Model-based RESTful API Testing with Execution Feedback',
'formatfuzzer':'FormatFuzzer Effective Fuzzing of Binary File Formats',
'fuzzbench2021':'FuzzBench an open fuzzer benchmarking platform and service',
'benchmarkproperties':'Fuzzing On Benchmarking Outcome as a Function of Benchmark Properties',
'stateinspector2022':'The Closer You Look The More You Learn A Grey-box Approach to Protocol State Machine Learning',
'evaluatingsynthetic2022':'Evaluating Synthetic Bugs',
'protocolguard2026':'ProtocolGuard Detecting Protocol Non-compliance Bugs via LLM-guided Static Analysis and Dynamic Verification',
'bsfuzzer2026':'BSFuzzer Context-Aware Semantic Fuzzing for BLE Logic Flaw Detection',
'mercuriuzz2026':'Identifying Logical Vulnerabilities in QUIC Implementations',
'distfuzz2025':'Blackbox Fuzzing of Distributed Systems with Multi-Dimensional Inputs and Symmetry-Based Feedback Pruning'
}
summary={}
for key,title in queries.items():
 p=D/(key+'.json')
 url='https://api.crossref.org/works?'+urllib.parse.urlencode({'query.title':title,'rows':3,'filter':'until-pub-date:2026-09-29'})
 try:
  if p.exists():data=json.loads(p.read_text())
  else:
   req=urllib.request.Request(url,headers={'User-Agent':'ManuscriptReferenceAudit/1.0','Accept':'application/json'})
   with urllib.request.urlopen(req,timeout=18) as r:data=json.load(r)
   p.write_text(json.dumps({'endpoint':url,'response':data},ensure_ascii=False,indent=2))
  if 'response' in data:data=data['response']
  rows=[]
  for m in data['message']['items']:
   rows.append({k:m.get(k) for k in ['DOI','title','container-title','published','published-online','published-print','page','volume','issue','type']})
  summary[key]=rows;print(key,json.dumps(rows,ensure_ascii=False),flush=True)
 except Exception as e:summary[key]={'error':str(e),'endpoint':url};print(key,'ERROR',str(e),flush=True)
 time.sleep(.3)
(B/'crossref_candidates.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
