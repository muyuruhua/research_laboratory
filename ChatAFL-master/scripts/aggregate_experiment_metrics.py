#!/usr/bin/env python3
import csv,os,sys
from collections import defaultdict

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))

results = defaultdict(lambda: {'l_abs':{}, 'b_abs':{}})
edges = defaultdict(lambda: {})

for dirpath,dirs,files in os.walk(ROOT):
    # only consider result folders coming from res_* archives
    if '/res_' not in dirpath and '\\res_' not in dirpath:
        continue
    for fn in files:
        if fn=='results.csv':
            path=os.path.join(dirpath,fn)
            try:
                with open(path,'r',encoding='utf-8') as f:
                    reader=csv.reader(f)
                    header=next(reader)
                    # expected columns: time,subject,fuzzer,run,cov_type,cov
                    for row in reader:
                        if len(row)<6:
                            continue
                        _,subject,fuzzer,_,cov_type,cov = row[:6]
                        key=(subject,fuzzer)
                        try:
                            val=int(float(cov))
                        except:
                            continue
                        if cov_type=='l_abs':
                            prev = results[subject]['l_abs'].get(fuzzer,0)
                            results[subject]['l_abs'][fuzzer]=max(prev,val)
                        if cov_type=='b_abs':
                            prev = results[subject]['b_abs'].get(fuzzer,0)
                            results[subject]['b_abs'][fuzzer]=max(prev,val)
            except Exception as e:
                print('# error reading',path,e,file=sys.stderr)
        if fn=='states.csv':
            path=os.path.join(dirpath,fn)
            try:
                with open(path,'r',encoding='utf-8') as f:
                    reader=csv.reader(f)
                    header=next(reader)
                    # time,subject,fuzzer,run,state_type,state
                    for row in reader:
                        if len(row)<6:
                            continue
                        _,subject,fuzzer,_,state_type,state = row[:6]
                        if state_type!='edges':
                            continue
                        try:
                            val=int(float(state))
                        except:
                            continue
                        prev = edges[(subject)].get(fuzzer,0)
                        edges[subject][fuzzer]=max(prev,val)
            except Exception as e:
                print('# error reading',path,e,file=sys.stderr)

# Build table per subject
subjects = sorted(set(list(results.keys()) + list(edges.keys())))

def bold_best(d):
    if not d:
        return {k:str(v) for k,v in d.items()}
    best=max(d.values())
    out={}
    for k,v in d.items():
        s=str(v)
        if v==best:
            s='**'+s+'**'
        out[k]=s
    return out

for subject in subjects:
    lmap = results[subject]['l_abs'] if subject in results else {}
    bmap = results[subject]['b_abs'] if subject in results else {}
    emap = edges.get(subject,{})
    fuzzers = sorted(set(list(lmap.keys())+list(bmap.keys())+list(emap.keys())))
    if not fuzzers:
        continue
    print('\nSubject:',subject)
    print('fuzzer | l_abs | b_abs | edges')
    print('---|---:|---:|---:')
    lbold = bold_best({f:int(lmap.get(f,0)) for f in fuzzers})
    bbold = bold_best({f:int(bmap.get(f,0)) for f in fuzzers})
    ebold = bold_best({f:int(emap.get(f,0)) for f in fuzzers})
    for f in fuzzers:
        la = lbold.get(f,str(int(lmap.get(f,0))))
        ba = bbold.get(f,str(int(bmap.get(f,0))))
        ea = ebold.get(f,str(int(emap.get(f,0))))
        print(f'{f} | {la} | {ba} | {ea}')
