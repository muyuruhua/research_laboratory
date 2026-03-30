#!/usr/bin/env python3
import csv,os,sys,tarfile,re
from collections import defaultdict

dirs = [
    os.path.join(os.path.dirname(__file__),'..','benchmark','results-bftpd_Mar-16_23-10-02'),
    os.path.join(os.path.dirname(__file__),'..','benchmark','results-bftpd_Mar-17_16-49-50'),
]

def read_results(path):
    res = defaultdict(lambda: {'l_abs':0,'b_abs':0})
    fpath = os.path.join(path,'results.csv')
    if not os.path.exists(fpath):
        return res
    with open(fpath,'r',encoding='utf-8') as f:
        r=csv.reader(f)
        try:
            next(r)
        except StopIteration:
            return res
        for row in r:
            if len(row)<6:
                continue
            _,subject,fuzzer,run,cov_type,cov = row[:6]
            key=(fuzzer,run)
            try:
                val=int(float(cov))
            except:
                continue
            if cov_type=='l_abs':
                res[key]['l_abs']=max(res[key]['l_abs'],val)
            if cov_type=='b_abs':
                res[key]['b_abs']=max(res[key]['b_abs'],val)
    return res

def read_states(path):
    res = defaultdict(int)
    fpath = os.path.join(path,'states.csv')
    if not os.path.exists(fpath):
        return res
    with open(fpath,'r',encoding='utf-8') as f:
        r=csv.reader(f)
        try:
            next(r)
        except StopIteration:
            return res
        for row in r:
            if len(row)<6:
                continue
            _,subject,fuzzer,run,state_type,state = row[:6]
            if state_type!='edges':
                continue
            key=(fuzzer,run)
            try:
                val=int(float(state))
            except:
                continue
            res[key]=max(res[key],val)
    return res


def read_tar_metrics(tarpath):
    """Return dict mapping (fuzzer,run)->(l_abs,b_abs,edges) extracted from tarball contents."""
    out = {}
    m = re.search(r'out-bftpd-(.+)_(\d+)\.tar\.gz$', os.path.basename(tarpath))
    if not m:
        return out
    fuzzer = m.group(1)
    run = m.group(2)
    l_abs = None
    b_abs = None
    edges = 0
    try:
        with tarfile.open(tarpath,'r:gz') as tf:
            for member in tf.getmembers():
                name = member.name
                if name.endswith('cov_over_time.csv'):
                    try:
                        f = tf.extractfile(member)
                        if f:
                            txt = f.read().decode('utf-8',errors='ignore').strip()
                            lines = [l for l in txt.splitlines() if l.strip() and not l.startswith('#')]
                            if len(lines)>1:
                                last = lines[-1]
                                parts = last.split(',')
                                if len(parts)>=5:
                                    try:
                                        l_abs = int(float(parts[2].strip()))
                                    except:
                                        pass
                                    try:
                                        b_abs = int(float(parts[4].strip()))
                                    except:
                                        pass
                    except Exception:
                        pass
                if name.endswith('ipsm.dot') or os.path.basename(name)=='ipsm.dot':
                    try:
                        f = tf.extractfile(member)
                        if f:
                            txt = f.read().decode('utf-8',errors='ignore')
                            edges += txt.count('->')
                    except Exception:
                        pass
    except Exception:
        return out
    out[(fuzzer,run)] = (l_abs or 0, b_abs or 0, edges)
    return out

all_tables = []
for d in dirs:
    label = os.path.basename(d)
    if not os.path.isdir(d):
        all_tables.append((label, None, None))
        continue
    rmap = read_results(d)
    smap = read_states(d)
    # also parse any out-*.tar.gz archives in the directory
    for fn in os.listdir(d):
        if fn.endswith('.tar.gz'):
            tpath = os.path.join(d,fn)
            tmetrics = read_tar_metrics(tpath)
            for (fuzzer,run), (l,b,e) in tmetrics.items():
                key=(fuzzer,run)
                # update maps if larger than existing
                if l and l> rmap.get(key,{'l_abs':0})['l_abs']:
                    rmap[key]['l_abs']=l
                if b and b> rmap.get(key,{'b_abs':0})['b_abs']:
                    rmap[key]['b_abs']=b
                if e and e> smap.get(key,0):
                    smap[key]=e
    # combine keys
    keys = sorted(set(list(rmap.keys())+list(smap.keys())), key=lambda x:(x[0], int(x[1]) if x[1].isdigit() else x[1]))
    rows = []
    for k in keys:
        l = rmap.get(k,{'l_abs':0})['l_abs']
        b = rmap.get(k,{'b_abs':0})['b_abs']
        e = smap.get(k,0)
        rows.append((k[0],k[1],l,b,e))
    all_tables.append((label, d, rows))

for label,d,rows in all_tables:
    print('\nDirectory:',label)
    if rows is None or len(rows)==0:
        print('  (no results or directory missing)')
        continue
    print('fuzzer | run | l_abs | b_abs | edges')
    print('---|---:|---:|---:|---:')
    for f,run,l,b,e in rows:
        print(f'{f} | {run} | {l} | {b} | {e}')
