#!/usr/bin/env python3
import tarfile,sys,os,re
ROOT=os.path.join(os.path.dirname(__file__), '..', 'ablation')
ROOT=os.path.abspath(ROOT)
print('archive,tarfile,run,lines,branches,ipsm_edges')
for dirpath in sorted(os.listdir(ROOT)):
    d=os.path.join(ROOT,dirpath)
    if not os.path.isdir(d):
        continue
    for fname in sorted(os.listdir(d)):
        if not fname.endswith('.tar.gz'):
            continue
        tpath=os.path.join(d,fname)
        run_match=re.search(r'_(\d+)\.tar\.gz$', fname)
        run=run_match.group(1) if run_match else ''
        lines=''
        branches=''
        ipsm_edges=0
        try:
            with tarfile.open(tpath,'r:gz') as tf:
                # try cov_over_time.csv first (gives l_abs, b_abs directly)
                for member in tf.getmembers():
                    if member.name.endswith('cov_over_time.csv'):
                        f=tf.extractfile(member)
                        if f:
                            txt=f.read().decode('utf-8',errors='ignore').strip()
                            lines_list=[l for l in txt.splitlines() if l.strip() and not l.startswith('#')]
                            if len(lines_list)>1:
                                last=lines_list[-1]
                                parts=last.split(',')
                                # expected Time,l_per,l_abs,b_per,b_abs
                                if len(parts)>=5:
                                    l_abs_val=parts[2].strip()
                                    b_abs_val=parts[4].strip()
                                    # validate numeric
                                    if re.match(r'^\d+$', l_abs_val):
                                        lines=l_abs_val
                                    if re.match(r'^\d+$', b_abs_val):
                                        branches=b_abs_val
                # fallback: search cov_html html files for numbers
                if not lines or not branches:
                    for member in tf.getmembers():
                        n=member.name
                        bname=os.path.basename(n)
                        if '/cov_html/' in n and n.endswith('.html'):
                            try:
                                f=tf.extractfile(member)
                                if f:
                                    txt=f.read().decode('utf-8',errors='ignore')
                                    if not lines:
                                        m=re.search(r'Lines\s*[:]?\s*([0-9,]+)', txt)
                                        if m:
                                            lines=m.group(1).replace(',','')
                                    if not branches:
                                        m2=re.search(r'Branches?\s*[:]?\s*([0-9,]+)', txt, re.I)
                                        if m2:
                                            branches=m2.group(1).replace(',','')
                            except Exception:
                                pass
                # count ipsm edges
                for member in tf.getmembers():
                    if member.name.endswith('ipsm.dot') or os.path.basename(member.name)=='ipsm.dot':
                        try:
                            f=tf.extractfile(member)
                            if f:
                                txt=f.read().decode('utf-8',errors='ignore')
                                ipsm_edges += len(re.findall(r'->', txt))
                        except Exception:
                            pass
        except Exception as e:
            print(f'# ERROR reading {tpath}: {e}', file=sys.stderr)
        print(f'{dirpath},{fname},{run},{lines},{branches},{ipsm_edges}')
