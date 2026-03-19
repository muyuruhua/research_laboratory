#!/usr/bin/env python3
import csv,subprocess,statistics
p = subprocess.Popen(["python3","scripts/extract_ablation_metrics.py"], stdout=subprocess.PIPE, text=True)
reader = csv.DictReader(p.stdout)
by = {}
for r in reader:
    key=r['archive']
    by.setdefault(key,[]).append((int(r['lines']) if r['lines'] else None, int(r['branches']) if r['branches'] else None, int(r['ipsm_edges']) if r['ipsm_edges'] else 0))
print('archive,median_lines,median_branches,median_ipsm_edges,run_count')
for k in sorted(by.keys()):
    v=by[k]
    lines=[x[0] for x in v if x[0] is not None]
    branches=[x[1] for x in v if x[1] is not None]
    ipsm=[x[2] for x in v]
    mlines=int(statistics.median(lines)) if lines else ''
    mbranches=int(statistics.median(branches)) if branches else ''
    mipsm=int(statistics.median(ipsm)) if ipsm else 0
    print(f"{k},{mlines},{mbranches},{mipsm},{len(v)}")
