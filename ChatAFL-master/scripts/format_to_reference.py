#!/usr/bin/env python3
import os
import csv
from datetime import datetime

ROOT = os.path.join(os.path.dirname(__file__), '..')
IN_PATH = os.path.join(ROOT, 'benchmark', 'recovered-containers-2026-03-16_09-19-25', 'results.csv')
OUT_DIR = os.path.join(ROOT, 'benchmark', f'results-recovered-2026-03-16_09-19-25')
os.makedirs(OUT_DIR, exist_ok=True)

out_rows = []
with open(IN_PATH, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for r in reader:
        time = r.get('time','')
        subject = r.get('subject','') or ''
        fuzzer = r.get('fuzzer','')
        # use run=1 as default
        run = '1'
        bitmap = r.get('bitmap_cvg','')
        if bitmap.endswith('%'):
            bitmap = bitmap[:-1]
        # create two entries: l_per and b_per
        if bitmap:
            out_rows.append({'time':time,'subject':subject,'fuzzer':fuzzer,'run':run,'cov_type':'l_per','cov':bitmap})
            out_rows.append({'time':time,'subject':subject,'fuzzer':fuzzer,'run':run,'cov_type':'b_per','cov':bitmap})
        else:
            out_rows.append({'time':time,'subject':subject,'fuzzer':fuzzer,'run':run,'cov_type':'l_per','cov':''})
            out_rows.append({'time':time,'subject':subject,'fuzzer':fuzzer,'run':run,'cov_type':'b_per','cov':''})

results_path = os.path.join(OUT_DIR, 'results.csv')
with open(results_path, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['time','subject','fuzzer','run','cov_type','cov']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in out_rows:
        writer.writerow(row)

# create other files empty to match reference
open(os.path.join(OUT_DIR,'llm_cost.csv'),'w',encoding='utf-8').write('')
open(os.path.join(OUT_DIR,'mean_plot_data.csv'),'w',encoding='utf-8').write('')
open(os.path.join(OUT_DIR,'states.csv'),'w',encoding='utf-8').write('')

print('Wrote reference-format results to', results_path)
