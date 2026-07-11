#!/usr/bin/env python3
import os
import csv
from datetime import datetime

ROOT = os.path.join(os.path.dirname(__file__), '..')
RECD = os.path.join(ROOT, 'recovered_data')

# Lists provided by the user (mapped to fuzzer types)
aflnet = ['1019471e1cae','18257ee3838d','20489d80f9f1','7828601b63f3','1a7c417a0833','61d20769891b','95c22519cb26','a94a828981fe','f34a3389827f','f0422f1b690a']
chatafl = ['7ede83fe42f1','59385db6025b','fef1b16747cc','89f429f03e53','8705f3cbebad','11fd00130f76','a12eddfcf886','2029826af9b6']
loopfuzz = ['ed8fe8593deb','e38c6ffd6384','ca656cf4fb31','f08ff16051e2','467c0c9473a8','5cd96a3ce01c','42a24abf9fba','88f97531726c','26391854b422','389daf0811fe']

ALL = {'aflnet': aflnet, 'chatafl': chatafl, 'loopfuzz': loopfuzz}

OUT_DIR = os.path.join(ROOT, 'benchmark', f'recovered-containers-{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}')
os.makedirs(OUT_DIR, exist_ok=True)

def parse_fuzzer_stats(path):
    data = {}
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if ':' not in line:
                    continue
                k, v = line.split(':', 1)
                k = k.strip()
                v = v.strip()
                data[k] = v
    except Exception:
        return None
    return data

rows = []
for fuzzer_name, ids in ALL.items():
    for cid in ids:
        container_dir = os.path.join(RECD, cid)
        if not os.path.isdir(container_dir):
            rows.append({'time':'', 'subject':'', 'fuzzer':fuzzer_name, 'container':cid, 'execs_done':'', 'paths_total':'', 'bitmap_cvg':'', 'unique_crashes':'', 'unique_hangs':'', 'command_line':'', 'note':'container missing'})
            continue
        found = False
        for root, dirs, files in os.walk(container_dir):
            if 'fuzzer_stats' in files:
                fs = os.path.join(root, 'fuzzer_stats')
                data = parse_fuzzer_stats(fs)
                if not data:
                    continue
                # try to infer subject from path: look for out-<subject>-<fuzzer>
                subject = ''
                parts = root.split(os.sep)
                for p in parts:
                    if p.startswith('out-'):
                        # out-<subject>-<fuzzer> or out-<subject>-aflnet
                        sp = p[len('out-'):]
                        # split by last -
                        if '-' in sp:
                            subject = '-'.join(sp.split('-')[:-1])
                        else:
                            subject = sp
                        break
                rows.append({
                    'time': data.get('last_update', data.get('start_time', '')),
                    'subject': subject,
                    'fuzzer': fuzzer_name,
                    'container': cid,
                    'execs_done': data.get('execs_done',''),
                    'paths_total': data.get('paths_total',''),
                    'bitmap_cvg': data.get('bitmap_cvg',''),
                    'unique_crashes': data.get('unique_crashes',''),
                    'unique_hangs': data.get('unique_hangs',''),
                    'command_line': data.get('command_line',''),
                    'note': fs.replace(ROOT + os.sep, '')
                })
                found = True
        if not found:
            rows.append({'time':'', 'subject':'', 'fuzzer':fuzzer_name, 'container':cid, 'execs_done':'', 'paths_total':'', 'bitmap_cvg':'', 'unique_crashes':'', 'unique_hangs':'', 'command_line':'', 'note':'no fuzzer_stats found'})

# write results.csv similar-ish to reference but with fields we have
results_path = os.path.join(OUT_DIR, 'results.csv')
with open(results_path, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['time','subject','fuzzer','container','execs_done','paths_total','bitmap_cvg','unique_crashes','unique_hangs','command_line','note']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        writer.writerow(r)

# create minimal placeholder files to match folder structure
open(os.path.join(OUT_DIR, 'llm_cost.csv'), 'w', encoding='utf-8').write('')
open(os.path.join(OUT_DIR, 'mean_plot_data.csv'), 'w', encoding='utf-8').write('')
open(os.path.join(OUT_DIR, 'states.csv'), 'w', encoding='utf-8').write('')

print('Wrote', results_path)
