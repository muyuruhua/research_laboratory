#!/usr/bin/env python3
import os
import csv
import shutil
from datetime import datetime

ROOT = os.path.join(os.path.dirname(__file__), '..')
SRC_DIR = os.path.join(ROOT, 'benchmark', 'results-recovered-2026-03-16_09-19-25')
OUT_BASE = os.path.join(ROOT, 'benchmark')

subjects = ['kamailio', 'live555']
timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

def make_target(subject):
    name = f'results-{subject}-{timestamp}'
    path = os.path.join(OUT_BASE, name)
    os.makedirs(path, exist_ok=True)
    return path

def copy_matching_tars(subject, target_dir):
    for fn in os.listdir(SRC_DIR):
        if not fn.endswith('.tar.gz'):
            continue
        # accept prefixes like out-<subject>-* or out-<subject>_* or out-<subject>*
        if fn.startswith(f'out-{subject}-') or fn.startswith(f'out-{subject}_') or fn.startswith(f'out-{subject}'):
            shutil.copy2(os.path.join(SRC_DIR, fn), os.path.join(target_dir, fn))

def filter_results_for_subject(subject, src_results, dst_path):
    out_rows = []
    with open(src_results, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r.get('subject','') == subject:
                out_rows.append(r)
    # write filtered results.csv in dst_path
    if out_rows:
        fieldnames = list(out_rows[0].keys())
        with open(os.path.join(dst_path, 'results.csv'), 'w', newline='', encoding='utf-8') as wf:
            writer = csv.DictWriter(wf, fieldnames=fieldnames)
            writer.writeheader()
            for r in out_rows:
                writer.writerow(r)
    else:
        # create empty results.csv
        with open(os.path.join(dst_path, 'results.csv'), 'w', newline='', encoding='utf-8') as wf:
            wf.write('time,subject,fuzzer,run,cov_type,cov\n')

def copy_placeholders(target_dir):
    # copy llm_cost, mean_plot_data, states if exist; otherwise create empty
    for name in ('llm_cost.csv','mean_plot_data.csv','states.csv','cov_over_time_recovered.png','state_over_time_recovered.png'):
        src = os.path.join(SRC_DIR, name)
        dst = os.path.join(target_dir, name.replace('recovered',''+''))
        if os.path.exists(src):
            shutil.copy2(src, dst)
        else:
            open(dst, 'wb').close()

def main():
    src_results = os.path.join(SRC_DIR, 'results.csv')
    if not os.path.exists(SRC_DIR) or not os.path.exists(src_results):
        print('Source recovered directory or results.csv missing:', SRC_DIR)
        return
    for subject in subjects:
        tgt = make_target(subject)
        copy_matching_tars(subject, tgt)
        filter_results_for_subject(subject, src_results, tgt)
        copy_placeholders(tgt)
        print('Created', tgt)

if __name__ == '__main__':
    main()
