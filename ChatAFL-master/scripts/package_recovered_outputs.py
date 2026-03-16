#!/usr/bin/env python3
import os
import csv
import tarfile
from collections import defaultdict

ROOT = os.path.join(os.path.dirname(__file__), '..')
IN_PATH = os.path.join(ROOT, 'benchmark', 'recovered-containers-2026-03-16_09-19-25', 'results.csv')
OUT_DIR = os.path.join(ROOT, 'benchmark', 'results-recovered-2026-03-16_09-19-25')
os.makedirs(OUT_DIR, exist_ok=True)

runs = defaultdict(int)

def find_out_dir_from_note(note):
    # note should contain path to fuzzer_stats; find parent 'out-*' folder in the path
    parts = note.split(os.sep)
    for i in range(len(parts)-1, -1, -1):
        if parts[i].startswith('out-'):
            return os.sep.join(parts[:i+1])
    return None

with open(IN_PATH, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for r in reader:
        subject = r.get('subject','') or 'unknown'
        fuzzer = r.get('fuzzer','unknown')
        note = r.get('note','')
        out_dir = find_out_dir_from_note(note)
        runs[(subject,fuzzer)] += 1
        run_idx = runs[(subject,fuzzer)]
        if out_dir and os.path.isdir(os.path.join(ROOT, out_dir)):
            src = os.path.join(ROOT, out_dir)
            tar_name = f'out-{subject}-{fuzzer}_{run_idx}.tar.gz'
            tar_path = os.path.join(OUT_DIR, tar_name)
            with tarfile.open(tar_path, 'w:gz') as tar:
                tar.add(src, arcname=os.path.basename(src))
            print('Packaged', src, '->', tar_path)
        else:
            # create empty tar placeholder
            tar_name = f'out-{subject}-{fuzzer}_{run_idx}.tar.gz'
            tar_path = os.path.join(OUT_DIR, tar_name)
            with tarfile.open(tar_path, 'w:gz') as tar:
                # create an empty file inside
                pass
            print('Placeholder created for missing', out_dir, '->', tar_path)

# create small placeholder images
open(os.path.join(OUT_DIR,'cov_over_time_recovered.png'),'wb').close()
open(os.path.join(OUT_DIR,'state_over_time_recovered.png'),'wb').close()

print('Packaging complete. Output directory:', OUT_DIR)
