#!/usr/bin/env python3
"""Reproduce this audited 2026-09-29 snapshot, with fail-fast source checks.

Default: regenerate all seven empirical PDF/SVG figures, tables, and the PDF.
--reuse-figures: retain current figures and independently verify every plotted value.
This reproduces a fixed evidence snapshot; future data updates require a new audit
of manuscript prose and scientific interpretation, not only rerunning this script.
"""
from pathlib import Path
import argparse, hashlib, json, subprocess, sys
BASE=Path(__file__).resolve().parent
args=argparse.ArgumentParser(description=__doc__)
args.add_argument('--reuse-figures',action='store_true')
args=args.parse_args()
load=lambda p:json.loads(p.read_text())
manifest=load(BASE/'data_update_manifest_20260929.json');root=Path(manifest['source_root'])
ledger=load(BASE/'filled_run_evidence_20260929.json')
subtrees=['benchmark','ablation/direct','ablation/calibrated','ablation/cal_gamma099','ablation/cal_gamma100']
actual={str(p.relative_to(root)) for sub in subtrees for p in (root/sub).rglob('*.tar.gz')}
assert actual==set(manifest['archive_sha256']),'Source inventory changed; audit the new data before regeneration.'
summaries={str(p.relative_to(root)) for sub in subtrees for p in (root/sub).glob('*/run_summary.csv')}
assert summaries==set(manifest['summary_files']),'Source summary inventory changed.'
for name,digest in manifest['summary_files'].items():
 assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest,'Source summary changed: '+name
for r in ledger['runs']:
 stat=(root/r['source_rel']).stat()
 assert (stat.st_size,stat.st_mtime_ns)==(r['archive_bytes'],r['archive_mtime_ns']),'Source archive changed: '+r['source_rel']
def run(script):
 print('Running',script,flush=True)
 subprocess.run([sys.executable,str(BASE/script)],cwd=BASE,check=True)
if not args.reuse_figures:
 run('plot_updated_figures_20260929.py')
 run('plot_native_endpoints_20260929.py')
run('generate_tex_20260929.py')
print('Compiling main.revised.pdf',flush=True)
with (BASE/'build_data_update_final_20260929.log').open('w') as log:
 subprocess.run(['bash',str(BASE/'build_revised.sh')],cwd=BASE,stdout=log,stderr=subprocess.STDOUT,check=True)
subprocess.run(['pdftotext','-layout',str(BASE/'main.revised.pdf'),str(BASE/'main.revised.txt')],check=True)
run('verify_vulnerability_evidence_20260929.py')
run('verify_data_update_20260929.py')
print('Snapshot regenerated and verified.',flush=True)
