#!/usr/bin/env python3
"""Read numeric figure evidence without extracting archive paths to disk.

Uses the audited run ledger to identify sources. Rebuild with this script;
plotting thereafter uses the versioned compact evidence, not /tmp caches.
"""
import argparse
import csv
import gzip
import hashlib
import io
import json
import math
import tarfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
FIELDS = ['episode_id', 'time_ms', 'selected_state', 'alpha_before', 'beta_before',
          'posterior_mean_before', 'sampled_theta', 'frontier_score',
          'final_selection_score', 'mutations', 'new_code_edges', 'new_state_edges',
          'reward', 'alpha_after', 'beta_after', 'episode_latency_ms']

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=Path('/home/ckt/Documents/000_2026_test_dev/Key_Experiment'))
    args = parser.parse_args()
    ledger_path = BASE / 'filled_run_evidence_20260930.json'
    ledger = json.loads(ledger_path.read_text())['runs']
    runs = [r for r in ledger if r['arm'] in 'ABCDE']
    cache_dir = BASE / 'figure_evidence_cache_20260930'
    cache_dir.mkdir(exist_ok=True)
    output = {'schema': 1, 'episode_fields': FIELDS, 'nominal_n': 10,
              'ledger_sha256': hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
              'policy': 'D is benchmark LoopFuzz, counted once; no fabricated runs or zero padding.',
              'runs': []}
    for i, row in enumerate(runs):
        path = args.source_root / row['source_rel']
        cache_path = cache_dir / (hashlib.sha256(row['source_rel'].encode()).hexdigest() + '.json.gz')
        if cache_path.exists():
            with gzip.open(cache_path, 'rt') as f:
                cached = json.load(f)
            if cached['archive_bytes'] == path.stat().st_size and cached['archive_mtime_ns'] == path.stat().st_mtime_ns and all(cached.get(k) == v for k, v in row.items()):
                output['runs'].append(cached)
                continue
        need = {'cov_over_time.csv', 'fuzzer_stats'}
        if row['arm'] == 'E':
            need.update(['state-episodes.jsonl', 'run-config.jsonl'])
        found = {}
        with tarfile.open(path, 'r|*') as archive:
            for member in archive:
                name = member.name.rsplit('/', 1)[-1]
                if member.isfile() and name in need:
                    assert name not in found, (path, name, 'ambiguous member')
                    raw = archive.extractfile(member).read()
                    found[name] = (member.name, raw)
        assert 'cov_over_time.csv' in found, path
        member, raw = found['cov_over_time.csv']
        points = {}
        duplicates = 0
        for x in csv.DictReader(io.StringIO(raw.decode('utf-8'))):
            t, y = float(x['Time']), float(x['b_abs'])
            assert math.isfinite(t) and math.isfinite(y) and y >= 0, path
            duplicates += int(t in points)
            points[t] = max(points.get(t, -1), y)
        points = sorted(points.items())
        assert len(points) >= 2, path
        stats = dict(line.split(':', 1) for line in found['fuzzer_stats'][1].decode('utf-8').splitlines() if ':' in line)
        stats = {k.strip(): v.strip() for k, v in stats.items()}
        start = int(stats['start_time'])
        auc = sum((b[0]-a[0])*(a[1]+b[1])/7200 for a, b in zip(points, points[1:]))
        assert math.isclose(auc, row['auc_branch_hours'], rel_tol=1e-10, abs_tol=1e-6), path
        endpoint_matches = points[-1][1] == float(row['summary']['b_abs'])
        item = dict(row)
        item.update({'archive_bytes': path.stat().st_size, 'archive_mtime_ns': path.stat().st_mtime_ns,
                     'fuzzer_start_time': start, 'coverage_member': member, 'coverage_sha256': hashlib.sha256(raw).hexdigest(),
                     'duplicate_timestamps': duplicates, 'endpoint_matches_summary': endpoint_matches,
                     'coverage': [[(t-start)/3600, y] for t, y in points]})
        if row['arm'] == 'E':
            ev_raw = found.get('state-episodes.jsonl', ('', b''))[1]
            events = [json.loads(x) for x in ev_raw.decode('utf-8').splitlines() if x.strip()]
            assert len(events) == row['episodes'], path
            item['episode_data'] = [[e.get(k) for k in FIELDS] for e in events]
            item['episode_sha256'] = hashlib.sha256(ev_raw).hexdigest()
            configs = [json.loads(x) for x in found.get('run-config.jsonl', ('', b''))[1].decode('utf-8').splitlines() if x.strip()]
            cfg = configs[-1] if configs else {}
            item['config_evidence'] = {k: cfg.get(k) for k in ['phase', 'calibration', 'cal_gamma', 'cal_epsilon', 'start_time_ms', 'end_time_ms']}
        with gzip.GzipFile(filename=str(cache_path), mode='wb', mtime=0) as f:
            f.write(json.dumps(item, separators=(',', ':'), allow_nan=False).encode())
        output['runs'].append(item)
        if (i+1) % 40 == 0 or i+1 == len(runs):
            print(f'Numeric figure evidence: {i+1}/{len(runs)} archives', flush=True)
    with gzip.GzipFile(filename=str(BASE / 'vector_figure_evidence_20260930.json.gz'), mode='wb', mtime=0) as f:
        f.write(json.dumps(output, separators=(',', ':'), allow_nan=False).encode())
    print('Evidence saved; original archives unchanged.', flush=True)

if __name__ == '__main__':
    main()
