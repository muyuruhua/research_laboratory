#!/usr/bin/env python3
"""
Full recovery script: converts recovered container data into benchmark-ready
directories matching the reference format (results-pure-ftpd_Mar-10_22-37-08).

Generates per-subject directories:
  results-kamailio_recovered_Mar-16_HH-MM-SS/
  results-live555_recovered_Mar-16_HH-MM-SS/

Each containing:
  results.csv          — time-series coverage (time,subject,fuzzer,run,cov_type,cov)
  states.csv           — time-series state    (time,subject,fuzzer,run,state_type,state)
  mean_plot_data.csv   — averaged state data  (subject,fuzzer,data_type,time,data)
  llm_cost.csv         — LLM token costs      (fuzzer,run,runtime_min,...)
  out-<subject>-<fuzzer>_<run>.tar.gz  — packaged output directories
"""
import csv
import math
import os
import sys
import tarfile
from collections import defaultdict
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RECOVERED = os.path.join(ROOT, 'recovered_data')
BENCH = os.path.join(ROOT, 'benchmark')
TIMESTAMP = datetime.now().strftime('Mar-%d_%H-%M-%S')

# ── User-provided container → fuzzer mapping ────────────────────────
MAPPING = {
    'kamailio': {
        'aflnet': [
            '1019471e1cae', '18257ee3838d', '20489d80f9f1',
            'a94a828981fe', 'f34a3389827f',
        ],
        'chatafl': [
            '7ede83fe42f1', '59385db6025b', 'fef1b16747cc', '89f429f03e53',
        ],
        'chatafl_opt': [
            'ed8fe8593deb', 'e38c6ffd6384', '467c0c9473a8',
            '5cd96a3ce01c', '26391854b422',
        ],
    },
    'live555': {
        'aflnet': [
            '7828601b63f3', '1a7c417a0833', '61d20769891b',
            '95c22519cb26', 'f0422f1b690a',
        ],
        'chatafl': [
            '8705f3cbebad', '11fd00130f76', 'a12eddfcf886', '2029826af9b6',
        ],
        'chatafl_opt': [
            'ca656cf4fb31', 'f08ff16051e2', '42a24abf9fba',
            '88f97531726c', '389daf0811fe',
        ],
    },
}


# ── helpers ──────────────────────────────────────────────────────────
def find_out_dir(container_id):
    """Return the first out-* directory inside recovered_data/<cid>/experiments/."""
    base = os.path.join(RECOVERED, container_id, 'experiments')
    if not os.path.isdir(base):
        return None
    for dirpath, dirnames, _ in os.walk(base):
        for d in dirnames:
            if d.startswith('out-'):
                return os.path.join(dirpath, d)
    return None


def read_cov_over_time(out_dir):
    """Read cov_over_time.csv → list of (time, l_per, l_abs, b_per, b_abs)."""
    path = os.path.join(out_dir, 'cov_over_time.csv')
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, 'r') as f:
        f.readline()  # skip header
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 5:
                continue
            try:
                rows.append((int(parts[0]), parts[1], parts[2], parts[3], parts[4]))
            except ValueError:
                continue
    return rows


def read_plot_data(out_dir):
    """Read plot_data → list of (time, n_nodes, n_edges)."""
    path = os.path.join(out_dir, 'plot_data')
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, 'r') as f:
        f.readline()  # skip header comment
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 13:
                continue
            try:
                time_val = int(parts[0])
                nodes = int(parts[11])
                edges = int(parts[12])
                rows.append((time_val, nodes, edges))
            except ValueError:
                continue
    return rows


def read_fuzzer_stats(out_dir):
    """Parse fuzzer_stats → dict."""
    path = os.path.join(out_dir, 'fuzzer_stats')
    info = {}
    if not os.path.isfile(path):
        return info
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            if ':' not in line:
                continue
            k, v = line.split(':', 1)
            info[k.strip()] = v.strip()
    return info


def make_tar(src_dir, tar_path):
    """Create tar.gz from a directory."""
    with tarfile.open(tar_path, 'w:gz') as tar:
        tar.add(src_dir, arcname=os.path.basename(src_dir))


def compute_mean_plot_data(states_rows, step=60, cutoff=1440):
    """
    Compute mean state data across runs, binned at 0,1,61,121,...,1441 minutes.
    states_rows: list of (time, subject, fuzzer, run, state_type, state_value)
    Returns list of (subject, fuzzer, data_type, time_min, mean_val).
    """
    # group by (subject, fuzzer, run, state_type) → list of (time, value)
    grouped = defaultdict(list)
    for (t, subj, fuz, run, stype, sval) in states_rows:
        grouped[(subj, fuz, run, stype)].append((t, float(sval)))

    # find start_time per (subject, fuzzer, run)
    start_times = {}
    for (subj, fuz, run, stype), vals in grouped.items():
        key = (subj, fuz, run)
        if key not in start_times:
            start_times[key] = min(v[0] for v in vals)
        else:
            start_times[key] = min(start_times[key], min(v[0] for v in vals))

    # unique (subject, fuzzer, state_type) combos
    combos = sorted(set((subj, fuz, stype) for (subj, fuz, _, stype) in grouped.keys()))

    results = []
    for (subj, fuz, stype) in combos:
        # time bins: 0, 1, 61, 121, ..., cutoff+1
        time_bins = [0, 1] + list(range(61, cutoff + 2, step))
        for time_min in time_bins:
            total = 0.0
            count = 0
            # iterate all runs for this (subject, fuzzer, state_type)
            runs = set(run for (s, f, run, st) in grouped.keys()
                       if s == subj and f == fuz and st == stype)
            for run in runs:
                key = (subj, fuz, run, stype)
                vals = grouped.get(key, [])
                if not vals:
                    continue
                start = start_times.get((subj, fuz, run), vals[0][0])
                cutoff_ts = start + time_min * 60
                # find last value at or before cutoff_ts
                last_val = None
                for (t, v) in sorted(vals):
                    if t <= cutoff_ts:
                        last_val = v
                    else:
                        break
                if last_val is not None:
                    total += last_val
                    count += 1
            mean_val = round(total / max(1, count), 1)
            results.append((subj, fuz, stype, time_min, mean_val))
    return results


# ── main ─────────────────────────────────────────────────────────────
def process_subject(subject, fuzzer_map):
    dir_name = f'results-{subject}_recovered_{TIMESTAMP}'
    out_base = os.path.join(BENCH, dir_name)
    os.makedirs(out_base, exist_ok=True)

    results_rows = []   # for results.csv
    states_rows = []    # for states.csv (raw tuples for mean calc)
    llm_rows = []       # for llm_cost.csv

    results_csv_path = os.path.join(out_base, 'results.csv')
    states_csv_path = os.path.join(out_base, 'states.csv')
    mean_csv_path = os.path.join(out_base, 'mean_plot_data.csv')
    llm_csv_path = os.path.join(out_base, 'llm_cost.csv')

    for fuzzer, container_ids in fuzzer_map.items():
        for run_idx, cid in enumerate(container_ids, start=1):
            out_dir = find_out_dir(cid)
            if not out_dir:
                print(f'  WARNING: no out-* dir for {cid}', file=sys.stderr)
                continue

            # ── results.csv (coverage time-series) ──
            cov_rows = read_cov_over_time(out_dir)
            for (t, lper, labs, bper, babs) in cov_rows:
                results_rows.append((t, subject, fuzzer, run_idx, 'l_per', lper))
                results_rows.append((t, subject, fuzzer, run_idx, 'l_abs', labs))
                results_rows.append((t, subject, fuzzer, run_idx, 'b_per', bper))
                results_rows.append((t, subject, fuzzer, run_idx, 'b_abs', babs))

            # ── states.csv (state time-series) ──
            plot_rows = read_plot_data(out_dir)
            for (t, nodes, edges) in plot_rows:
                states_rows.append((t, subject, fuzzer, run_idx, 'nodes', nodes))
                states_rows.append((t, subject, fuzzer, run_idx, 'edges', edges))

            # ── llm_cost.csv ──
            stats = read_fuzzer_stats(out_dir)
            start_t = int(stats.get('start_time', '0') or '0')
            last_t = int(stats.get('last_update', str(start_t)) or str(start_t))
            runtime_min = (last_t - start_t) // 60 if start_t > 0 else 0
            calls = stats.get('llm_total_calls', '')
            pt = stats.get('llm_prompt_tokens', '')
            ct = stats.get('llm_completion_tok', '')
            dedup = stats.get('llm_dedup_hits', '')
            token_source = 'exact' if calls else 'estimated'

            # estimate tokens from stall-interactions if not in fuzzer_stats
            if not calls:
                stall_dir = os.path.join(out_dir, 'stall-interactions')
                if os.path.isdir(stall_dir):
                    prompts = sorted(f for f in os.listdir(stall_dir) if f.startswith('prompt-'))
                    responses = sorted(f for f in os.listdir(stall_dir) if f.startswith('response-'))
                    calls = str(len(prompts))
                    total_pt = 0
                    total_ct = 0
                    for pf in prompts:
                        try:
                            total_pt += os.path.getsize(os.path.join(stall_dir, pf)) // 4
                        except OSError:
                            pass
                    for rf in responses:
                        try:
                            total_ct += os.path.getsize(os.path.join(stall_dir, rf)) // 4
                        except OSError:
                            pass
                    pt = str(total_pt)
                    ct = str(total_ct)
                    dedup = '0'
                    token_source = 'estimated'

            # cost calculation (gpt-4o-mini: $0.15/1M prompt, $0.60/1M completion)
            pt_val = int(pt) if pt else 0
            ct_val = int(ct) if ct else 0
            cost = (pt_val * 0.15 + ct_val * 0.60) / 1_000_000
            pt_24h = int(pt_val / runtime_min * 1440) if runtime_min > 0 else 0
            ct_24h = int(ct_val / runtime_min * 1440) if runtime_min > 0 else 0
            cost_24h = cost / runtime_min * 1440 if runtime_min > 0 else 0

            llm_rows.append([
                fuzzer, run_idx, runtime_min,
                calls or '0', pt_val, ct_val, dedup or '0',
                f'{cost:.6f}', pt_24h, ct_24h, f'{cost_24h:.6f}', token_source
            ])

            # ── tar.gz packaging ──
            tar_name = f'out-{subject}-{fuzzer}_{run_idx}.tar.gz'
            tar_path = os.path.join(out_base, tar_name)
            print(f'  Packaging {cid} → {tar_name}')
            make_tar(out_dir, tar_path)

    # ── Write results.csv ──
    with open(results_csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['time', 'subject', 'fuzzer', 'run', 'cov_type', 'cov'])
        for row in results_rows:
            w.writerow(row)
    print(f'  results.csv: {len(results_rows)} rows')

    # ── Write states.csv ──
    with open(states_csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['time', 'subject', 'fuzzer', 'run', 'state_type', 'state'])
        for row in states_rows:
            w.writerow(row)
    print(f'  states.csv: {len(states_rows)} rows')

    # ── Write mean_plot_data.csv ──
    mean_data = compute_mean_plot_data(states_rows)
    with open(mean_csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['subject', 'fuzzer', 'data_type', 'time', 'data'])
        for row in mean_data:
            w.writerow(row)
    print(f'  mean_plot_data.csv: {len(mean_data)} rows')

    # ── Write llm_cost.csv ──
    with open(llm_csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['fuzzer', 'run', 'runtime_min', 'llm_calls',
                     'prompt_tokens', 'completion_tokens', 'dedup_hits',
                     'cost_usd', 'prompt_per_24h', 'compl_per_24h',
                     'cost_per_24h', 'token_source'])
        for row in llm_rows:
            w.writerow(row)
    print(f'  llm_cost.csv: {len(llm_rows)} rows')

    # ── Placeholder PNGs ──
    for name in [f'cov_over_time_{subject}_{TIMESTAMP}.png',
                 f'state_over_time_{subject}_{TIMESTAMP}.png']:
        open(os.path.join(out_base, name), 'wb').close()

    print(f'  ✓ Done → {dir_name}/')
    return dir_name


def main():
    print('=' * 60)
    print(f'Full recovery — {TIMESTAMP}')
    print('=' * 60)
    created = []
    for subject, fuzzer_map in MAPPING.items():
        print(f'\n── {subject} ──')
        d = process_subject(subject, fuzzer_map)
        created.append(d)
    print('\n' + '=' * 60)
    print('Created directories:')
    for d in created:
        print(f'  benchmark/{d}/')
    print('=' * 60)


if __name__ == '__main__':
    main()
