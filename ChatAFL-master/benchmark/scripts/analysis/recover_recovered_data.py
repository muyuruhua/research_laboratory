#!/usr/bin/env python3
import csv
import os
import re
import sys
from collections import defaultdict
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
RECOVERED = os.path.join(ROOT, 'recovered_data')
OUT_BASE = os.path.join(ROOT, 'benchmark')
LOOPFUZZ_FUZZER = 'loopfuzz'
LEGACY_LOOPFUZZ_FUZZERS = {'chat' + 'afl_opt', 'chat' + 'afl-opt'}
KNOWN_FUZZERS = (
    LOOPFUZZ_FUZZER,
    'chatafl',
    'aflnet',
    'aflnwe',
    'stateafl',
    'nsfuzz',
    'snpsfuzzer',
    'mbfuzzer',
    *LEGACY_LOOPFUZZ_FUZZERS,
)


def normalize_fuzzer_name(name):
    return LOOPFUZZ_FUZZER if name in LEGACY_LOOPFUZZ_FUZZERS else name

def find_out_dirs(root):
    out_dirs = []
    for entry in os.listdir(root):
        exp = os.path.join(root, entry, 'experiments')
        if not os.path.isdir(exp):
            continue
        for d in os.listdir(exp):
            path = os.path.join(exp, d)
            # look for out-* directories under experiments or nested
            for sub in os.walk(path):
                for name in sub[1]:
                    if name.startswith('out-'):
                        out_dirs.append(os.path.join(sub[0], name))
    return sorted(set(out_dirs))

# parse out name like out-live555-chatafl or out-forked-daapd-loopfuzz
OUT_RE = re.compile(r'^out-(.+)-([^-]+)$')


def parse_out_dir_name(path):
    name = os.path.basename(path)
    if not name.startswith('out-'):
        return None
    body = name[4:]
    for fuzzer in sorted(KNOWN_FUZZERS, key=len, reverse=True):
        suffix = '-' + fuzzer
        if body.endswith(suffix):
            return body[:-len(suffix)], normalize_fuzzer_name(fuzzer)
    m = OUT_RE.match(name)
    if not m:
        return None
    return m.group(1), normalize_fuzzer_name(m.group(2))


def read_cov_over_time(path):
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, 'r') as f:
        header = f.readline()
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(',')]
            # expect: Time,l_per,l_abs,b_per,b_abs
            try:
                time = int(parts[0])
                l_per = parts[1]
                l_abs = parts[2]
                b_per = parts[3]
                b_abs = parts[4]
                rows.append((time, l_per, l_abs, b_per, b_abs))
            except Exception:
                continue
    return rows


def read_plot_data(path):
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, 'r') as f:
        hdr = f.readline()
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(',')]
            try:
                time = int(parts[0])
                nodes = parts[11]  # n_nodes
                edges = parts[12]  # n_edges
                rows.append((time, nodes, edges))
            except Exception:
                continue
    return rows


def read_fuzzer_stats(path):
    info = {}
    if not os.path.isfile(path):
        return info
    with open(path, 'r') as f:
        for line in f:
            if ':' not in line:
                continue
            k, v = line.split(':', 1)
            info[k.strip()] = v.strip()
    return info


def main():
    out_dirs = find_out_dirs(RECOVERED)
    if not out_dirs:
        print('No out-* dirs found under recovered_data', file=sys.stderr)
        sys.exit(1)

    # group runs per (subject,fuzzer)
    groups = defaultdict(list)
    meta = {}
    for d in out_dirs:
        parsed = parse_out_dir_name(d)
        if not parsed:
            continue
        subject, fuzzer = parsed
        groups[(subject, fuzzer)].append(d)

    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H%M%SZ')
    outdir = os.path.join(OUT_BASE, f'results-recovered_{timestamp}')
    os.makedirs(outdir, exist_ok=True)

    results_csv = os.path.join(outdir, 'results.csv')
    states_csv = os.path.join(outdir, 'states.csv')
    mean_csv = os.path.join(outdir, 'mean_plot_data.csv')
    llm_csv = os.path.join(outdir, 'llm_cost.csv')

    # headers
    with open(results_csv, 'w', newline='') as rf, open(states_csv, 'w', newline='') as sf, open(llm_csv, 'w', newline='') as lf:
        rwriter = csv.writer(rf)
        swriter = csv.writer(sf)
        lwriter = csv.writer(lf)
        rwriter.writerow(['time','subject','fuzzer','run','cov_type','cov'])
        swriter.writerow(['time','subject','fuzzer','run','state_type','state'])
        lwriter.writerow(['fuzzer','run','runtime_min','llm_calls','prompt_tokens','completion_tokens','notes'])

        # iterate groups and treat each element as a run (indexing 1..N)
        for (subject,fuzzer), dirs in sorted(groups.items()):
            for idx, d in enumerate(sorted(dirs), start=1):
                covf = os.path.join(d, 'cov_over_time.csv')
                plotf = os.path.join(d, 'plot_data')
                statf = os.path.join(d, 'fuzzer_stats')

                cov_rows = read_cov_over_time(covf)
                for (t,lper,labs,bper,babs) in cov_rows:
                    rwriter.writerow([t, subject, fuzzer, idx, 'l_per', lper])
                    rwriter.writerow([t, subject, fuzzer, idx, 'l_abs', labs])
                    rwriter.writerow([t, subject, fuzzer, idx, 'b_per', bper])
                    rwriter.writerow([t, subject, fuzzer, idx, 'b_abs', babs])

                plot_rows = read_plot_data(plotf)
                for (t,nodes,edges) in plot_rows:
                    swriter.writerow([t, subject, fuzzer, idx, 'nodes', nodes])
                    swriter.writerow([t, subject, fuzzer, idx, 'edges', edges])

                stats = read_fuzzer_stats(statf)
                try:
                    start = int(stats.get('start_time','0'))
                    last = int(stats.get('last_update', start))
                    runtime_min = (last - start) // 60 if start>0 else ''
                    calls = stats.get('llm_total_calls','')
                    pt = stats.get('llm_prompt_tokens','')
                    ct = stats.get('llm_completion_tok','')
                except Exception:
                    runtime_min = ''
                    calls = ''
                    pt = ''
                    ct = ''
                lwriter.writerow([fuzzer, idx, runtime_min, calls, pt, ct, 'recovered'])

    # generate mean_plot_data.csv (simple averaging at minute buckets with step=60)
    import pandas as pd
    df_states = pd.read_csv(states_csv)
    mean_list = []
    step = 60
    cutoff = 1440
    for (subject,fuzzer) in sorted({(r[1],r[2]) for r in csv.reader(open(results_csv))}):
        pass
    # Better: compute from df_states
    subjects = df_states['subject'].unique()
    for subject in subjects:
        for fuzzer in df_states[df_states['subject']==subject]['fuzzer'].unique():
            for data_type in ['nodes','edges']:
                mean_list.append((subject,fuzzer,data_type,0,0.0))
                for time_min in range(1, cutoff+1, step):
                    cov_total = 0.0
                    run_count = 0
                    for run in df_states[(df_states['subject']==subject) & (df_states['fuzzer']==fuzzer)]['run'].unique():
                        df_run = df_states[(df_states['subject']==subject) & (df_states['fuzzer']==fuzzer) & (df_states['run']==run)]
                        if df_run.empty:
                            continue
                        try:
                            start = int(df_run.iloc[0]['time'])
                        except Exception:
                            continue
                        # select rows up to start + time_min*60
                        cutoff_ts = start + time_min*60
                        df3 = df_run[df_run['time'] <= cutoff_ts]
                        if df3.empty:
                            continue
                        last_val = float(df3.iloc[-1]['state'])
                        cov_total += last_val
                        run_count += 1
                    mean = cov_total / max(1, run_count)
                    mean_list.append((subject,fuzzer,data_type,time_min,mean))

    mean_df = pd.DataFrame(mean_list, columns=['subject','fuzzer','data_type','time','data'])
    mean_df.to_csv(mean_csv, index=False)

    print('Recovered CSVs written to', outdir)

if __name__ == '__main__':
    main()
