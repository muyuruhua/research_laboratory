from __future__ import annotations

import json
import re
import tarfile
from pathlib import Path

import pandas as pd

try:
    from scipy.stats import mannwhitneyu
except Exception:  # pragma: no cover
    mannwhitneyu = None

ROOT = Path('/home/ckt/Documents/000_2026_test_dev/experiment_data')
OUT_DIR = Path('/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/generated')
PRIMARY_ROOT = ROOT / 'ten groups data (ten)'
ABLATION_ROOT = ROOT / 'ten groups ablation(ten)'
NSFUZZ_ROOT = ROOT / 'NSFUZZER(ten)'
MBFUZZER_DIR = ROOT / 'MBFUZZER(ten)' / 'parallel-results-mosquitto_Apr-16_18-58-00 (2.0.18)'

LOOPFUZZ_FUZZER = 'loopfuzz'
LEGACY_LOOPFUZZ_FUZZERS = {'chat' + 'afl_opt', 'chat' + 'afl-opt'}
PRIMARY_FUZZERS = ['aflnet', 'chatafl', LOOPFUZZ_FUZZER]
ABLATION_VARIANTS = [
    'adaptive_full',
    'wo_refinement',
    'wo_frontier',
    'wo_state_prompt',
    'fixed200_full',
    'fixed512_full',
]


def normalize_fuzzer_name(name: str) -> str:
    return LOOPFUZZ_FUZZER if name in LEGACY_LOOPFUZZ_FUZZERS else name


def count_ipsm_edges(dot_text: str) -> int:
    return len(re.findall(r'(?m)(?:"?\d+"?)\s*->\s*(?:"?\d+"?)', dot_text))


def parse_tar_metrics(tar_path: Path) -> dict:
    with tarfile.open(tar_path, 'r:gz') as tf:
        names = tf.getnames()
        stats_name = next(n for n in names if n.endswith('/fuzzer_stats'))
        cov_name = next(n for n in names if n.endswith('/cov_over_time.csv'))
        dot_name = next((n for n in names if n.endswith('/ipsm.dot')), None)

        stats_text = tf.extractfile(stats_name).read().decode('utf-8', errors='ignore').splitlines()
        stats = {}
        for line in stats_text:
            if ':' in line:
                key, value = line.split(':', 1)
                stats[key.strip()] = value.strip()

        cov_df = pd.read_csv(tf.extractfile(cov_name))
        start = int(stats.get('start_time', '0'))
        last = int(stats.get('last_update', '0'))
        runtime_min = (last - start) / 60 if start and last else 0.0
        result = {
            'runtime_min': runtime_min,
            'b_abs': float(cov_df['b_abs'].iloc[-1]),
            'l_abs': float(cov_df['l_abs'].iloc[-1]),
        }
        if dot_name:
            dot_text = tf.extractfile(dot_name).read().decode('utf-8', errors='ignore')
            result['edges'] = count_ipsm_edges(dot_text)
        return result


def exact_mwu(left: list[float], right: list[float]) -> float | None:
    if mannwhitneyu is None:
        return None
    return float(mannwhitneyu(left, right, alternative='two-sided', method='exact').pvalue)


def summarize_series(values: list[float]) -> dict:
    series = pd.Series(values, dtype='float64')
    return {
        'values': [float(v) for v in series.tolist()],
        'mean': float(series.mean()),
        'sd': float(series.std(ddof=1)) if len(series) > 1 else 0.0,
        'n': int(series.shape[0]),
    }


def build_primary_summary() -> dict:
    summary: dict[str, dict] = {}
    for result_dir in sorted(PRIMARY_ROOT.glob('results-*_*_ten')):
        subject = result_dir.name.split('results-')[1].split('_Mar-')[0]
        run_summary = pd.read_csv(result_dir / 'run_summary.csv')
        if 'fuzzer' in run_summary:
            run_summary['fuzzer'] = run_summary['fuzzer'].map(normalize_fuzzer_name)
        subject_item = {'primary': {}, 'pvalues': {}, 'paths': {'dir': str(result_dir)}}
        for fuzzer in PRIMARY_FUZZERS:
            sub = run_summary[run_summary['fuzzer'] == fuzzer].sort_values('run')
            subject_item['primary'][fuzzer] = {
                'b_abs': summarize_series(sub['b_abs'].tolist()),
                'l_abs': summarize_series(sub['l_abs'].tolist()),
                'edges': summarize_series(sub['edges'].tolist()),
            }
        for metric in ['b_abs', 'edges']:
            loop_vals = subject_item['primary'][LOOPFUZZ_FUZZER][metric]['values']
            subject_item['pvalues'][metric] = {}
            for base in ['aflnet', 'chatafl']:
                base_vals = subject_item['primary'][base][metric]['values']
                subject_item['pvalues'][metric][base] = exact_mwu(loop_vals, base_vals)
        summary[subject] = subject_item

    for ns_dir in sorted([p for p in NSFUZZ_ROOT.iterdir() if p.is_dir()]):
        subject = ns_dir.name.replace('-nsfuzz', '')
        cov_vals, line_vals, edge_vals = [], [], []
        for tar_path in sorted(ns_dir.glob('out-*.tar.gz')):
            metrics = parse_tar_metrics(tar_path)
            cov_vals.append(metrics['b_abs'])
            line_vals.append(metrics['l_abs'])
            if 'edges' in metrics:
                edge_vals.append(metrics['edges'])
        summary.setdefault(subject, {'primary': {}, 'pvalues': {}, 'paths': {}})
        summary[subject]['nsfuzz'] = {
            'b_abs': summarize_series(cov_vals),
            'l_abs': summarize_series(line_vals),
            'edges': summarize_series(edge_vals) if edge_vals else None,
        }

    if MBFUZZER_DIR.exists():
        mb_df = pd.read_csv(MBFUZZER_DIR / 'summary.csv')
        summary.setdefault('mosquitto', {'primary': {}, 'pvalues': {}, 'paths': {}})
        summary['mosquitto']['mbfuzzer'] = {
            'b_abs': summarize_series(mb_df['branch_covered'].tolist()),
            'l_abs': summarize_series(mb_df['line_covered'].tolist()),
        }
    return summary


def build_ablation_summary() -> dict:
    summary: dict[str, dict] = {}
    for result_dir in sorted([p for p in ABLATION_ROOT.iterdir() if p.is_dir()]):
        match = re.match(r'results-(.+?)_ablation_(.+?)_(\d{8}T\d+)$', result_dir.name)
        if not match:
            continue
        subject, variant, _ = match.groups()
        rows = []
        bad_runs = []
        for tar_path in sorted(result_dir.glob('*.tar.gz')):
            run = int(re.search(r'_(\d+)\.tar\.gz$', tar_path.name).group(1))
            try:
                metrics = parse_tar_metrics(tar_path)
                metrics['run'] = run
                rows.append(metrics)
            except Exception as exc:  # pragma: no cover
                bad_runs.append({'run': run, 'error': type(exc).__name__})
        valid_rows = [row for row in rows if row['runtime_min'] >= 1400]
        chosen_rows = sorted(valid_rows, key=lambda row: row['run'])[:10]
        chosen_df = pd.DataFrame(chosen_rows)
        summary.setdefault(subject, {})[variant] = {
            'available_valid_runs': len(valid_rows),
            'chosen_runs': [int(row['run']) for row in chosen_rows],
            'bad_runs': bad_runs,
            'b_abs': summarize_series(chosen_df['b_abs'].tolist()) if not chosen_df.empty else None,
            'l_abs': summarize_series(chosen_df['l_abs'].tolist()) if not chosen_df.empty else None,
            'edges': summarize_series(chosen_df['edges'].tolist()) if not chosen_df.empty and 'edges' in chosen_df else None,
        }
    return summary


def build_compact_report(primary: dict, ablation: dict) -> dict:
    loop_wins_cov = []
    loop_wins_edges = []
    for subject, item in primary.items():
        if 'primary' not in item or not item['primary']:
            continue
        cov_means = {name: item['primary'][name]['b_abs']['mean'] for name in PRIMARY_FUZZERS if name in item['primary']}
        edge_means = {name: item['primary'][name]['edges']['mean'] for name in PRIMARY_FUZZERS if name in item['primary']}
        if cov_means and max(cov_means, key=cov_means.get) == LOOPFUZZ_FUZZER:
            loop_wins_cov.append(subject)
        if edge_means and max(edge_means, key=edge_means.get) == LOOPFUZZ_FUZZER:
            loop_wins_edges.append(subject)

    ablation_overview = {}
    for subject, variants in ablation.items():
        adaptive = variants.get('adaptive_full')
        if not adaptive or not adaptive.get('b_abs'):
            continue
        adaptive_cov = adaptive['b_abs']['mean']
        adaptive_edges = adaptive['edges']['mean'] if adaptive.get('edges') else None
        ablation_overview[subject] = {}
        for variant, values in variants.items():
            if variant == 'adaptive_full' or not values.get('b_abs'):
                continue
            entry = {
                'cov_delta': float(values['b_abs']['mean'] - adaptive_cov),
            }
            if adaptive_edges is not None and values.get('edges'):
                entry['edges_delta'] = float(values['edges']['mean'] - adaptive_edges)
            ablation_overview[subject][variant] = entry
    return {
        'loopfuzz_cov_wins_primary': sorted(loop_wins_cov),
        'loopfuzz_edge_wins_primary': sorted(loop_wins_edges),
        'ablation_overview': ablation_overview,
    }


def main() -> None:
    primary = build_primary_summary()
    ablation = build_ablation_summary()
    compact = build_compact_report(primary, ablation)
    (OUT_DIR / 'paper_results_summary.json').write_text(json.dumps({'primary': primary, 'ablation': ablation}, indent=2))
    (OUT_DIR / 'paper_results_compact.json').write_text(json.dumps(compact, indent=2))
    print('wrote', OUT_DIR / 'paper_results_summary.json')
    print('wrote', OUT_DIR / 'paper_results_compact.json')


if __name__ == '__main__':
    main()
