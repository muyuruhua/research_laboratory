#!/usr/bin/env python3
"""
严谨分析消融实验数据：
1. 统计每个协议、每个消融项的run数量
2. 检查run_summary.csv中的重复记录（基于start_time/last_update, edges, b_abs）
3. 去重后计算b_abs和edges的均值
4. 与ablation_full进行对比
"""

import os
import csv
import glob
from collections import defaultdict

BASE_DIR = "/home/ckt/Documents/000_2026_test_dev/experiment_data/ten_groups_ablation_ten"

ABLATION_TYPES = [
    "_ablation_full_",
    "_ablation_wo_adaptive_",
    "_ablation_wo_frontier_",
    "_ablation_wo_hypothesis_",
    "_ablation_wo_refinement_",
]

def parse_dirname(dirname):
    """Extract protocol and ablation type from directory name."""
    # Format: results-<protocol>_ablation_<type>_<timestamp>
    # Remove 'results-' prefix
    rest = dirname.replace("results-", "", 1)

    for ab_type in ABLATION_TYPES:
        if ab_type in rest:
            protocol = rest.split(ab_type)[0]
            return protocol, ab_type, rest

    return None, None, rest

def find_duplicates(rows):
    """
    Find duplicate runs based on (start_time, edges, b_abs) or (last_update, edges, b_abs).
    Two rows are considered duplicates if they have the SAME edges AND b_abs
    AND either same start_time or same last_update.
    """
    seen = {}  # (edges, b_abs, start_time) or (edges, b_abs, last_update) -> list of indices
    duplicates = []
    unique_indices = set()

    for i, row in enumerate(rows):
        edges = row.get('edges', '').strip()
        b_abs = row.get('b_abs', '').strip()
        start_time = row.get('start_time', '').strip()
        last_update = row.get('last_update', '').strip()

        key_st = (edges, b_abs, start_time)
        key_lu = (edges, b_abs, last_update)

        matched = False
        for key in [key_st, key_lu]:
            if key in seen:
                duplicates.append((i, seen[key], row, rows[seen[key]]))
                matched = True
                break

        if not matched:
            seen[key_st] = i
            seen[key_lu] = i
            unique_indices.add(i)

    return duplicates, unique_indices

def read_csv(filepath):
    """Read CSV and return list of dicts."""
    rows = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    except Exception as e:
        print(f"  ERROR reading {filepath}: {e}")
    return rows

def analyze():
    # Get all result directories
    all_dirs = sorted(glob.glob(os.path.join(BASE_DIR, "results-*")))

    # Group by protocol
    protocol_data = defaultdict(dict)  # protocol -> {ablation_type -> {rows, duplicates, ...}}

    print("=" * 120)
    print("消融实验数据严谨分析")
    print("=" * 120)

    for d in all_dirs:
        dirname = os.path.basename(d)
        protocol, ab_type, full_name = parse_dirname(dirname)

        if protocol is None:
            continue

        csv_path = os.path.join(d, "run_summary.csv")
        if not os.path.exists(csv_path):
            print(f"WARNING: {csv_path} does not exist!")
            continue

        rows = read_csv(csv_path)
        dup_pairs, unique_indices = find_duplicates(rows)

        protocol_data[protocol][ab_type] = {
            'rows': rows,
            'dup_pairs': dup_pairs,
            'unique_indices': unique_indices,
            'dirname': dirname,
        }

    # ============================================================
    # SECTION 1: 逐协议、逐消融项统计run数量和重复情况
    # ============================================================
    print("\n\n" + "=" * 120)
    print("第一部分：逐协议逐消融项 — Run数量与重复统计")
    print("=" * 120)

    all_protocols = sorted(protocol_data.keys())

    for protocol in all_protocols:
        print(f"\n{'─' * 100}")
        print(f"【协议: {protocol}】")
        print(f"{'─' * 100}")

        for ab_type in ABLATION_TYPES:
            if ab_type not in protocol_data[protocol]:
                print(f"  {ab_type}: 数据缺失!")
                continue

            data = protocol_data[protocol][ab_type]
            rows = data['rows']
            dup_pairs = data['dup_pairs']
            unique_indices = data['unique_indices']

            total_runs = len(rows)
            dup_count = len(dup_pairs)
            unique_count = len(unique_indices)

            print(f"\n  ▸ {ab_type}")
            print(f"    目录: {data['dirname']}")
            print(f"    总记录数: {total_runs}")
            print(f"    重复记录组数: {dup_count}")
            print(f"    去重后记录数: {unique_count}")

            if dup_pairs:
                print(f"    ⚠ 重复详情:")
                for dup_idx, orig_idx, dup_row, orig_row in dup_pairs:
                    print(f"      Run #{dup_row.get('run','?')} 与 Run #{orig_row.get('run','?')} 重复")
                    print(f"        edges={dup_row.get('edges','?')}, b_abs={dup_row.get('b_abs','?')}, "
                          f"start_time={dup_row.get('start_time','?')}, last_update={dup_row.get('last_update','?')}")

            # Compute means after dedup
            if unique_count > 0:
                unique_rows = [rows[i] for i in sorted(unique_indices)]
                b_abs_vals = []
                edges_vals = []
                for r in unique_rows:
                    try:
                        b_abs_vals.append(float(r.get('b_abs', 0)))
                        edges_vals.append(float(r.get('edges', 0)))
                    except (ValueError, TypeError):
                        pass

                mean_b_abs = sum(b_abs_vals) / len(b_abs_vals) if b_abs_vals else 0
                mean_edges = sum(edges_vals) / len(edges_vals) if edges_vals else 0
                print(f"    去重后 b_abs 均值: {mean_b_abs:.2f}")
                print(f"    去重后 edges 均值: {mean_edges:.2f}")
            else:
                mean_b_abs = 0
                mean_edges = 0

    # ============================================================
    # SECTION 2: 消融对比总表
    # ============================================================
    print("\n\n" + "=" * 120)
    print("第二部分：消融对比总表（去重后均值）")
    print("=" * 120)

    # Compute per-protocol ablation comparison
    print(f"\n{'协议':<22} {'指标':<10} {'full':<12} {'wo_adaptive':<14} {'wo_frontier':<14} {'wo_hypothesis':<14} {'wo_refinement':<14}")
    print("-" * 110)

    # Collect all data for summary
    summary_b_abs = {ab: [] for ab in ABLATION_TYPES}
    summary_edges = {ab: [] for ab in ABLATION_TYPES}

    for protocol in all_protocols:
        means = {}
        for ab_type in ABLATION_TYPES:
            if ab_type in protocol_data[protocol]:
                data = protocol_data[protocol][ab_type]
                rows = data['rows']
                unique_indices = data['unique_indices']
                unique_rows = [rows[i] for i in sorted(unique_indices)]

                b_abs_vals = []
                edges_vals = []
                for r in unique_rows:
                    try:
                        b_abs_vals.append(float(r.get('b_abs', 0)))
                        edges_vals.append(float(r.get('edges', 0)))
                    except (ValueError, TypeError):
                        pass

                if b_abs_vals:
                    means[ab_type] = {
                        'b_abs': sum(b_abs_vals) / len(b_abs_vals),
                        'edges': sum(edges_vals) / len(edges_vals),
                        'n': len(b_abs_vals),
                    }
                    summary_b_abs[ab_type].append(means[ab_type]['b_abs'])
                    summary_edges[ab_type].append(means[ab_type]['edges'])

        # Print b_abs row
        full_b = means.get('_ablation_full_', {}).get('b_abs', None)
        print(f"{protocol:<22} {'b_abs':<10}", end="")
        for ab_type in ABLATION_TYPES:
            v = means.get(ab_type, {}).get('b_abs', None)
            if v is not None:
                diff_str = ""
                if ab_type != "_ablation_full_" and full_b is not None:
                    diff = v - full_b
                    diff_str = f" ({diff:+.1f})"
                print(f" {v:<10.1f}{diff_str:<8}", end=" ")
            else:
                print(f" {'N/A':<18}", end=" ")
        print()

        # Print edges row
        full_e = means.get('_ablation_full_', {}).get('edges', None)
        print(f"{'':<22} {'edges':<10}", end="")
        for ab_type in ABLATION_TYPES:
            v = means.get(ab_type, {}).get('edges', None)
            if v is not None:
                diff_str = ""
                if ab_type != "_ablation_full_" and full_e is not None:
                    diff = v - full_e
                    diff_str = f" ({diff:+.1f})"
                print(f" {v:<10.1f}{diff_str:<8}", end=" ")
            else:
                print(f" {'N/A':<18}", end=" ")
        print()

        # Print run count row
        print(f"{'':<22} {'runs':<10}", end="")
        for ab_type in ABLATION_TYPES:
            n = means.get(ab_type, {}).get('n', None)
            if n is not None:
                print(f" n={n:<15}", end=" ")
            else:
                print(f" {'N/A':<18}", end=" ")
        print()
        print()

    # ============================================================
    # SECTION 3: 跨协议汇总
    # ============================================================
    print("\n" + "=" * 120)
    print("第三部分：跨协议汇总 — 各消融项平均 b_abs 和 edges（去重后）")
    print("=" * 120)

    print(f"\n{'消融项':<30} {'平均b_abs':<14} {'vs full Δ':<12} {'平均edges':<14} {'vs full Δ':<12} {'协议数':<8}")
    print("-" * 90)

    full_avg_b = sum(summary_b_abs['_ablation_full_']) / len(summary_b_abs['_ablation_full_']) if summary_b_abs['_ablation_full_'] else 0
    full_avg_e = sum(summary_edges['_ablation_full_']) / len(summary_edges['_ablation_full_']) if summary_edges['_ablation_full_'] else 0

    for ab_type in ABLATION_TYPES:
        b_vals = summary_b_abs[ab_type]
        e_vals = summary_edges[ab_type]

        if b_vals:
            avg_b = sum(b_vals) / len(b_vals)
            avg_e = sum(e_vals) / len(e_vals)
            delta_b = avg_b - full_avg_b
            delta_e = avg_e - full_avg_e
            print(f"{ab_type:<30} {avg_b:<14.2f} {delta_b:<+12.2f} {avg_e:<14.2f} {delta_e:<+12.2f} {len(b_vals):<8}")
        else:
            print(f"{ab_type:<30} {'N/A':<14} {'N/A':<12} {'N/A':<14} {'N/A':<12} {0:<8}")

    # ============================================================
    # SECTION 4: 逐协议消融对比（百分比变化）
    # ============================================================
    print("\n\n" + "=" * 120)
    print("第四部分：逐协议消融效应 — 与full相比的百分比变化")
    print("=" * 120)

    print(f"\n{'协议':<22} {'指标':<8} {'wo_adaptive':<16} {'wo_frontier':<16} {'wo_hypothesis':<16} {'wo_refinement':<16}")
    print("-" * 90)

    for protocol in all_protocols:
        data = protocol_data[protocol]
        full_data = data.get('_ablation_full_')
        if not full_data:
            continue

        # Compute full means
        full_rows = full_data['rows']
        full_unique = [full_rows[i] for i in sorted(full_data['unique_indices'])]
        full_b = sum(float(r['b_abs']) for r in full_unique) / len(full_unique)
        full_e = sum(float(r['edges']) for r in full_unique) / len(full_unique)

        for metric, metric_name in [('b_abs', 'b_abs'), ('edges', 'edges')]:
            print(f"{protocol:<22} {metric_name:<8}", end="")
            for ab_type in ['_ablation_wo_adaptive_', '_ablation_wo_frontier_',
                           '_ablation_wo_hypothesis_', '_ablation_wo_refinement_']:
                ab_data = data.get(ab_type)
                if ab_data:
                    ab_rows = ab_data['rows']
                    ab_unique = [ab_rows[i] for i in sorted(ab_data['unique_indices'])]
                    ab_val = sum(float(r[metric]) for r in ab_unique) / len(ab_unique)
                    full_val = full_b if metric == 'b_abs' else full_e
                    pct_change = ((ab_val - full_val) / full_val * 100) if full_val != 0 else 0
                    print(f" {pct_change:<+14.2f}%", end=" ")
                else:
                    print(f" {'N/A':<14}", end=" ")
            print()
        print()

    # ============================================================
    # SECTION 5: 重复记录汇总
    # ============================================================
    print("\n" + "=" * 120)
    print("第五部分：所有重复记录汇总")
    print("=" * 120)

    total_dups = 0
    for protocol in all_protocols:
        for ab_type in ABLATION_TYPES:
            if ab_type in protocol_data[protocol]:
                dup_pairs = protocol_data[protocol][ab_type]['dup_pairs']
                if dup_pairs:
                    total_dups += len(dup_pairs)
                    for dup_idx, orig_idx, dup_row, orig_row in dup_pairs:
                        print(f"  [{protocol}] {ab_type}: Run#{dup_row.get('run','?')} ⇄ Run#{orig_row.get('run','?')} "
                              f"(edges={dup_row.get('edges','?')}, b_abs={dup_row.get('b_abs','?')}, "
                              f"start_time={dup_row.get('start_time','?')})")

    if total_dups == 0:
        print("  ✓ 未发现任何重复记录！")
    else:
        print(f"\n  共发现 {total_dups} 组重复记录")

    print("\n" + "=" * 120)
    print("分析完成")
    print("=" * 120)

if __name__ == "__main__":
    analyze()
