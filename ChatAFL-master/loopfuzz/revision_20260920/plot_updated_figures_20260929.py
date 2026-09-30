#!/usr/bin/env python3
"""Reproduce publication figures from versioned numeric archive evidence.

PDF and SVG contain vector paths/text only. PNG files are inspection previews.
No extrapolation, synthetic runs, causal fits, or inferred CVE events are used.
"""
import csv
import gzip
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
import xml.etree.ElementTree as ET

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
import numpy as np

BASE = Path(__file__).resolve().parent
OUT = BASE / 'figures_updated_20260929'
TARGETS = ['lightftp', 'bftpd', 'proftpd', 'pure-ftpd', 'exim', 'live555', 'kamailio', 'forked-daapd', 'lighttpd1']
NAMES = dict(zip(TARGETS, ['LightFTP', 'bftpd', 'ProFTPD', 'Pure-FTPd', 'Exim', 'Live555', 'Kamailio', 'Forked-daapd', 'Lighttpd1']))
COLORS = dict(zip('ABCDE', ['#444444', '#0072B2', '#E69F00', '#009E73', '#CC79A7']))
STYLES = dict(zip('ABCDE', ['-', '--', '-.', '-', ':']))
MARKERS = dict(zip('ABCDE', ['o', 's', '^', 'D', 'o']))
LABELS = {'A': 'A: AFLNet', 'B': 'B: ChatAFL', 'C': 'C: direct', 'D': 'D: gated fixed', 'E': 'E: calibrated'}
SEED = 20260929
BOOTSTRAPS = 2000
BINS = np.linspace(0, 1, 11)
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 8,
    'axes.labelsize': 8, 'axes.titlesize': 8.5, 'xtick.labelsize': 7,
    'ytick.labelsize': 7, 'legend.fontsize': 7.5, 'axes.linewidth': .6,
    'lines.linewidth': 1.2, 'pdf.fonttype': 42, 'ps.fonttype': 42,
    'svg.fonttype': 'none', 'svg.hashsalt': 'loopfuzz-20260929',
    'savefig.dpi': 240, 'axes.spines.top': False, 'axes.spines.right': False})


def dump(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def save(fig, name):
    fig.savefig(OUT / (name + '.pdf'), bbox_inches='tight', pad_inches=.03,
                metadata={'CreationDate': None, 'ModDate': None})
    fig.savefig(OUT / (name + '.svg'), bbox_inches='tight', pad_inches=.03,
                metadata={'Date': None})
    preview = BASE / 'figure_checks_20260929'
    preview.mkdir(exist_ok=True)
    fig.savefig(preview / (name + '.png'), bbox_inches='tight', pad_inches=.03)
    assert not ET.parse(OUT / (name + '.svg')).findall('.//{http://www.w3.org/2000/svg}image')
    plt.close(fig)


def csvout(name, rows):
    assert rows
    with (OUT / name).open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def arm_legend(fig, arms, scatter=False, **kwargs):
    fig.legend([Line2D([], [], color=COLORS[a], linestyle='none' if scatter else STYLES[a], marker=MARKERS[a], markersize=4,
                        markerfacecolor='none' if scatter else COLORS[a])
                for a in arms], [LABELS[a] for a in arms], frameon=False, **kwargs)


def coverage(runs):
    grid = np.arange(289) / 12  # five-minute grid, hours since fuzzer start
    fig, axes = plt.subplots(3, 3, figsize=(7.2, 4.45))
    rows, audit = [], {}
    fig.subplots_adjust(left=.085, right=.99, top=.85, bottom=.09, wspace=.30, hspace=.72)
    arm_legend(fig, 'ABCDE', loc='upper center', bbox_to_anchor=(.52, .997), ncol=5,
               columnspacing=1.1, handlelength=2.2)
    for ti, (target, ax) in enumerate(zip(TARGETS, axes.flat)):
        n24 = []
        for arm in 'ABCDE':
            group = [r for r in runs if r['target'] == target and r['arm'] == arm]
            if not group:
                n24.append('–')
                continue
            series = []
            for r in group:
                c = np.array(r['coverage'], dtype=float)
                assert np.all(np.diff(c[:, 0]) > 0)
                vals = np.interp(grid, c[:, 0], c[:, 1], left=np.nan, right=np.nan)
                supported = (grid >= c[0, 0]) & (grid <= c[-1, 0])
                assert np.array_equal(np.isfinite(vals), supported)
                series.append(vals)
                audit[r['source_rel']] = {'first_hour': float(c[0, 0]), 'last_hour': float(c[-1, 0]),
                    'branch_decreases': int(np.sum(np.diff(c[:, 1]) < 0)),
                    'duplicate_timestamps': r['duplicate_timestamps'],
                    'endpoint_matches_summary': r['endpoint_matches_summary'],
                    'trajectory_terminal': float(c[-1,1]), 'summary_terminal': float(r['summary']['b_abs'])}
            matrix = np.array(series)
            n = np.sum(np.isfinite(matrix), axis=0)
            valid = n > 0
            q = np.full((3, len(grid)), np.nan)
            q[:, valid] = np.nanquantile(matrix[:, valid], [.25, .5, .75], axis=0)
            ax.plot(grid, q[1], color=COLORS[arm], linestyle=STYLES[arm], linewidth=1.25,
                    marker=MARKERS[arm], markevery=48, markersize=2.5)
            ax.fill_between(grid, q[0], q[2], color=COLORS[arm], alpha=.11, linewidth=0)
            n24.append(str(n[-1]))
            for j, hour in enumerate(grid):
                rows.append({'target': target, 'arm': arm, 'hour': hour, 'n_observed': int(n[j]),
                    'n_archives': len(group), 'N_nominal': 10,
                    'q25': q[0, j] if valid[j] else '', 'median': q[1, j] if valid[j] else '',
                    'q75': q[2, j] if valid[j] else ''})
        ax.set_title(f'({chr(97+ti)}) {NAMES[target]}', loc='left', pad=14)
        ax.text(0, 1.018, 'n at 24 h (A–E): ' + '/'.join(n24), transform=ax.transAxes, fontsize=7.0)
        ax.set_xlim(0, 24); ax.set_xticks([0, 6, 12, 18, 24])
        ax.grid(alpha=.18, linewidth=.5)
        ax.ticklabel_format(axis='y', style='plain', useOffset=False)
    fig.supylabel('Observed source-level code branches', x=.008, fontsize=9)
    fig.supxlabel('Elapsed fuzzer time (h)', y=.018, fontsize=9)
    csvout('coverage_trajectory_values.csv', rows)
    dump('coverage_audit.json', audit)
    save(fig, 'coverage_trajectories')
    return {'archives': len(audit), 'groups': len({(x['arm'], x['target']) for x in rows}),
            'grid_hours': [0, 24], 'interval_minutes': 5,
            'time_origin': 'fuzzer_stats.start_time (Unix seconds)',
            'interpolation': 'linear, within observed first/last timestamp only',
            'band': 'empirical 25th–75th percentile; not a confidence interval',
            'first_hour_range': [min(v['first_hour'] for v in audit.values()), max(v['first_hour'] for v in audit.values())],
            'last_hour_range': [min(v['last_hour'] for v in audit.values()), max(v['last_hour'] for v in audit.values())],
            'runs_with_branch_decreases': sum(v['branch_decreases'] > 0 for v in audit.values())}


def weighted_ap(y, p, weights):
    """Non-interpolated average precision; ties share a single threshold."""
    order = np.argsort(-p, kind='stable')
    y, p, w = y[order], p[order], weights[order]
    idx = np.r_[np.flatnonzero(np.diff(p)), len(p)-1]
    tp = np.cumsum(w*y)[idx]; total = np.cumsum(w)[idx]
    if tp[-1] <= 0:
        return float('nan')
    precision = np.divide(tp, total, out=np.zeros_like(tp, dtype=float), where=total > 0)
    return float(np.sum(np.diff(np.r_[0., tp]) * precision) / tp[-1])


def reliability(runs, fields):
    fig = plt.figure(figsize=(7.2, 6.15))
    outer = fig.add_gridspec(3, 3, left=.08, right=.985, top=.895, bottom=.085,
                             wspace=.31, hspace=.40)
    bins_rows, metrics, audits = [], [], []
    fig.text(.52, .989, 'Pre-update probability and observed proxy reward', ha='center', fontsize=9)
    for ti, target in enumerate(TARGETS):
        gs = outer[ti//3, ti%3].subgridspec(2, 1, height_ratios=[4, 1.4], hspace=.08)
        ax = fig.add_subplot(gs[0]); hist = fig.add_subplot(gs[1], sharex=ax)
        ax.set_title(f'({chr(97+ti)}) {NAMES[target]}', loc='left', pad=16)
        group = [r for r in runs if r['arm'] == 'E' and r['target'] == target]
        if not group:
            ax.axis('off'); hist.axis('off')
            ax.text(.5, .45, 'No E observations\nMetrics unavailable', ha='center', va='center', transform=ax.transAxes, color='#666666')
            continue
        probs, rewards, baseline, cluster = [], [], [], []
        diag = Counter(); run_counts = []
        for ri, r in enumerate(group):
            prev = {}; seen_ids = set(); successes = 0; seen = 0; accepted = 0
            previous_time = -math.inf
            for data in r['episode_data']:
                e = dict(zip(fields, data)); diag['logged'] += 1
                p, y, a, b = [e[k] for k in ['posterior_mean_before', 'reward', 'alpha_before', 'beta_before']]
                assert all(math.isfinite(float(x)) for x in [p, y, a, b])
                assert 0 <= p <= 1 and y in [0, 1] and a > 0 and b > 0
                assert math.isclose(p, a/(a+b), abs_tol=1e-10)
                assert y == int(e['new_code_edges'] > 0)
                assert e['episode_id'] not in seen_ids
                assert e['time_ms'] >= previous_time
                previous_time = e['time_ms']; seen_ids.add(e['episode_id'])
                assert math.isclose(e['alpha_after'], 1+.995*(a-1)+y, abs_tol=1e-9)
                assert math.isclose(e['beta_after'], 1+.995*(b-1)+1-y, abs_tol=1e-9)
                s = e['selected_state']
                if s in prev and max(abs(a-prev[s][0]), abs(b-prev[s][1])) > 1e-9:
                    diag['posterior_discontinuities'] += 1
                prev[s] = [e['alpha_after'], e['beta_after']]
                if e['mutations'] == 0:
                    diag['zero_mutation_excluded'] += 1
                    continue
                assert e['mutations'] > 0
                probs.append(p); rewards.append(y); cluster.append(ri)
                # Prequential pooled-within-run reference; no future reward used.
                baseline.append((1+successes)/(2+seen))
                successes += y; seen += 1; accepted += 1
            run_counts.append(accepted)
            assert accepted > 0
        p, y, base = np.array(probs), np.array(rewards), np.array(baseline)
        cl = np.array(cluster); n_runs = len(group)
        bi = np.minimum((p*10).astype(int), 9)
        counts = np.zeros((n_runs, 10)); ps = counts.copy(); ys = counts.copy()
        brier = np.zeros(n_runs); brier_base = np.zeros(n_runs)
        for ri in range(n_runs):
            m = cl == ri
            counts[ri] = np.bincount(bi[m], minlength=10)
            ps[ri] = np.bincount(bi[m], weights=p[m], minlength=10)
            ys[ri] = np.bincount(bi[m], weights=y[m], minlength=10)
            brier[ri] = np.sum((p[m]-y[m])**2)
            brier_base[ri] = np.sum((base[m]-y[m])**2)
        n = counts.sum(axis=0); valid = n > 0
        phat = np.divide(ps.sum(axis=0), n, out=np.full(10, np.nan), where=valid)
        freq = np.divide(ys.sum(axis=0), n, out=np.full(10, np.nan), where=valid)
        metric = {'target': target, 'n_runs': n_runs, 'N_nominal': 10, 'episodes': len(y),
                  'positive_rewards': int(y.sum()), 'prevalence': float(y.mean()),
                  'brier': float(brier.sum()/n.sum()), 'brier_prequential': float(brier_base.sum()/n.sum()),
                  'ece_10': float(np.sum(np.abs(ys.sum(axis=0)-ps.sum(axis=0)))/n.sum()),
                  'auprc_ap': weighted_ap(y, p, np.ones(len(y)))}
        rng = np.random.default_rng(SEED + ti)
        draws = rng.multinomial(n_runs, np.ones(n_runs)/n_runs, size=BOOTSTRAPS)
        bn = draws @ counts; by = draws @ ys; bp = draws @ ps
        with np.errstate(invalid='ignore', divide='ignore'):
            bf = by/bn
        bounds = np.full((2, 10), np.nan)
        contributing = np.sum(counts > 0, axis=0)
        for j in range(10):
            finite = np.isfinite(bf[:, j])
            if contributing[j] >= 2:
                bounds[:, j] = np.quantile(bf[finite, j], [.025, .975])
        boot_metrics = {'brier': (draws @ brier) / bn.sum(axis=1),
                        'brier_prequential': (draws @ brier_base) / bn.sum(axis=1),
                        'ece_10': np.sum(np.abs(by-bp), axis=1)/bn.sum(axis=1),
                        'auprc_ap': np.array([weighted_ap(y, p, d[cl]) for d in draws])}
        for name, vals in boot_metrics.items():
            finite = vals[np.isfinite(vals)]
            metric[name+'_lo'], metric[name+'_hi'] = [float(x) for x in np.quantile(finite, [.025, .975])]
            metric[name+'_valid_bootstraps'] = len(finite)
        metrics.append(metric)
        diag['included'] = len(y); diag['runs'] = n_runs; diag['positive_rewards'] = int(y.sum())
        audits.append({'target': target, **dict(diag), 'per_run_included': run_counts})
        ax.plot([0, 1], [0, 1], color='#777777', linestyle='--', linewidth=.7)
        for j in range(10):
            if not valid[j]:
                continue
            if np.isfinite(bounds[0, j]):
                ax.vlines(phat[j], bounds[0, j], bounds[1, j], color=COLORS['E'], linewidth=1.1)
            ax.plot(phat[j], freq[j], 'o', color=COLORS['E'], markersize=3.2)
        ax.set_title(f'({chr(97+ti)}) {NAMES[target]}', loc='left', pad=16)
        ax.text(0, 1.018, f'n={n_runs}; m={len(y):,}', transform=ax.transAxes, fontsize=7.0)
        ax.set(xlim=(0, 1), ylim=(-.035, 1.04), xticks=[0, .5, 1], yticks=[0, .5, 1])
        ax.tick_params(labelbottom=False); ax.grid(alpha=.15, linewidth=.4)
        hist.bar(BINS[:-1]+.05, n, width=.08, color=COLORS['E'], alpha=.55, linewidth=0)
        hist.set_ylim(0, max(n)*2.2); hist.set_yticks([]); hist.tick_params(axis='x', length=2, pad=1)
        for j in range(10):
            if n[j]: hist.text(j/10+.05, n[j]+max(n)*.04, str(int(n[j])), ha='center', va='bottom', fontsize=6.3, rotation=90)
            bins_rows.append({'target': target, 'bin_left': j/10, 'bin_right': (j+1)/10,
                'episodes': int(n[j]), 'contributing_runs': int(contributing[j]),
                'mean_prediction': float(phat[j]) if valid[j] else '',
                'observed_reward_rate': float(freq[j]) if valid[j] else '',
                'ci_low': float(bounds[0,j]) if math.isfinite(bounds[0,j]) else '',
                'ci_high': float(bounds[1,j]) if math.isfinite(bounds[1,j]) else ''})
    fig.supylabel('Observed proxy-reward frequency', x=.009, fontsize=9)
    fig.supxlabel('Pre-update probability (lower strips: episode counts by bin)', y=.017, fontsize=8.5)
    csvout('reliability_bins.csv', bins_rows); csvout('reliability_metrics.csv', metrics)
    dump('episode_audit.json', audits)
    save(fig, 'logged_reward_reliability')
    table = [r'% Generated logged-reward diagnostics, not fixed-energy source-branch outcomes.',
        r'\begin{table*}[t]', r'\centering\footnotesize',
        r'\caption{E-archive diagnostics for the logged coverage-save reward on positive-execution episodes. Values in brackets are percentile 95\% CIs from 2,000 bootstrap resamples of whole runs within each target. BS and ECE are lower-is-better; AUPRC uses non-interpolated AP. The prequential reference uses Beta(1,1)-smoothed past included rewards in the same run. These are descriptive diagnostics, not the fixed-energy code-branch metrics in Table~\ref{tab:mechanisms}.}',
        r'\label{tab:logged_calibration}', r'\begin{tabularx}{\textwidth}{l r r *{4}{>{\centering\arraybackslash}X}}',
        r'\toprule', r'Target & $n$ & Episodes & BS & Reference BS & ECE (10 bins) & AUPRC (AP) \\', r'\midrule']
    for target in TARGETS:
        matches = [m for m in metrics if m['target'] == target]
        if not matches:
            table.append(NAMES[target] + r' & \missing & \missing & \missing & \missing & \missing & \missing \\')
            continue
        m = matches[0]
        cells = [NAMES[target], str(m['n_runs']), f"{m['episodes']:,}"]
        for key in ['brier', 'brier_prequential', 'ece_10', 'auprc_ap']:
            cells.append(r'\shortstack{' + f'{m[key]:.3f}' + r'\\' + '{' + f'[{m[key+"_lo"]:.3f}, {m[key+"_hi"]:.3f}]' + '}}')
        table.append(' & '.join(cells) + r' \\')
    table += [r'\bottomrule', r'\end{tabularx}', r'\end{table*}']
    (OUT/'logged_calibration_table.tex').write_text('\n'.join(table)+'\n')
    return {'target_metrics': metrics, 'audit': audits, 'bootstrap_replicates': BOOTSTRAPS, 'seed': SEED,
        'weighting': 'episodes within target, resampling whole runs',
        'exclusions': 'mutations == 0; no fabricated completions; end-of-run episodes retained as logged',
        'note': 'No equal-energy or completion-status claim; 3 posterior discontinuities are reported, not silently repaired.'}


def dispositions(runs):
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.55))
    fig.subplots_adjust(left=.045, right=.985, top=.69, bottom=.22, wspace=.25)
    summary = []; bars = []
    for arm in 'CDE':
        group = [r for r in runs if r['arm'] == arm]
        c = sum(r['candidates'] for r in group); t = sum(r['trials'] for r in group)
        disp = Counter(); fail = Counter()
        for r in group:
            disp.update(r['dispositions']); fail.update(r['first_failed_logged_predicate'])
            assert not r['orphan_trials'] and not r['duplicate_candidate_ids'] and not r['duplicate_trial_ids']
        missing = sum(r['unmatched_candidates'] for r in group)
        assert t + missing == c
        assert disp.get('reject', 0)+disp.get('durable', 0) == t
        summary.append({'arm': arm, 'n_archives': len(group), 'candidates': c, 'trials': t,
            'reject': disp.get('reject', 0), 'durable': disp.get('durable', 0), 'unmatched': missing,
            'p_first_fail': fail.get('p_pass', 0), 'u_first_fail': fail.get('u_pass', 0),
            'r_first_fail': fail.get('r_pass', 0)})
    # Keys are normalized by the audited ledger; validate spelling before use.
    for row, arm in zip(summary, 'CDE'):
        group = [r for r in runs if r['arm'] == arm]
        allkeys = set(k for r in group for k in r['first_failed_logged_predicate'])
        assert allkeys <= {'p_pass', 'u_pass', 'r_pass', 'pass_all'}, allkeys
        assert sum(row[k] for k in ['p_first_fail','u_first_fail','r_first_fail']) <= row['trials']
    cats = [('durable', '#009E73', ''), ('reject', '#999999', ''), ('unmatched', '#E69F00', '')]
    for ai, row in enumerate(summary):
        left = 0
        for key, color, hatch in cats:
            width = 100*row[key]/row['candidates']
            axes[0].barh(ai, width, left=left, height=.55, color=color, hatch=hatch, edgecolor='white', linewidth=.3)
            left += width
        axes[0].text(0, ai-.39, f'{row["durable"]:,} durable; {row["reject"]:,} reject; {row["unmatched"]} unmatched', fontsize=6.3)
        passed = row['trials']-row['p_first_fail']-row['u_first_fail']-row['r_first_fail']
        row['pur_all_pass'] = passed
        axes[1].barh(ai, 100*row['u_first_fail']/row['trials'], color='#999999', height=.55)
        axes[1].barh(ai, 100*passed/row['trials'], left=100*row['u_first_fail']/row['trials'], color='#56B4E9', height=.55)
        axes[1].text(0, ai-.39, f'P/U/R: {row["p_first_fail"]}/{row["u_first_fail"]:,}/{row["r_first_fail"]}; all pass: {passed}', fontsize=6.3)
    for ax in axes:
        ax.set_xlim(0,100); ax.set_ylim(2.6,-.75)
        ax.set_yticks(range(3),list('CDE')); ax.set_xticks([0,25,50,75,100])
        ax.grid(axis='x',alpha=.15,linewidth=.5)
    axes[0].set_title('(a) Reported candidate dispositions',loc='left',pad=27)
    axes[0].set_xlabel('Share of candidate records (%)')
    axes[1].set_title('(b) First failed predicate (P → U → R)',loc='left',pad=27)
    axes[1].set_xlabel('Share of matched trials (%)')
    axes[0].legend([Patch(facecolor=c,edgecolor='white') for _,c,h in cats],
               ['Durable','Reject','Unmatched'],loc='lower center',ncol=3,frameon=False,
               bbox_to_anchor=(.5,1.0),fontsize=6.6,columnspacing=.8)
    axes[1].legend([Patch(facecolor='#999999'),Patch(facecolor='#56B4E9')],
                  ['U first fails','P/U/R all pass'],loc='lower center',bbox_to_anchor=(.5,1.00),
                  ncol=2,frameon=False,fontsize=6.3)
    csvout('candidate_disposition_values.csv',summary)
    save(fig,'candidate_dispositions')
    return summary


def costs(runs, key, name, xlabel):
    fig, axes = plt.subplots(3,3,figsize=(7.2,3.75))
    fig.subplots_adjust(left=.085,right=.99,top=.86,bottom=.12,wspace=.33,hspace=.88)
    arm_legend(fig,'BCDE',scatter=True,loc='upper center',bbox_to_anchor=(.52,.995),ncol=4,columnspacing=1.5)
    vals=[]
    for ti,(target,ax) in enumerate(zip(TARGETS,axes.flat)):
        counts=[]
        for arm in 'BCDE':
            n=0
            for r in runs:
                if (r['target'],r['arm']) != (target,arm): continue
                if key=='tokens':
                    if r['prompt_tokens'] is None or r['completion_tokens'] is None: continue
                    value=r['prompt_tokens']+r['completion_tokens']; x=value/1000
                else:
                    if r['model_calls'] is None: continue
                    value=r['model_calls']; x=value
                y=float(r['summary']['b_abs']); assert value>=0
                ax.scatter(x,y,s=15,marker=MARKERS[arm],facecolor='none',edgecolor=COLORS[arm],linewidth=.75,alpha=.8)
                n+=1
                vals.append({'source_rel':r['source_rel'],'target':target,'arm':arm,'usage':value,
                             'branches':y,'runtime_min':r['summary']['runtime_min']})
            counts.append(str(n) if n else '–')
        ax.set_title(f'({chr(97+ti)}) {NAMES[target]}',loc='left',pad=14)
        ax.text(0,1.018,'n (B–E): '+ '/'.join(counts),transform=ax.transAxes,fontsize=7.0)
        ax.ticklabel_format(style='plain',useOffset=False)
        ax.grid(alpha=.18,linewidth=.5)
        ax.xaxis.set_major_locator(plt.MaxNLocator(4))
        ax.yaxis.set_major_locator(plt.MaxNLocator(3))
    fig.supylabel('Terminal code branches',x=.009,fontsize=9)
    fig.supxlabel(xlabel,y=.018,fontsize=9)
    csvout(name+'_values.csv',vals)
    save(fig,name)
    return {'observations':len(vals),'units': 'tokens' if key=='tokens' else 'calls',
        'A': 'No saved comparable model counter; omitted, not imputed as zero',
        'interpretation':'Descriptive endpoints at unequal horizons; no cost-matched frontier or provider-billing claim.'}


def posterior_cases(runs, fields):
    targets=['forked-daapd','lighttpd1','lightftp']
    fig,axes=plt.subplots(2,3,figsize=(7.2,3.6),sharex='col')
    fig.subplots_adjust(left=.085,right=.99,top=.84,bottom=.12,wspace=.29,hspace=.42)
    fig.text(.52,.976,'Productivity estimates and scheduling multipliers: three E cases',ha='center',fontsize=9)
    fig.text(.52,.942,'Selection: lower-median terminal coverage run, then two most observed states',ha='center',fontsize=7.5)
    selected=[]; rows=[]
    for col,target in enumerate(targets):
        group=sorted([r for r in runs if r['arm']=='E' and r['target']==target],key=lambda r:(float(r['summary']['b_abs']),r['source_rel']))
        r=group[(len(group)-1)//2]
        events=[dict(zip(fields,e)) for e in r['episode_data']]
        counts=Counter(e['selected_state'] for e in events if e['mutations']>0)
        states=sorted(counts,key=lambda s:(-counts[s],s))[:2]
        selected.append({'target':target,'source_rel':r['source_rel'],'run':r['run'],
                         'branches':r['summary']['b_abs'],'states':states})
        for s,color,style in zip(states,['#0072B2','#D55E00'],['-','--']):
            ev=[e for e in events if e['selected_state']==s]
            t=np.array([(e['time_ms']/1000-r['fuzzer_start_time'])/3600 for e in ev])
            p=np.array([e['posterior_mean_before'] for e in ev])
            mult=np.array([e['final_selection_score']/e['frontier_score'] if e['frontier_score']>0 else np.nan for e in ev])
            axes[0,col].plot(t,p,color=color,linestyle=style,linewidth=.9,label=f'State {s}')
            axes[1,col].plot(t,mult,color=color,linestyle=style,linewidth=.65,alpha=.8)
            for hour,e,m in zip(t,ev,mult):
                rows.append({'source_rel':r['source_rel'],'target':target,'state':s,'episode_id':e['episode_id'],
                    'hour_episode_end':float(hour),'pre_update_probability':e['posterior_mean_before'],
                    'logged_reward':e['reward'],'mutations':e['mutations'],
                    'score_multiplier':float(m) if math.isfinite(m) else ''})
        axes[0,col].set_title(f'({chr(97+col)}) {NAMES[target]}: run {r["run"]}',loc='left')
        axes[0,col].legend(frameon=False,fontsize=6.5,loc='lower left')
        for ax in axes[:,col]:
            ax.set_ylim(-.03,1.05);ax.set_yticks([0,.5,1]);ax.set_xlim(0,26);ax.set_xticks([0,6,12,18,24]);ax.grid(alpha=.17,linewidth=.4)
    axes[0,0].set_ylabel('Pre-update probability')
    axes[1,0].set_ylabel('Final score / frontier score')
    fig.supxlabel('Elapsed fuzzer time at episode end (h)',y=.015,fontsize=9)
    csvout('posterior_case_values.csv',rows); dump('posterior_case_selection.json',selected)
    save(fig,'posterior_cases')
    return selected


def main():
    OUT.mkdir(exist_ok=True)
    path=BASE/'vector_figure_evidence_20260929.json.gz'
    with gzip.open(path,'rt') as f:data=json.load(f)
    runs=data['runs']
    assert len(runs)==465 and len({r['source_rel'] for r in runs})==465
    assert all(r['source_rel'].startswith('benchmark/') for r in runs if r['arm']=='D')
    assert sum(r['arm']=='E' and r['target']=='bftpd' for r in runs)==10
    # Metric edge cases independently validate weighting and tie conventions.
    assert math.isclose(weighted_ap(np.array([0,0,1,1]),np.array([.1,.4,.35,.8]),np.ones(4)),5/6)
    assert math.isclose(weighted_ap(np.array([0,1]),np.array([.5,.5]),np.ones(2)),.5)
    assert math.isnan(weighted_ap(np.array([0,0]),np.array([.2,.3]),np.ones(2)))
    report={'schema':1,'evidence_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'numpy':np.__version__,'matplotlib':matplotlib.__version__,'nominal_n':10}
    report['coverage']=coverage(runs);print('Coverage trajectories saved.',flush=True)
    report['reliability']=reliability(runs,data['episode_fields']);print('Reliability diagnostics saved.',flush=True)
    report['dispositions']=dispositions(runs);print('Candidate disposition saved.',flush=True)
    report['token_cost']=costs(runs,'tokens','token_cost_coverage','Reported prompt + completion tokens (thousands)')
    report['call_cost']=costs(runs,'calls','call_cost_coverage','Reported model calls')
    report['posterior_cases']=posterior_cases(runs,data['episode_fields'])
    dump('figure_analysis_report.json',report)
    print('All six figures saved as vector PDF/SVG plus PNG previews.',flush=True)

if __name__=='__main__':
    main()
    # Keep reviewed caption/cell wording after regenerating this snapshot.
    from refine_float_text import apply_edits as apply_float_copy_edits
    apply_float_copy_edits()
