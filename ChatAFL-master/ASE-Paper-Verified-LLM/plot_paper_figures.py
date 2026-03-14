from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
PAPER_DIR = Path(__file__).resolve().parent
FIGURES_DIR = PAPER_DIR / 'figures'

FUZZER_ORDER = ['aflnet', 'chatafl', 'chatafl_opt']
FUZZER_LABELS = {
    'aflnet': 'AFLNet',
    'chatafl': 'ChatAFL',
    'chatafl_opt': 'VeriSPFuzz',
}
FUZZER_COLORS = {
    'aflnet': '#1f77b4',
    'chatafl': '#ff7f0e',
    'chatafl_opt': '#d62728',
}
FUZZER_STYLES = {
    'aflnet': '-',
    'chatafl': '--',
    'chatafl_opt': '-.',
}
FUZZER_MARKERS = {
    'aflnet': 'o',
    'chatafl': 's',
    'chatafl_opt': '^',
}

TARGETS = [
    {
        'title': 'ProFTPD',
        'subject': 'proftpd',
        'mean_csv': ROOT / 'benchmark' / 'results-proftpd_Mar-12_00-39-29' / 'mean_plot_data.csv',
        'results_csv': ROOT / 'benchmark' / 'results-proftpd_Mar-12_00-39-29' / 'results.csv',
    },
    {
        'title': 'Exim',
        'subject': 'exim',
        'mean_csv': ROOT / 'benchmark' / 'results-exim_Mar-06_22-09-54' / 'mean_plot_data.csv',
        'results_csv': ROOT / 'benchmark' / 'results-exim_Mar-06_22-09-54' / 'results.csv',
    },
    {
        'title': 'Pure-FTPd',
        'subject': 'pure-ftpd',
        'mean_csv': ROOT / 'benchmark' / 'results-pure-ftpd_Mar-10_22-37-08' / 'mean_plot_data.csv',
        'results_csv': ROOT / 'benchmark' / 'results-pure-ftpd_Mar-10_22-37-08' / 'results.csv',
    },
    {
        'title': 'Kamailio',
        'subject': 'kamailio',
        'mean_csv': ROOT / 'benchmark' / 'results-kamailio_Mar-12_00-39-29' / 'mean_plot_data.csv',
        'results_csv': ROOT / 'benchmark' / 'results-kamailio_Mar-12_00-39-29' / 'results.csv',
    },
    {
        'title': 'Forked-daapd',
        'subject': 'forked-daapd',
        'mean_csv': ROOT / 'benchmark' / 'results-forked-daapd_Mar-08_14-28-15' / 'mean_plot_data.csv',
        'results_csv': ROOT / 'benchmark' / 'results-forked-daapd_Mar-08_14-28-15' / 'results.csv',
    },
    {
        'title': 'Mosquitto',
        'subject': 'mosquitto',
        'mean_csv': ROOT / 'benchmark' / 'results-mosquitto_Mar-10_22-37-08' / 'mean_plot_data.csv',
        'results_csv': ROOT / 'benchmark' / 'results-mosquitto_Mar-10_22-37-08' / 'results.csv',
    },
]

RESERVED_TARGET = 'Live555\nReserved'


def load_mean_data(target):
    dataframe = pd.read_csv(target['mean_csv'])
    return dataframe[dataframe['subject'] == target['subject']].copy()


def style_axis(axis, title, ylabel):
    axis.set_title(title, fontsize=10, pad=6)
    axis.set_xlabel('Time (min)', fontsize=9)
    axis.set_ylabel(ylabel, fontsize=9)
    axis.tick_params(axis='both', labelsize=8)
    axis.grid(True, alpha=0.25, linewidth=0.6)


def add_series(axis, dataframe, metric_column, metric_name):
    for fuzzer in FUZZER_ORDER:
        series = dataframe[(dataframe[metric_column] == metric_name) & (dataframe['fuzzer'] == fuzzer)]
        if series.empty:
            continue
        axis.plot(
            series['time'],
            series['data'],
            label=FUZZER_LABELS[fuzzer],
            color=FUZZER_COLORS[fuzzer],
            linestyle=FUZZER_STYLES[fuzzer],
            marker=FUZZER_MARKERS[fuzzer],
            markevery=max(1, len(series) // 8),
            markersize=3.5,
            linewidth=1.8,
        )


def create_figure_grid():
    figure, axes = plt.subplots(2, 4, figsize=(11.4, 5.8), constrained_layout=True)
    return figure, axes.flatten()


def generate_state_figure():
    figure, axes = create_figure_grid()
    for axis, target in zip(axes, TARGETS):
        dataframe = load_mean_data(target)
        add_series(axis, dataframe, 'data_type', 'edges')
        style_axis(axis, target['title'], 'State transitions')
    reserved_axis = axes[len(TARGETS)]
    reserved_axis.text(0.5, 0.55, RESERVED_TARGET, ha='center', va='center', fontsize=11, fontweight='bold')
    reserved_axis.set_xticks([])
    reserved_axis.set_yticks([])
    reserved_axis.set_frame_on(True)
    for axis in axes[len(TARGETS) + 1:]:
        axis.axis('off')
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(handles, labels, loc='upper center', ncol=3, frameon=False, bbox_to_anchor=(0.5, 1.08), fontsize=9)
    figure.savefig(FIGURES_DIR / 'state_coverage.pdf', bbox_inches='tight')
    plt.close(figure)


def generate_edge_figure():
    figure, axes = create_figure_grid()
    for axis, target in zip(axes, TARGETS):
        dataframe = pd.read_csv(target['results_csv'])
        dataframe = dataframe[(dataframe['subject'] == target['subject']) & (dataframe['cov_type'] == 'b_abs')]
        mean_rows = []
        for fuzzer in FUZZER_ORDER:
            fuzzer_df = dataframe[dataframe['fuzzer'] == fuzzer]
            if fuzzer_df.empty:
                continue
            mean_rows.append((target['subject'], fuzzer, 0, 0.0))
            for time in range(1, 1441, 60):
                coverage_total = 0.0
                run_count = 0
                for run in sorted(fuzzer_df['run'].unique()):
                    run_df = fuzzer_df[fuzzer_df['run'] == run]
                    start_time = run_df.iloc[0]['time']
                    clipped_df = run_df[run_df['time'] <= start_time + time * 60]
                    if clipped_df.empty:
                        continue
                    coverage_total += clipped_df.tail(1).iloc[0]['cov']
                    run_count += 1
                mean_rows.append((target['subject'], fuzzer, time, coverage_total / max(run_count, 1)))
        mean_df = pd.DataFrame(mean_rows, columns=['subject', 'fuzzer', 'time', 'data'])
        for fuzzer in FUZZER_ORDER:
            series = mean_df[mean_df['fuzzer'] == fuzzer]
            if series.empty:
                continue
            axis.plot(
                series['time'],
                series['data'],
                label=FUZZER_LABELS[fuzzer],
                color=FUZZER_COLORS[fuzzer],
                linestyle=FUZZER_STYLES[fuzzer],
                marker=FUZZER_MARKERS[fuzzer],
                markevery=max(1, len(series) // 8),
                markersize=3.5,
                linewidth=1.8,
            )
        style_axis(axis, target['title'], 'Code-edge coverage')
    reserved_axis = axes[len(TARGETS)]
    reserved_axis.text(0.5, 0.55, RESERVED_TARGET, ha='center', va='center', fontsize=11, fontweight='bold')
    reserved_axis.set_xticks([])
    reserved_axis.set_yticks([])
    reserved_axis.set_frame_on(True)
    for axis in axes[len(TARGETS) + 1:]:
        axis.axis('off')
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(handles, labels, loc='upper center', ncol=3, frameon=False, bbox_to_anchor=(0.5, 1.08), fontsize=9)
    figure.savefig(FIGURES_DIR / 'edge_coverage.pdf', bbox_inches='tight')
    plt.close(figure)


if __name__ == '__main__':
    generate_state_figure()
    generate_edge_figure()
