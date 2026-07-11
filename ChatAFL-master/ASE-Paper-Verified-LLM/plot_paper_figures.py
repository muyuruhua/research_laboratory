from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

PAPER_DIR = Path(__file__).resolve().parent
FIGURES_DIR = PAPER_DIR / 'figures'
DATA_ROOT = Path('/home/ckt/Documents/000_2026_test_dev/experiment_data/ten groups data (ten)')

FUZZER_ORDER = ['aflnet', 'chatafl', 'loopfuzz']
FUZZER_LABELS = {
    'aflnet': 'AFLNet',
    'chatafl': 'ChatAFL',
    'loopfuzz': 'LoopFuzz',
}
FUZZER_COLORS = {
    'aflnet': '#1f77b4',
    'chatafl': '#ff7f0e',
    'loopfuzz': '#d62728',
}
FUZZER_STYLES = {
    'aflnet': '-',
    'chatafl': '--',
    'loopfuzz': '-.',
}
FUZZER_MARKERS = {
    'aflnet': 'o',
    'chatafl': 's',
    'loopfuzz': '^',
}

TARGETS = [
    ('LightFTP', 'lightftp'),
    ('bftpd', 'bftpd'),
    ('ProFTPD', 'proftpd'),
    ('Pure-FTPd', 'pure-ftpd'),
    ('Exim', 'exim'),
    ('Live555', 'live555'),
    ('Kamailio', 'kamailio'),
    ('Forked-daapd', 'forked-daapd'),
    ('Lighttpd1', 'lighttpd1'),
    ('Mosquitto*', 'mosquitto'),
]


def style_axis(axis, title, ylabel):
    axis.set_title(title, fontsize=10, pad=6)
    axis.set_xlabel('Time (min)', fontsize=9)
    axis.set_ylabel(ylabel, fontsize=9)
    axis.tick_params(axis='both', labelsize=8)
    axis.grid(True, alpha=0.25, linewidth=0.6)


def add_series(axis, dataframe, time_column, value_column):
    for fuzzer in FUZZER_ORDER:
        series = dataframe[dataframe['fuzzer'] == fuzzer]
        if series.empty:
            continue
        axis.plot(
            series[time_column],
            series[value_column],
            label=FUZZER_LABELS[fuzzer],
            color=FUZZER_COLORS[fuzzer],
            linestyle=FUZZER_STYLES[fuzzer],
            marker=FUZZER_MARKERS[fuzzer],
            markevery=max(1, len(series) // 8),
            markersize=3.5,
            linewidth=1.8,
        )


def create_figure_grid():
    figure, axes = plt.subplots(3, 4, figsize=(11.6, 8.2), constrained_layout=True)
    return figure, axes.flatten()


def build_mean_series(dataframe, value_column, step_minutes=60):
    rows = []
    for fuzzer in FUZZER_ORDER:
        fuzzer_df = dataframe[dataframe['fuzzer'] == fuzzer]
        if fuzzer_df.empty:
            continue
        for minute in range(0, 1441, step_minutes):
            values = []
            for run in sorted(fuzzer_df['run'].unique()):
                run_df = fuzzer_df[fuzzer_df['run'] == run].sort_values('elapsed_min')
                clipped = run_df[run_df['elapsed_min'] <= minute]
                if clipped.empty:
                    continue
                values.append(float(clipped.iloc[-1][value_column]))
            if values:
                rows.append({'fuzzer': fuzzer, 'elapsed_min': minute, 'value': sum(values) / len(values)})
    return pd.DataFrame(rows)


def generate_state_figure():
    figure, axes = create_figure_grid()
    for axis, (title, subject) in zip(axes, TARGETS):
        state_path = DATA_ROOT / f'results-{subject}_Mar-16_23-10-02_ten' / 'states.csv'
        dataframe = pd.read_csv(state_path)
        dataframe = dataframe[(dataframe['subject'] == subject) & (dataframe['state_type'] == 'edges')].copy()
        dataframe['elapsed_min'] = dataframe.groupby(['fuzzer', 'run'])['time'].transform(lambda s: (s - s.min()) / 60.0)
        mean_df = build_mean_series(dataframe, 'state')
        add_series(axis, mean_df, 'elapsed_min', 'value')
        style_axis(axis, title, 'IPSM edges')
    for axis in axes[len(TARGETS):]:
        axis.axis('off')
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(handles, labels, loc='upper center', ncol=3, frameon=False, bbox_to_anchor=(0.5, 1.08), fontsize=9)
    figure.savefig(FIGURES_DIR / 'state_coverage.pdf', bbox_inches='tight')
    plt.close(figure)


def generate_edge_figure():
    figure, axes = create_figure_grid()
    for axis, (title, subject) in zip(axes, TARGETS):
        coverage_path = DATA_ROOT / f'results-{subject}_Mar-16_23-10-02_ten' / 'results.csv'
        dataframe = pd.read_csv(coverage_path)
        dataframe = dataframe[(dataframe['subject'] == subject) & (dataframe['cov_type'] == 'b_abs')].copy()
        dataframe['elapsed_min'] = dataframe.groupby(['fuzzer', 'run'])['time'].transform(lambda s: (s - s.min()) / 60.0)
        mean_df = build_mean_series(dataframe, 'cov')
        add_series(axis, mean_df, 'elapsed_min', 'value')
        style_axis(axis, title, 'Code-edge coverage')
    for axis in axes[len(TARGETS):]:
        axis.axis('off')
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(handles, labels, loc='upper center', ncol=3, frameon=False, bbox_to_anchor=(0.5, 1.02), fontsize=9)
    figure.savefig(FIGURES_DIR / 'edge_coverage.pdf', bbox_inches='tight')
    plt.close(figure)


if __name__ == '__main__':
    generate_state_figure()
    generate_edge_figure()
