#!/usr/bin/env python3
"""Regenerate primary trajectory figures from cached trajectory CSV files."""

from __future__ import annotations

import argparse
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import MultipleLocator

plt.rcParams.update(
    {
        "font.size": 7,
        "axes.labelsize": 6.5,
        "axes.titlesize": 7.5,
        "xtick.labelsize": 6,
        "ytick.labelsize": 6,
        "legend.fontsize": 7,
        "axes.linewidth": 0.6,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    }
)

TARGET_ORDER = [
    ("LightFTP", "lightftp"),
    ("bftpd", "bftpd"),
    ("ProFTPD", "proftpd"),
    ("Pure-FTPd", "pure-ftpd"),
    ("Exim", "exim"),
    ("Live555", "live555"),
    ("Kamailio", "kamailio"),
    ("Forked-daapd", "forked-daapd"),
    ("Lighttpd1", "lighttpd1"),
]

FUZZER_ORDER = ["aflnet", "chatafl", "loopfuzz"]
FUZZER_LABEL = {
    "aflnet": "AFLNet",
    "chatafl": "ChatAFL",
    "loopfuzz": "LoopFuzz",
}

COLORS = {
    "aflnet": "#1f77b4",
    "chatafl": "#ff7f0e",
    "loopfuzz": "#d62728",
}

LINESTYLES = {
    "aflnet": "-",
    "chatafl": "--",
    "loopfuzz": "-.",
}

MARKERS = {
    "aflnet": "o",
    "chatafl": "s",
    "loopfuzz": "^",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--figures-dir", type=Path, default=Path("figures"))
    return parser.parse_args()


def style_axes(ax: plt.Axes, title: str, ylabel: str) -> None:
    ax.set_title(title, pad=4)
    ax.set_xlabel("Time (min)", labelpad=1.0)
    ax.set_ylabel(ylabel, labelpad=1.0)
    ax.set_xlim(0, 1440)
    ax.set_xticks([0, 720, 1440])
    ax.grid(True, color="#D9D9D9", linewidth=0.45, alpha=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="both", width=0.6, length=2.5, pad=1.0)


def nice_tick_step(raw_step: float) -> float:
    if raw_step <= 0 or not math.isfinite(raw_step):
        return 1.0
    exponent = math.floor(math.log10(raw_step))
    fraction = raw_step / (10**exponent)
    for nice in (1, 2, 2.5, 5, 10):
        if fraction <= nice:
            return nice * (10**exponent)
    return 10 * (10**exponent)


def set_post_initial_y_axis(ax: plt.Axes, trajectory: pd.DataFrame) -> None:
    y_values = trajectory.loc[trajectory["elapsed_min"] > 0, "value"]
    if y_values.empty:
        y_values = trajectory["value"]
    y_min = float(y_values.min())
    y_max = float(y_values.max())
    span = y_max - y_min
    if span <= 0:
        span = max(abs(y_max) * 0.05, 1.0)
        y_min -= span
        y_max += span
    major_step = nice_tick_step(span / 4.0)
    pad = max(major_step * 0.35, span * 0.04)
    ax.set_ylim(y_min - pad, y_max + pad)
    ax.yaxis.set_major_locator(MultipleLocator(major_step))
    ax.yaxis.set_minor_locator(MultipleLocator(major_step / 2.0))
    ax.grid(True, which="minor", axis="y", color="#ECECEC", linewidth=0.3, alpha=0.7)


def add_series(ax: plt.Axes, trajectory: pd.DataFrame) -> None:
    for fuzzer in FUZZER_ORDER:
        series = trajectory[trajectory["fuzzer"] == fuzzer].sort_values("elapsed_min")
        if series.empty:
            continue
        ax.plot(
            series["elapsed_min"],
            series["value"],
            color=COLORS[fuzzer],
            linestyle=LINESTYLES[fuzzer],
            marker=MARKERS[fuzzer],
            markevery=max(1, len(series) // 6),
            markersize=2.4,
            linewidth=1.25,
            label=FUZZER_LABEL[fuzzer],
        )


def filter_cached_csv(trajectory_csv: Path) -> None:
    lines = trajectory_csv.read_text().splitlines()
    filtered = [
        line
        for line in lines
        if not line.startswith("mosquitto,") and not line.startswith("Mosquitto,")
    ]
    trajectory_csv.write_text("\n".join(filtered) + "\n")


def plot_grid(trajectory_csv: Path, metric: str, out_dir: Path) -> None:
    filter_cached_csv(trajectory_csv)
    all_trajectories = pd.read_csv(trajectory_csv)

    filename = (
        "primary_branch_coverage_curve"
        if metric == "branch"
        else "primary_edge_exploration_curve"
    )
    ylabel = r"Branch coverage ($b\_abs$)" if metric == "branch" else "IPSM edges"

    fig, axes = plt.subplots(3, 3, figsize=(8.1, 6.5), constrained_layout=True)
    axes_flat = axes.flatten()

    for ax, (target_label, subject) in zip(axes_flat, TARGET_ORDER):
        sub = all_trajectories[all_trajectories["subject"] == subject]
        add_series(ax, sub)
        style_axes(ax, target_label, ylabel)
        set_post_initial_y_axis(ax, sub)

    handles, labels = axes_flat[0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper center",
        ncol=3,
        frameon=False,
        bbox_to_anchor=(0.5, 1.025),
        handlelength=2.0,
    )

    for ext in ["pdf", "svg", "png"]:
        kwargs = {"bbox_inches": "tight"}
        if ext == "png":
            kwargs["dpi"] = 300
        fig.savefig(out_dir / f"{filename}.{ext}", **kwargs)
    plt.close(fig)


def main() -> None:
    args = parse_args()
    plot_grid(args.figures_dir / "primary_branch_coverage_trajectory.csv", "branch", args.figures_dir)
    plot_grid(args.figures_dir / "primary_edge_exploration_trajectory.csv", "edge", args.figures_dir)


if __name__ == "__main__":
    main()
