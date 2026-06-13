#!/usr/bin/env python3
"""Regenerate primary trajectory figures from cached trajectory CSV files."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd

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

FUZZER_ORDER = ["aflnet", "chatafl", "chatafl_opt"]
FUZZER_LABEL = {
    "aflnet": "AFLNet",
    "chatafl": "ChatAFL",
    "chatafl_opt": "LoopFuzz",
}

COLORS = {
    "aflnet": "#1f77b4",
    "chatafl": "#ff7f0e",
    "chatafl_opt": "#d62728",
}

LINESTYLES = {
    "aflnet": "-",
    "chatafl": "--",
    "chatafl_opt": "-.",
}

MARKERS = {
    "aflnet": "o",
    "chatafl": "s",
    "chatafl_opt": "^",
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
