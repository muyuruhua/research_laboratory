#!/usr/bin/env python3
"""Generate primary multi-panel trajectory figures from the selected archives."""

from __future__ import annotations

import argparse
import io
import tarfile
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
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

TRAJECTORY_TARGET_ORDER = TARGET_ORDER

FUZZER_ORDER = ["aflnet", "chatafl", "loopfuzz"]
FUZZER_LABEL = {
    "aflnet": "AFLNet",
    "chatafl": "Ctl. ChatAFL",
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
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path("/home/ckt/Documents/000_2026_test_dev/experiment_data/ten_groups_data_ten"),
        help="Directory containing results-*/run_summary.csv files.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/loopfuzz/figures"),
        help="Directory where generated figures and summaries are written.",
    )
    return parser.parse_args()


def selected_rows(df: pd.DataFrame, fuzzer: str) -> pd.DataFrame:
    mask = (df["fuzzer"] == fuzzer) & (df["runtime_min"] >= 1400)
    if "status" in df.columns:
        mask = mask & (df["status"] == "completed")
    rows = df[mask].copy()
    rows = rows.sort_values("run", kind="mergesort")
    if len(rows) > 10:
        rows = rows.head(10)
    return rows


def trajectory_rows(df: pd.DataFrame, fuzzer: str, subject: str) -> pd.DataFrame:
    return selected_rows(df, fuzzer)


def load_summary(data_root: Path) -> pd.DataFrame:
    records = []
    for target_label, subject in TARGET_ORDER:
        csv_path = data_root / f"results-{subject}_Mar-16_23-10-02_ten" / "run_summary.csv"
        if not csv_path.exists():
            raise FileNotFoundError(f"Missing run summary: {csv_path}")
        df = pd.read_csv(csv_path)
        for fuzzer in FUZZER_ORDER:
            rows = selected_rows(df, fuzzer)
            if rows.empty:
                raise ValueError(f"No selected rows for {subject}/{fuzzer}")
            for metric in ["b_abs", "edges"]:
                records.append(
                    {
                        "target": target_label,
                        "subject": subject,
                        "fuzzer": fuzzer,
                        "fuzzer_label": FUZZER_LABEL[fuzzer],
                        "metric": metric,
                        "runs": len(rows),
                        "mean": rows[metric].mean(),
                        "sd": rows[metric].std(ddof=1) if len(rows) > 1 else 0.0,
                    }
                )
    summary = pd.DataFrame.from_records(records)
    baseline = (
        summary[summary["fuzzer"] == "aflnet"]
        .loc[:, ["target", "metric", "mean"]]
        .rename(columns={"mean": "aflnet_mean"})
    )
    summary = summary.merge(baseline, on=["target", "metric"], how="left")
    summary["relative_mean"] = summary["mean"] / summary["aflnet_mean"]
    summary["relative_sd"] = summary["sd"] / summary["aflnet_mean"]
    return summary


def read_tar_member(tar_path: Path, suffix: str) -> bytes:
    with tarfile.open(tar_path, "r:gz") as archive:
        for member in archive.getmembers():
            if member.isfile() and member.name.endswith(suffix):
                extracted = archive.extractfile(member)
                if extracted is None:
                    break
                return extracted.read()
    raise FileNotFoundError(f"Missing {suffix} in {tar_path}")


def load_branch_trajectory(tar_path: Path) -> pd.DataFrame:
    raw = read_tar_member(tar_path, "/cov_over_time.csv")
    df = pd.read_csv(io.BytesIO(raw), usecols=["Time", "b_abs"])
    df = df.rename(columns={"Time": "unix_time", "b_abs": "value"})
    df["unix_time"] = pd.to_numeric(df["unix_time"], errors="coerce")
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    df = df.dropna(subset=["unix_time", "value"]).sort_values("unix_time")
    if df.empty:
        raise ValueError(f"No branch trajectory rows in {tar_path}")
    df["elapsed_min"] = (df["unix_time"] - df["unix_time"].iloc[0]) / 60.0
    return df.loc[:, ["elapsed_min", "value"]]


def load_edge_trajectory(tar_path: Path) -> pd.DataFrame:
    raw = read_tar_member(tar_path, "/plot_data")
    # AFL plot_data always stores unix_time at column 0 and n_edges at column 12.
    df = pd.read_csv(
        io.BytesIO(raw),
        comment="#",
        header=None,
        usecols=[0, 12],
        names=["unix_time", "value"],
    )
    df["unix_time"] = pd.to_numeric(df["unix_time"], errors="coerce")
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    df = df.dropna(subset=["unix_time", "value"]).sort_values("unix_time")
    if df.empty:
        raise ValueError(f"No edge trajectory rows in {tar_path}")
    df["elapsed_min"] = (df["unix_time"] - df["unix_time"].iloc[0]) / 60.0
    return df.loc[:, ["elapsed_min", "value"]]


def last_value_at(run_df: pd.DataFrame, minute: int) -> float | None:
    clipped = run_df[run_df["elapsed_min"] <= minute]
    if clipped.empty:
        return None
    return float(clipped.iloc[-1]["value"])


def build_mean_trajectory(
    data_root: Path, subject: str, metric: str, step_minutes: int = 60
) -> pd.DataFrame:
    csv_path = data_root / f"results-{subject}_Mar-16_23-10-02_ten" / "run_summary.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Missing run summary: {csv_path}")
    run_summary = pd.read_csv(csv_path)
    result_dir = csv_path.parent
    loader = load_branch_trajectory if metric == "branch" else load_edge_trajectory

    records = []
    for fuzzer in FUZZER_ORDER:
        selected = trajectory_rows(run_summary, fuzzer, subject)
        if selected.empty:
            continue

        runs = []
        for _, row in selected.iterrows():
            tar_path = result_dir / row["source"]
            run_df = loader(tar_path)
            run_df["run"] = int(row["run"])
            runs.append(run_df)

        for minute in range(0, 1441, step_minutes):
            values = [last_value_at(run_df, minute) for run_df in runs]
            values = [value for value in values if value is not None]
            if values:
                records.append(
                    {
                        "subject": subject,
                        "fuzzer": fuzzer,
                        "fuzzer_label": FUZZER_LABEL[fuzzer],
                        "elapsed_min": minute,
                        "value": float(np.mean(values)),
                        "runs": len(values),
                    }
                )
    return pd.DataFrame.from_records(records)


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


def plot_trajectory_grid(
    all_trajectories: pd.DataFrame, metric: str, out_dir: Path
) -> None:
    filename = (
        "primary_branch_coverage_curve"
        if metric == "branch"
        else "primary_edge_exploration_curve"
    )
    ylabel = "Absolute branch coverage" if metric == "branch" else "IPSM edges"

    fig, axes = plt.subplots(3, 4, figsize=(9.2, 6.5), constrained_layout=True)
    axes_flat = axes.flatten()

    for ax, (target_label, subject) in zip(axes_flat, TRAJECTORY_TARGET_ORDER):
        sub = all_trajectories[all_trajectories["subject"] == subject]
        add_series(ax, sub)
        style_axes(ax, target_label, ylabel)

    for ax in axes_flat[len(TRAJECTORY_TARGET_ORDER) :]:
        ax.axis("off")

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
    args.out_dir.mkdir(parents=True, exist_ok=True)
    summary = load_summary(args.data_root)
    summary.to_csv(args.out_dir / "primary_curve_summary.csv", index=False)
    for metric, csv_name in [
        ("branch", "primary_branch_coverage_trajectory.csv"),
        ("edge", "primary_edge_exploration_trajectory.csv"),
    ]:
        trajectories = []
        for _, subject in TRAJECTORY_TARGET_ORDER:
            trajectories.append(build_mean_trajectory(args.data_root, subject, metric))
        all_trajectories = pd.concat(trajectories, ignore_index=True)
        all_trajectories.to_csv(args.out_dir / csv_name, index=False)
        plot_trajectory_grid(all_trajectories, metric, args.out_dir)
    print(summary.pivot_table(index=["target", "fuzzer_label"], columns="metric", values="mean"))


if __name__ == "__main__":
    main()
