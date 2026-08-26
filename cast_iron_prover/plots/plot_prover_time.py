#!/usr/bin/env python3
"""Plot prover time vs ballot count with one line per simulated_blockchain_leaves (log scale)."""
import csv
import sys
from collections import defaultdict
import matplotlib
import matplotlib.pyplot as plt
import numpy as np

# ── Wong (2011) colorblind-safe palette ──────────────────────────────────────
WONG_PALETTE = [
    "#E69F00",  # orange
    "#56B4E9",  # sky blue
    "#009E73",  # bluish green
    "#F0E442",  # yellow
    "#0072B2",  # blue
    "#D55E00",  # vermillion
    "#CC79A7",  # reddish purple
    "#000000",  # black
]

# Marker styles to add a second visual channel (useful for B&W printing too)
MARKERS = ["o", "s", "^", "D", "v", "P", "X", "*"]


def read_csv(path):
    by_key = defaultdict(list)
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            leaves  = int(row["simulated_blockchain_leaves"])
            ballots = int(row["ballots"])
            secs    = float(row["proof_time_seconds"])
            # optional column: 1 = extrapolated value (see predict_missing.py)
            pred    = str(row.get("predicted", "0") or "0").strip() == "1"
            by_key[(ballots, leaves, pred)].append(secs)

    agg = {}
    for (b, l, p), times in by_key.items():
        agg[(b, l, p)] = (np.mean(times), np.std(times) if len(times) > 1 else 0.0)

    by_leaves = defaultdict(lambda: ([], [], [], []))
    for (ballots, leaves, pred), (mean_s, std_s) in agg.items():
        by_leaves[leaves][0].append(ballots)
        by_leaves[leaves][1].append(mean_s)
        by_leaves[leaves][2].append(std_s)
        by_leaves[leaves][3].append(pred)

    result = {}
    for leaves in sorted(by_leaves.keys()):
        ballots, means, stds, preds = by_leaves[leaves]
        order = np.argsort(ballots)
        result[leaves] = (
            [ballots[i] for i in order],
            [means[i]   for i in order],
            [stds[i]    for i in order],
            [preds[i]   for i in order],
        )
    return result


def make_label(leaves):
    if leaves == -1:
        return "MACI"
    exp = int(round(np.log2(leaves)))
    return rf"Cast Iron ($\ell=2^{{{exp}}}$)"


def main():
    csv_path = "plots/prover_time_total.csv"
    png_path = "plots/prover_time_total.png"
    if len(sys.argv) >= 2:
        csv_path = sys.argv[1]
    if len(sys.argv) >= 3:
        png_path = sys.argv[2]

    by_leaves = read_csv(csv_path)
    if not by_leaves:
        raise SystemExit("no data to plot")

    # ── Use LaTeX-quality fonts (Computer Modern) without requiring a full LaTeX install
    matplotlib.rcParams.update({
        "text.usetex":        False,         # set True if LaTeX is installed for exact CM fonts
        "font.family":        "serif",
        "font.serif":         ["DejaVu Serif", "Times New Roman", "Times"],
        "mathtext.fontset":   "cm",
        "axes.titlesize":     14,
        "axes.labelsize":     14,
        "xtick.labelsize":    12,
        "ytick.labelsize":    12,
        "legend.fontsize":    11,
        "legend.framealpha":  0.92,
        "legend.edgecolor":   "0.6",
        "lines.linewidth":    2.2,
        "lines.markersize":   7,
        "grid.linewidth":     0.6,
        "grid.alpha":         0.55,
        "figure.dpi":         150,
    })

    fig, ax = plt.subplots(figsize=(6.5, 4.5))   # ~column width for two-column IEEE/ACM

    leaves_sorted = sorted(by_leaves.keys())
    n_curves = len(leaves_sorted)

    for i, leaves in enumerate(leaves_sorted):
        xs, ys, yerrs, _preds = by_leaves[leaves]   # predicted points are drawn like measured ones
        color    = WONG_PALETTE[i % len(WONG_PALETTE)]
        marker   = MARKERS[i % len(MARKERS)]
        label    = make_label(leaves)

        # MACI: dashed + no fill marker; Cast Iron: solid
        if leaves == -1:
            ax.plot(xs, ys, color=color, linewidth=2.4,
                    linestyle="--", marker=marker,
                    markerfacecolor="white", markeredgewidth=1.8,
                    markersize=7, label=label, zorder=3)
        else:
            ax.plot(xs, ys, color=color, linewidth=2.2,
                    linestyle="-", marker=marker,
                    markersize=6.5, label=label, zorder=3)

    ax.set_xlabel("Number of ballots")
    ax.set_ylabel("Prover time (seconds)")
    ax.set_xscale("log")
    ax.set_yscale("log")

    ax.grid(True, which="major", linestyle="-",  linewidth=0.6, alpha=0.45)
    ax.grid(True, which="minor", linestyle=":",  linewidth=0.4, alpha=0.30)

    # Legend: put MACI first, then Cast Iron lines sorted by leaves
    handles, labels = ax.get_legend_handles_labels()
    # MACI (-1) was inserted at its sorted position; just sort so MACI is first
    pairs = sorted(zip(labels, handles),
                   key=lambda x: (-1 if x[0] == "MACI" else 0))
    labels_s, handles_s = zip(*pairs)
    ax.legend(handles_s, labels_s, loc="upper left",
              handlelength=2.4, handletextpad=0.5, borderpad=0.7)

    all_xs = [x for xs, _, _, _ in by_leaves.values() for x in xs]
    all_ys = [y for _, ys, _, _ in by_leaves.values() for y in ys]
    if all_xs and all_ys:
        ax.set_xlim(min(all_xs) * 0.85, max(all_xs) * 1.15)
        ax.set_ylim(min(all_ys) * 0.75, max(all_ys) * 1.35)

    fig.tight_layout(pad=0.5)
    fig.savefig(png_path, dpi=300, bbox_inches="tight")

    # Also save a PDF for direct inclusion in LaTeX
    pdf_path = png_path.replace(".png", ".pdf")
    fig.savefig(pdf_path, bbox_inches="tight")

    print(f"wrote {png_path}")
    print(f"wrote {pdf_path}")


if __name__ == "__main__":
    main()