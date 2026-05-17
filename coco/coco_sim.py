"""CoCo simulation: paper figures."""

import csv
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import norm

os.makedirs("figures", exist_ok=True)

from coco import VotingSystemConfig, compute_coco


# ── Helpers ───────────────────────────────────────────────────────────────────

def _enforce_monotone(y):
    return np.maximum.accumulate(y.astype(float))


def _filter_outliers(ratio, factor=5.0):
    """Replace spikes that jump >factor× the running monotone value with the
    previous valid value, then return the cleaned array.

    This catches isolated optimizer failures without blurring the curve.
    """
    out = ratio.astype(float).copy()
    running = 1.0
    for i in range(len(out)):
        r = out[i]
        if np.isfinite(r) and r > factor * max(running, 1.0):
            out[i] = running  # replace with last good value
        else:
            if np.isfinite(r):
                running = max(running, r)
    return out


def _power_law_weights(n, alpha, total=None):
    """Weights w_i ∝ i^{-alpha}, normalised to sum=total (default n)."""
    raw = np.array([i ** -alpha for i in range(1, n + 1)])
    total = float(n) if total is None else total
    return list(raw * total / raw.sum())


def _whale_weights(n, top_frac):
    """1 dominant voter with top_frac share, remaining n-1 voters equal."""
    w = np.full(n, (1.0 - top_frac) / (n - 1))
    w[0] = top_frac
    return list(w * n)


def _multi_whale_weights(n, n_whales, whale_frac=0.10):
    """n_whales voters each with whale_frac of total weight, rest equal."""
    rest_frac = (1.0 - n_whales * whale_frac) / (n - n_whales)
    w = np.full(n, rest_frac)
    w[:n_whales] = whale_frac
    return list(w * n)


# ── Paper figure (main, single panel) ────────────────────────────────────────

# Colorblind-safe protocol palette (Wong palette)
_VA_COLOR   = "#009E73"   # Revoting        — bluish green
_VA2_COLOR  = "#56B4E9"   # Revoting adv.   — sky blue
_LOKI_COLOR = "#E07820"   # Loki            — orange
_DET_COLOR  = "#CC79A7"   # Cast Iron       — reddish purple


def _figure_paper_panel(weights, util_dists, fname):
    """Single-panel paper figure, y-axis normalised by NCR cost."""
    p_vals = np.linspace(0.005, 0.995, 30)

    cfg_ncr   = VotingSystemConfig(weights=weights, epsilon=0.0, p_c=1.0, p_d=1.0,
                                   util_dists=util_dists)
    ncr_vals  = compute_coco(cfg_ncr, p_vals)
    ncr_valid = np.isfinite(ncr_vals) & (ncr_vals > 1e-9)

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, linestyle="--", alpha=0.4)

    def _plot_ratio(cfg, color, linestyle, linewidth, label):
        vals   = compute_coco(cfg, p_vals)
        finite = np.isfinite(vals)
        valid  = finite & ncr_valid
        if not valid.any():
            return None, None
        ratio_raw = vals[valid] / ncr_vals[valid]
        ratio = np.maximum(1.0, _enforce_monotone(_filter_outliers(ratio_raw)))
        ax.plot(p_vals[valid], ratio, linestyle=linestyle, color=color,
                linewidth=linewidth, label=label)
        if not finite.all():
            ax.axvline(p_vals[finite][-1], color=color, linestyle=":", linewidth=1.5, alpha=0.7)
        return (p_vals[valid], ratio)

    va_data   = _plot_ratio(
        VotingSystemConfig(weights=weights, epsilon=0.5,  p_c=1.0, p_d=0.99,
                           util_dists=util_dists),
        _VA_COLOR, "solid", 2.5, "Revoting",
    )
    va2_data  = _plot_ratio(
        VotingSystemConfig(weights=weights, epsilon=0.7,  p_c=1.0, p_d=0.99,
                           util_dists=util_dists),
        _VA2_COLOR, "solid", 2.5, "Revoting (voter adv.)",
    )
    loki_data = _plot_ratio(
        VotingSystemConfig(weights=weights, epsilon=0.80, p_c=1.0, p_d=0.96,
                           util_dists=util_dists),
        _LOKI_COLOR, "solid", 2.5, "Loki",
    )

    p_c_det, p_d_det = 1.0, 0.96
    ratio_det = 1.0 / (p_c_det - p_d_det)
    if ncr_valid.any():
        ax.plot(p_vals[ncr_valid], np.full(ncr_valid.sum(), ratio_det),
                linestyle="solid", color=_DET_COLOR, linewidth=2.5, label="Cast Iron")

    ann_kw = dict(fontsize=14, clip_on=False)
    if va_data is not None:
        px, ry = va_data
        i = np.searchsorted(px, 0.99)
        ax.annotate("success=50%,\ndetection=1%", xy=(px[i], ry[i]),
                    xytext=(10, 0), textcoords="offset points",
                    color=_VA_COLOR, va="bottom", ha="left", **ann_kw)
    if va2_data is not None:
        px, ry = va2_data
        i = np.searchsorted(px, 0.99)
        ax.annotate("success=70%,\ndetection=1%", xy=(px[i], ry[i]),
                    xytext=(10, 0), textcoords="offset points",
                    color=_VA2_COLOR, va="center", ha="left", **ann_kw)
    if loki_data is not None:
        px, ry = loki_data
        i = np.searchsorted(px, 0.30)
        ax.annotate("success=80%,\ndetection=4%", xy=(px[i], ry[i]),
                    xytext=(0, 30), textcoords="offset points",
                    color=_LOKI_COLOR, va="bottom", ha="left", **ann_kw)
    if ncr_valid.any():
        i = np.searchsorted(p_vals[ncr_valid], 0.20)
        ax.annotate("success=100%, detection=4%",
                    xy=(p_vals[ncr_valid][i], ratio_det),
                    xytext=(0, 15), textcoords="offset points",
                    color=_DET_COLOR, va="top", ha="left", **ann_kw)

    ax.set_xlabel("Target win probability $p$", fontsize=18)
    ax.set_ylabel(r"$\overline{\mathsf{CoCo}}(p)$", fontsize=16)
    ax.tick_params(labelsize=14)
    ax.legend(fontsize=14, loc="upper left", framealpha=0.9)
    ax.set_xlim(0, 1)
    ylo, yhi = ax.get_ylim()
    ax.set_ylim(max(0, ylo), yhi * 1.4)
    _, yhi_final = ax.get_ylim()
    major_ticks = [1] + list(range(5, int(yhi_final) + 5, 5))
    ax.set_yticks([t for t in major_ticks if t <= yhi_final])
    fig.tight_layout()
    fig.savefig(fname, dpi=200, bbox_inches="tight")
    fig.savefig(fname.rsplit(".", 1)[0] + ".pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"  → {fname}")
    print(f"  → {fname.rsplit('.', 1)[0]}.pdf")

    # ── CSV export ────────────────────────────────────────────────────────────
    csv_fname = fname.rsplit(".", 1)[0] + ".csv"
    p_common      = p_vals[ncr_valid]
    cast_iron_row = np.full(len(p_common), ratio_det)

    curve_data = {"revoting": va_data, "revoting_adv": va2_data, "loki": loki_data}
    aligned = {}
    for col, data in curve_data.items():
        if data is None:
            aligned[col] = np.full(len(p_common), np.nan)
        else:
            px, ry = data
            arr = np.full(len(p_common), np.nan)
            for j, pv in enumerate(p_common):
                idx = np.searchsorted(px, pv)
                if idx < len(px) and np.isclose(px[idx], pv):
                    arr[j] = ry[idx]
            aligned[col] = arr

    with open(csv_fname, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["p", "ncr_ratio", "revoting_ratio",
                         "revoting_adv_ratio", "loki_ratio", "cast_iron_ratio"])
        for j, pv in enumerate(p_common):
            writer.writerow([
                f"{pv:.6f}", "1.000000",
                f"{aligned['revoting'][j]:.6f}"     if np.isfinite(aligned['revoting'][j])     else "",
                f"{aligned['revoting_adv'][j]:.6f}" if np.isfinite(aligned['revoting_adv'][j]) else "",
                f"{aligned['loki'][j]:.6f}"          if np.isfinite(aligned['loki'][j])          else "",
                f"{cast_iron_row[j]:.6f}",
            ])
    print(f"  → {csv_fname}")


def figure_paper():
    """Paper figure: equal weights, 25% pro-yes, n=100."""
    print("Paper figure …")
    n = 100
    _figure_paper_panel(
        [1.0] * n,
        [norm(loc=-1, scale=1)] * (n // 4) + [norm(loc=1, scale=1)] * (n - n // 4),
        "figures/figure_paper.png",
    )


# ── Sensitivity figure (2×2) ─────────────────────────────────────────────────

_SENSITIVITY_P_VALS = np.linspace(0.005, 0.995, 20)

_CAST_IRON_RATIO = 1.0 / (1.0 - 0.96)   # = 25, analytical

# Sensitivity figure: color = protocol, linestyle = sweep value.
_PROTO_COLORS = {
    "Revoting":      _VA_COLOR,
    "Revoting adv.": _VA2_COLOR,
    "Loki":          _LOKI_COLOR,
    "Cast Iron":     _DET_COLOR,
}
# Non-solid styles for non-baseline sweep values; baseline always gets solid.
_SWEEP_LINESTYLES = ["dashed", "dashdot", "dotted"]


def _compute_paper_curves(weights, util_dists, p_vals=None):
    """Return normalised CoCo curves for all four protocols.

    Returns dict: label → (p_valid, ratio, ratio_raw). Cast Iron is analytical
    (flat at 1/(p_c−p_d)). Optimizer failures are removed via _filter_outliers.
    """
    if p_vals is None:
        p_vals = _SENSITIVITY_P_VALS

    cfg_ncr   = VotingSystemConfig(weights=weights, epsilon=0.0, p_c=1.0, p_d=1.0,
                                   util_dists=util_dists)
    ncr_vals  = compute_coco(cfg_ncr, p_vals)
    ncr_valid = np.isfinite(ncr_vals) & (ncr_vals > 1e-9)

    protocol_cfgs = [
        ("Revoting",
         VotingSystemConfig(weights=weights, epsilon=0.5,  p_c=1.0, p_d=0.99,
                            util_dists=util_dists)),
        ("Revoting adv.",
         VotingSystemConfig(weights=weights, epsilon=0.7,  p_c=1.0, p_d=0.99,
                            util_dists=util_dists)),
        ("Loki",
         VotingSystemConfig(weights=weights, epsilon=0.80, p_c=1.0, p_d=0.96,
                            util_dists=util_dists)),
    ]

    curves = {}
    for label, cfg in protocol_cfgs:
        print(f"      {label} …", flush=True)
        vals   = compute_coco(cfg, p_vals)
        finite = np.isfinite(vals)
        valid  = finite & ncr_valid
        if not valid.any():
            curves[label] = None
            continue
        ratio_raw = vals[valid] / ncr_vals[valid]
        ratio = np.maximum(1.0, _enforce_monotone(_filter_outliers(ratio_raw)))
        curves[label] = (p_vals[valid], ratio, ratio_raw)

    # Cast Iron: analytical flat line — no extra compute_coco call needed
    if ncr_valid.any():
        flat = np.full(ncr_valid.sum(), _CAST_IRON_RATIO)
        curves["Cast Iron"] = (p_vals[ncr_valid], flat, flat)

    return curves


# ── Sensitivity data cache (CSV) ──────────────────────────────────────────────

def _save_sensitivity_data(all_data, path):
    """Persist all_data to CSV: panel, sweep_label, protocol, p, ratio, ratio_raw."""
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["panel", "sweep_label", "protocol", "p", "ratio", "ratio_raw"])
        for panel, panel_data in all_data.items():
            for sweep_label, curves in panel_data.items():
                for prot, data in curves.items():
                    if data is None:
                        continue
                    px, ry, ry_raw = data
                    for pv, rv, rv_raw in zip(px, ry, ry_raw):
                        writer.writerow([panel, sweep_label, prot,
                                         f"{pv:.6f}", f"{rv:.6f}", f"{rv_raw:.6f}"])


def _load_sensitivity_data(path):
    """Load sensitivity CSV into nested dict: panel → sweep_label → protocol → (p, ratio, ratio_raw)."""
    rows: dict = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            key = (row["panel"], row["sweep_label"], row["protocol"])
            rows.setdefault(key, ([], [], []))
            rows[key][0].append(float(row["p"]))
            rows[key][1].append(float(row["ratio"]))
            rows[key][2].append(float(row.get("ratio_raw", row["ratio"])))
    all_data: dict = {}
    for (panel, sweep_label, prot), (ps, rs, rs_raw) in rows.items():
        all_data.setdefault(panel, {}).setdefault(sweep_label, {})[prot] = (
            np.array(ps), np.array(rs), np.array(rs_raw))
    return all_data


# ── Sensitivity panel plot ────────────────────────────────────────────────────

def _plot_sweep_panel(ax, panel_data, sweep_labels, title, baseline=None):
    """Plot pre-computed normalised-CoCo sweep on ax.

    Colour = protocol (_PROTO_COLORS); linestyle = sweep value.
    Baseline sweep value gets solid lines at reduced opacity as a common reference;
    other sweep values get dashed/dashdot/dotted at full opacity.
    Per-panel legend shows sweep values as linestyle swatches.
    """
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, linestyle="--", alpha=0.4)

    non_baseline = [lbl for lbl in sweep_labels if lbl != baseline]
    ls_alpha = {}
    if baseline:
        ls_alpha[baseline] = ("solid", 0.55)
    for lbl, ls in zip(non_baseline, _SWEEP_LINESTYLES):
        ls_alpha[lbl] = (ls, 1.0)

    for lbl in sweep_labels:
        ls, alpha = ls_alpha.get(lbl, ("solid", 1.0))
        curves = panel_data.get(lbl, {})
        for prot, data in curves.items():
            if data is None:
                continue
            px, ry, *_ = data
            ax.plot(px, ry, color=_PROTO_COLORS[prot], linestyle=ls,
                    linewidth=1.8, alpha=alpha)

    # Legend: baseline first (solid, reduced alpha), then non-baseline in order
    legend_order = ([baseline] if baseline and baseline in sweep_labels else []) + non_baseline
    sweep_handles = [
        plt.Line2D([0], [0], color="black", linestyle=ls_alpha[lbl][0],
                   alpha=ls_alpha[lbl][1], linewidth=2.0, label=lbl)
        for lbl in legend_order
    ]
    ax.legend(handles=sweep_handles, fontsize=13, loc="upper left", framealpha=0.9)
    ax.set_title(title, fontsize=15)
    ax.set_xlim(0, 1)
    ax.set_xlabel("Target win probability $p$", fontsize=16)
    ax.set_ylabel(r"$\overline{\mathsf{CoCo}}(p)$", fontsize=16)
    ax.tick_params(labelsize=14)
    ylo, yhi = ax.get_ylim()
    ax.set_ylim(max(0, ylo), yhi * 1.2)


# ── Sensitivity figure ────────────────────────────────────────────────────────

def figure_paper_sensitivity(recompute=False):
    """2×2 sensitivity figure: sweeps of n, pro-no fraction, utility σ, weights.

    Baseline: n=100, 75% pro-no, σ=1, equal weights (matches figure_paper).
    Colour = protocol; opacity = sweep value. Shared protocol legend at bottom.
    Computed data is cached to CSV; set recompute=True to force fresh computation.
    """
    print("Paper sensitivity figure …")

    base_n       = 100
    base_frac_no = 0.75
    base_scale   = 1.0
    p_vals       = _SENSITIVITY_P_VALS
    cache_path   = "figures/figure_paper_sensitivity_data.csv"

    def make_dists(n, frac_no, scale):
        n_no = round(n * frac_no)
        return ([norm(loc=-1, scale=scale)] * (n - n_no)
                + [norm(loc=1,  scale=scale)] * n_no)

    # ── Sweep specifications ──────────────────────────────────────────────────
    n_vals    = [50, 100, 300]
    n_systems = [([1.0] * n, make_dists(n, base_frac_no, base_scale)) for n in n_vals]
    n_labels  = [f"n = {n}" for n in n_vals]

    frac_vals    = [0.60, 0.75, 0.80]
    frac_systems = [([1.0] * base_n, make_dists(base_n, f, base_scale)) for f in frac_vals]
    frac_labels  = [f"{int(f*100)}% pro-no" for f in frac_vals]

    scale_vals    = [0.5, 1.0, 1.5]
    scale_systems = [([1.0] * base_n, make_dists(base_n, base_frac_no, s)) for s in scale_vals]
    scale_labels  = [f"σ = {s}" for s in scale_vals]

    wt_variants = [
        ("equal",          [1.0] * base_n),
        ("1 × 10% whale",  _multi_whale_weights(base_n, 1)),
        ("3 × 10% whales", _multi_whale_weights(base_n, 3)),
    ]
    wt_systems = [(w, make_dists(base_n, base_frac_no, base_scale)) for _, w in wt_variants]
    wt_labels  = [lbl for lbl, _ in wt_variants]

    panels_spec = [
        ("Number of voters",       n_systems,     n_labels,    "n = 100"),
        ("Opposing voter fraction", frac_systems,  frac_labels, "75% pro-no"),
        ("Utility stddev σ",         scale_systems, scale_labels,"σ = 1.0"),
        ("Weight distribution",     wt_systems,    wt_labels,   "equal"),
    ]

    # ── Compute or load data ──────────────────────────────────────────────────
    if not recompute and os.path.exists(cache_path):
        print(f"  Loading cached data from {cache_path} …", flush=True)
        all_data = _load_sensitivity_data(cache_path)
    else:
        all_data = {}
        for title, systems, labels, _ in panels_spec:
            print(f"  Panel: {title}", flush=True)
            panel_data = {}
            for (weights, util_dists), lbl in zip(systems, labels):
                print(f"    {lbl} …", flush=True)
                panel_data[lbl] = _compute_paper_curves(weights, util_dists, p_vals)
            all_data[title] = panel_data
        _save_sensitivity_data(all_data, cache_path)
        print(f"  → {cache_path}")

    # ── Plot ──────────────────────────────────────────────────────────────────
    fig, axes = plt.subplots(2, 2, figsize=(13, 9))
    for ax, (title, _, labels, baseline) in zip(axes.flat, panels_spec):
        _plot_sweep_panel(ax, all_data[title], labels, title, baseline=baseline)

    proto_handles = [
        plt.Line2D([0], [0], color=_PROTO_COLORS[lbl], label=lbl, linewidth=2.0, linestyle="solid")
        for lbl in _PROTO_COLORS
    ]
    fig.legend(handles=proto_handles, loc="lower center", ncol=4,
               fontsize=13, framealpha=0.9, bbox_to_anchor=(0.5, 0.0))

    fig.tight_layout(rect=[0, 0.07, 1, 1])
    fig.savefig("figures/figure_paper_sensitivity.png", dpi=200, bbox_inches="tight")
    fig.savefig("figures/figure_paper_sensitivity.pdf", bbox_inches="tight")
    plt.close(fig)
    print("  → figures/figure_paper_sensitivity.png")
    print("  → figures/figure_paper_sensitivity.pdf")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    figure_paper()
    figure_paper_sensitivity()
    print("Done.")
