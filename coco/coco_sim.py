"""CoCo simulation: systematic parameter sweeps."""

import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import norm

os.makedirs("figures", exist_ok=True)

from coco import (
    VotingSystemConfig, compute_coco, plot_coco_curves,
    linear_pivotality, sqrt_pivotality, quadratic_pivotality,
)
from coco.probability import winning_probability_clt, winning_probability_hybrid, dominant_voters

P_VALUES = np.linspace(0.01, 0.95, 20)
UTIL_DIST = norm(loc=1, scale=1)

# The three base mechanisms
BASE_MECHANISMS = [
    # (label, epsilon, p_c, p_d)
    ("NCR",       0.0, 1.0, 1.0),
    ("revote",    0.5, 1.0, 1.0),
    ("cast iron", 1.0, 0.3, 0.1),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _baseline_p(weights, util_dists):
    q0 = np.array([float(d.cdf(0)) for d in util_dists])
    threshold = sum(weights) / 2.0
    conditioned = dominant_voters(weights)
    return winning_probability_hybrid(q0, weights, threshold, conditioned)


def _compute_curves(weights, util_dists, mechanisms, pivotality_fn=None):
    curves = []
    for label, eps, p_c, p_d in mechanisms:
        kwargs = dict(weights=weights, epsilon=eps, p_c=p_c, p_d=p_d, util_dists=util_dists)
        if pivotality_fn is not None:
            kwargs["pivotality_fn"] = pivotality_fn
        cfg = VotingSystemConfig(**kwargs)
        vals = compute_coco(cfg, P_VALUES)
        curves.append((P_VALUES, vals, label))
    return curves


def _panel(ax, weights, util_dists, mechanisms, subtitle, pivotality_fn=None):
    curves = _compute_curves(weights, util_dists, mechanisms, pivotality_fn)
    plot_coco_curves(curves, ax=ax)
    bp = _baseline_p(weights, util_dists)
    ax.axvline(bp, color="black", linestyle=":", linewidth=1, alpha=0.5,
               label="no-bribe baseline")
    ax.legend(fontsize=7)
    ax.set_title(subtitle, fontsize=9)


def _power_law_weights(n, alpha, total=None):
    """Weights w_i ∝ i^{-alpha}, normalised to sum=total (default n)."""
    raw = np.array([i ** -alpha for i in range(1, n + 1)])
    total = float(n) if total is None else total
    return list(raw * total / raw.sum())


# ── Study 1: cast iron p_c − p_d ─────────────────────────────────────────────

def study_cast_iron_params():
    """Vary (p_c − p_d) for cast iron; NCR and revote as fixed references."""
    print("Study 1: cast iron p_c/p_d …")
    n, weights = 100, [1.0] * 100
    util_dists = [UTIL_DIST] * n

    variants = [
        (0.15, 0.10),   # diff = 0.05
        (0.20, 0.10),   # diff = 0.10
        (0.30, 0.10),   # diff = 0.20  — baseline
        (0.60, 0.10),   # diff = 0.50
    ]

    fig, axes = plt.subplots(2, 2, figsize=(12, 9))
    fig.suptitle(
        "Study 1: cast iron (ε=1) — varying payment differential p_c − p_d\n"
        "NCR and revote shown as references  [n=100 equal-weight voters]"
    )

    ncr_revote = BASE_MECHANISMS[:2]
    for ax, (p_c, p_d) in zip(axes.flat, variants):
        diff = p_c - p_d
        mechs = ncr_revote + [(f"cast iron (diff={diff:.2f})", 1.0, p_c, p_d)]
        _panel(ax, weights, util_dists, mechs, f"p_c={p_c}, p_d={p_d}  →  diff={diff:.2f}")

    fig.tight_layout()
    fig.savefig("figures/study1_cast_iron_params.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  → study1_cast_iron_params.png")


# ── Study 2: number of voters ─────────────────────────────────────────────────

def study_n_voters():
    """Vary number of equal-weight voters for all three mechanisms."""
    print("Study 2: number of voters …")

    voter_counts = [15, 50, 100, 1000]

    fig, axes = plt.subplots(2, 2, figsize=(12, 9))
    fig.suptitle("Study 2: varying number of equal-weight voters")

    for ax, n in zip(axes.flat, voter_counts):
        weights = [1.0] * n
        util_dists = [UTIL_DIST] * n
        _panel(ax, weights, util_dists, BASE_MECHANISMS, f"n = {n} voters")

    fig.tight_layout()
    fig.savefig("figures/study2_n_voters.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  → study2_n_voters.png")


# ── Study 3: weight distributions ────────────────────────────────────────────

def study_weight_distributions():
    """Vary weight concentration (power law) for all three mechanisms."""
    print("Study 3: weight distributions …")

    n = 100
    util_dists = [UTIL_DIST] * n

    variants = [
        ("equal",                     [1.0] * n),
        ("power law α=0.5",           _power_law_weights(n, 0.5)),
        ("power law α=1\n(harmonic)", _power_law_weights(n, 1.0)),
        ("power law α=2",             _power_law_weights(n, 2.0)),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(12, 9))
    fig.suptitle(
        "Study 3: varying weight concentration (n=100, total weight fixed)\n"
        "α=0 is equal; higher α concentrates weight on top voters"
    )

    for ax, (wlabel, weights) in zip(axes.flat, variants):
        w_arr = np.array(weights)
        max_share = w_arr.max() / w_arr.sum()
        subtitle = f"{wlabel}  (top voter: {max_share:.0%})"
        _panel(ax, weights, util_dists, BASE_MECHANISMS, subtitle)

    fig.tight_layout()
    fig.savefig("figures/study3_weight_distributions.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  → study3_weight_distributions.png")


# ── Study 4: revote epsilon sweep ────────────────────────────────────────────

def study_revote_epsilon():
    """Vary ε for the revote mechanism (p_c=p_d=1) from 0.5 to 1."""
    print("Study 4: revote epsilon sweep …")

    n, weights = 100, [1.0] * 100
    util_dists = [UTIL_DIST] * n

    curves = []
    cfg_ci = VotingSystemConfig(
        weights=weights, epsilon=1.0, p_c=0.6, p_d=0.1, util_dists=util_dists,
    )
    curves.append((P_VALUES, compute_coco(cfg_ci, P_VALUES), "cast iron (diff=0.5)"))

    for eps in [0.5, 0.6, 0.7, 0.8, 0.9, 1.0]:
        cfg = VotingSystemConfig(
            weights=weights, epsilon=eps, p_c=1.0, p_d=1.0, util_dists=util_dists,
        )
        curves.append((P_VALUES, compute_coco(cfg, P_VALUES), f"revote ε = {eps}"))

    fig, ax = plot_coco_curves(
        curves,
        title="Revote mechanism (p_c = p_d = 1): varying ε  [n=100]",
    )
    bp = _baseline_p(weights, util_dists)
    ax.axvline(bp, color="black", linestyle=":", linewidth=1, alpha=0.5,
               label="no-bribe baseline")
    ax.legend(fontsize=8)

    fig.savefig("figures/study4_revote_epsilon.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  → study4_revote_epsilon.png")


# ── Study 5: pivotality functions ────────────────────────────────────────────

def study_pivotality_fns():
    """Compare linear, sqrt, and quadratic pivotality for all three mechanisms."""
    print("Study 5: pivotality functions …")

    n, weights = 100, [1.0] * 100
    util_dists = [UTIL_DIST] * n

    # For equal weights w_i = W/n, the pivotality values are:
    #   linear:    phi = 2/n
    #   sqrt:      phi = 2/sqrt(n)
    #   quadratic: phi = (2/n)^2
    pivotality_variants = [
        ("linear  (φ = 2/n)",        linear_pivotality()),
        ("sqrt  (φ = 2/√n)",         sqrt_pivotality()),
        ("quadratic  (φ = (2/n)²)",  quadratic_pivotality()),
    ]

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    fig.suptitle(
        "Study 5: pivotality functions  [n=100 equal-weight voters]\n"
        "Higher φ → voter feels more pivotal → harder to bribe → higher CoCo"
    )

    for ax, (plabel, pfn) in zip(axes, pivotality_variants):
        phi_val = pfn(1.0, float(n))
        _panel(ax, weights, util_dists, BASE_MECHANISMS,
               f"{plabel}\n(φ = {phi_val:.4f})", pivotality_fn=pfn)

    fig.tight_layout()
    fig.savefig("figures/study5_pivotality_fns.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  → study5_pivotality_fns.png")


# ── Study 6: voter opposition ────────────────────────────────────────────────

def study_voter_opposition():
    """Mix pro-yes (loc=+1) and pro-no (loc=−1) voters; vary proportion and scale.

    Each voter draws u_no from either N(+1, σ) [pro-yes] or N(−1, σ) [pro-no].
    With zero bribe a pro-yes voter votes yes with prob Φ(1/σ) and a pro-no
    voter with prob Φ(−1/σ).  Varying the fraction f of pro-yes voters and the
    scale σ covers both the opposition level and preference certainty.
    """
    print("Study 6: voter opposition …")

    n, weights = 100, [1.0] * 100

    def mixed_dists(frac_no, sigma):
        """frac_no fraction get N(+1,σ) [pro-no], rest get N(−1,σ) [pro-yes]."""
        n_no = round(n * frac_no)
        return [norm(loc=-1, scale=sigma)] * (n - n_no) + [norm(loc=1, scale=sigma)] * n_no

    # 2x2: varying fraction of pro-no voters (σ=1 throughout)
    variants = [
        (0.5, 1.0, "50% pro-no"),
        (0.6, 1.0, "60% pro-no"),
        (0.7, 1.0, "70% pro-no"),
        (0.8, 1.0, "80% pro-no"),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(12, 9))
    fig.suptitle(
        "Study 6: voter opposition  [n=100 equal-weight voters]\n"
        "Pro-no: u_no ~ N(+1,1);  pro-yes: u_no ~ N(−1,1)"
    )

    for ax, (f_no, sig, subtitle) in zip(axes.flat, variants):
        util_dists = mixed_dists(f_no, sig)  # f_no is the loop variable
        _panel(ax, weights, util_dists, BASE_MECHANISMS, subtitle)

    fig.tight_layout()
    fig.savefig("figures/study6_voter_opposition.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  → study6_voter_opposition.png")


# ── Paper figure ─────────────────────────────────────────────────────────────

def _smooth_monotone(y, sigma=2.0):
    """Gaussian-smooth y then re-enforce monotonicity via cumulative max."""
    from scipy.ndimage import gaussian_filter1d
    smoothed = gaussian_filter1d(y.astype(float), sigma=sigma)
    return np.maximum.accumulate(smoothed)


def _enforce_monotone(y):
    """Enforce monotonicity without smoothing."""
    return np.maximum.accumulate(y.astype(float))


def _figure_paper_panel(weights, util_dists, fname):
    """Single-panel paper figure, y-axis normalised by NCR cost.

    All protocols use p_c=1 (adversary minimises capital requirements).
    Legend lines: NCR, VoteAgain, Loki (×3), Cast Iron.
    Cast Iron (γ=1) drawn as analytical flat line at 1/(α−β).
    """
    p_vals = np.linspace(0.005, 0.995, 30)

    # NCR baseline for normalisation
    cfg_ncr = VotingSystemConfig(
        weights=weights, epsilon=0.0, p_c=1.0, p_d=1.0, util_dists=util_dists,
    )
    ncr_vals = compute_coco(cfg_ncr, p_vals)
    ncr_valid = np.isfinite(ncr_vals) & (ncr_vals > 1e-9)

    from scipy.ndimage import gaussian_filter1d

    va_color   = "#009E73"           # VoteAgain — green
    loki_color = "#E07820"           # Loki — orange
    det_color  = "#CC79A7"           # Cast Iron — pink

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, linestyle="--", alpha=0.4)

    def _plot_ratio(cfg, color, linestyle, linewidth, label, smooth_sigma=0.0):
        """Compute and plot CoCo/NCR ratio; optionally apply light smoothing."""
        vals = compute_coco(cfg, p_vals)
        finite = np.isfinite(vals)
        valid = finite & ncr_valid
        if not valid.any():
            return None, None
        ratio = np.maximum(1.0, _enforce_monotone(vals[valid] / ncr_vals[valid]))
        if smooth_sigma > 0:
            ratio = np.maximum(1.0, _enforce_monotone(
                gaussian_filter1d(ratio, sigma=smooth_sigma)))
        line, = ax.plot(p_vals[valid], ratio, linestyle=linestyle, color=color,
                        linewidth=linewidth, label=label)
        if not finite.all():
            cutoff = p_vals[finite][-1]
            ax.axvline(cutoff, color=color, linestyle=":", linewidth=1.5, alpha=0.7)
            return line, (p_vals[valid], ratio)
        return line, (p_vals[valid], ratio)

    # ── Revoting: success=50%, detection=1% ───────────────────────────────────
    _, va_data = _plot_ratio(
        VotingSystemConfig(weights=weights, epsilon=0.5,
                           p_c=1.0, p_d=0.99, util_dists=util_dists),
        va_color, "solid", 2.5, "Revoting",
    )

    # ── Revoting boosted: success=70%, detection=1% ───────────────────────────
    _, va2_data = _plot_ratio(
        VotingSystemConfig(weights=weights, epsilon=0.7,
                           p_c=1.0, p_d=0.99, util_dists=util_dists),
        va_color, "dashed", 2.5, "Revoting (voter adv.)",
    )

    # ── Loki: success=80%, detection=4% ───────────────────────────────────────
    _, loki_data = _plot_ratio(
        VotingSystemConfig(weights=weights, epsilon=0.80,
                           p_c=1.0, p_d=0.96, util_dists=util_dists),
        loki_color, "solid", 2.5, "Loki", smooth_sigma=1.5,
    )

    # ── Cast Iron: success=100%, detection=4% — analytical flat ───────────────
    p_c_det, p_d_det = 1.0, 0.96
    ratio_det = 1.0 / (p_c_det - p_d_det)
    if ncr_valid.any():
        ax.plot(p_vals[ncr_valid], np.full(ncr_valid.sum(), ratio_det),
                linestyle="solid", color=det_color, linewidth=2.5,
                label="Cast Iron")

    # ── Curve annotations (parameters on the lines) ───────────────────────────
    ann_kw = dict(fontsize=14, clip_on=False)
    if va_data is not None:
        px, ry = va_data
        i = np.searchsorted(px, 0.99)
        ax.annotate("success=50%,\ndetection=1%", xy=(px[i], ry[i]),
                    xytext=(10, 0), textcoords="offset points",
                    color=va_color, va="bottom", ha="left", **ann_kw)
    if va2_data is not None:
        px, ry = va2_data
        i = np.searchsorted(px, 0.99)
        ax.annotate("success=70%,\ndetection=1%", xy=(px[i], ry[i]),
                    xytext=(10, 0), textcoords="offset points",
                    color=va_color, va="center", ha="left", **ann_kw)
    if loki_data is not None:
        px, ry = loki_data
        i = np.searchsorted(px, 0.30)
        ax.annotate("success=80%,\ndetection=4%", xy=(px[i], ry[i]),
                    xytext=(0, 30), textcoords="offset points",
                    color=loki_color, va="bottom", ha="left", **ann_kw)
    if ncr_valid.any():
        i = np.searchsorted(p_vals[ncr_valid], 0.20)
        ax.annotate("success=100%, detection=4%",
                    xy=(p_vals[ncr_valid][i], ratio_det),
                    xytext=(0, 15), textcoords="offset points",
                    color=det_color, va="top", ha="left", **ann_kw)

    ax.set_xlabel("Target win probability $p$", fontsize=18)
    ax.set_ylabel(r"$\overline{\mathsf{CoCo}}(p)$", fontsize=16)
    ax.tick_params(labelsize=14)
    ax.legend(fontsize=14, loc="upper left", framealpha=0.9)
    ax.set_xlim(0, 1)
    ylo, yhi = ax.get_ylim()
    ax.set_ylim(max(0, ylo), yhi * 1.25)
    # Fixed y-axis ticks: 1, 5, 10, 15, ...
    _, yhi_final = ax.get_ylim()
    major_ticks = [1] + list(range(5, int(yhi_final) + 5, 5))
    ax.set_yticks([t for t in major_ticks if t <= yhi_final])
    fig.tight_layout()
    fig.savefig(fname, dpi=200, bbox_inches="tight")
    fig.savefig(fname.rsplit(".", 1)[0] + ".pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"  → {fname}")
    print(f"  → {fname.rsplit('.', 1)[0]}.pdf")


def figure_paper():
    """Paper figure: equal weights, 25% pro-yes, n=100."""
    print("Paper figure …")
    n = 100
    _figure_paper_panel(
        [1.0] * n,
        [norm(loc=-1, scale=1)] * (n // 4) + [norm(loc=1, scale=1)] * (n - n // 4),
        "figures/figure_paper.png",
    )


# ── p_d sweep figure ─────────────────────────────────────────────────────────

def figure_pd_sweep():
    """Two-panel figure: effect of p_d on race-condition CoCo.

    Left panel:  γ=0.5.  Right panel: γ=0.75.
    Each panel shows NCR and cast-iron (α−β=0.1) as baselines, then
    race-condition curves for p_c=1 and p_d ∈ {0, 0.25, 0.5, 0.75, 1}.
    """
    print("p_d sweep figure …")
    n = 100
    weights   = [1.0] * n
    util_dists = [norm(loc=-1, scale=1)] * (n // 4) + [norm(loc=1, scale=1)] * (n - n // 4)
    p_vals = np.linspace(0.005, 0.995, 40)

    p_d_vals = [0.0, 0.25, 0.5, 0.75, 0.9, 0.95, 1.0]
    # Sequential blue colormap for p_d sweep
    cmap = plt.get_cmap("Blues")
    pd_colors = [cmap(0.35 + 0.55 * i / (len(p_d_vals) - 1)) for i in range(len(p_d_vals))]

    fig, axes = plt.subplots(1, 2, figsize=(14, 6), sharey=False)

    for ax, gamma in zip(axes, [0.5, 0.75]):
        # Baselines
        cfg_ncr = VotingSystemConfig(weights=weights, epsilon=0.0,
                                     p_c=1.0, p_d=1.0, util_dists=util_dists)
        vals = compute_coco(cfg_ncr, p_vals)
        finite = np.isfinite(vals)
        ax.plot(p_vals[finite], vals[finite], color="#000000",
                linestyle="solid", linewidth=1.8, label="NCR")

        cfg_ci = VotingSystemConfig(weights=weights, epsilon=1.0,
                                    p_c=0.2, p_d=0.1, util_dists=util_dists)
        vals = compute_coco(cfg_ci, p_vals)
        finite = np.isfinite(vals)
        ax.plot(p_vals[finite], vals[finite], color="#D55E00",
                linestyle="solid", linewidth=1.8,
                label=r"Detectable ($\alpha$−$\beta$=0.10)")

        # p_d sweep
        for p_d, color in zip(p_d_vals, pd_colors):
            cfg = VotingSystemConfig(weights=weights, epsilon=gamma,
                                     p_c=1.0, p_d=p_d, util_dists=util_dists)
            vals = compute_coco(cfg, p_vals)
            finite = np.isfinite(vals)
            if finite.any():
                ax.plot(p_vals[finite], vals[finite], color=color,
                        linestyle="dashed", linewidth=1.6,
                        label=fr"Race $\gamma$={gamma}, $\beta$={p_d}")
                if not finite.all():
                    ax.axvline(p_vals[finite][-1], color=color,
                               linestyle=":", linewidth=1.1, alpha=0.7)

        ax.set_title(fr"Race condition $\gamma$={gamma}", fontsize=12)
        ax.set_xlabel("Target win probability $p$", fontsize=12)
        ax.set_ylabel("CoCo (total bribe)", fontsize=12)
        ax.tick_params(labelsize=10)
        ax.legend(fontsize=9)
        ax.set_xlim(0, 1)
        ylo, yhi = ax.get_ylim()
        ax.set_ylim(ylo, yhi * 1.2)

    fig.tight_layout()
    fig.savefig("figures/figure_pd_sweep.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("  → figure_pd_sweep.png")


# ── Study 7: gamma sweep at fixed α−β ────────────────────────────────────────

def study_gamma_sweep():
    """Vary γ (0.8, 0.9, 0.95) at four fixed α−β levels (0.10, 0.05, 0.03, 0.01).

    p_c=1 throughout (adversary minimises capital requirements).
    Y-axis normalised by NCR cost.  Voter setup matches paper figure.
    """
    print("Study 7: gamma sweep …")
    n = 100
    weights    = [1.0] * n
    util_dists = [norm(loc=-1, scale=1)] * (n // 4) + [norm(loc=1, scale=1)] * (n - n // 4)
    p_vals     = np.linspace(0.005, 0.995, 30)

    gammas    = [0.80, 0.90, 0.95]
    ab_levels = [0.10, 0.05, 0.03, 0.01]
    gamma_colors = ["#F5C242", "#E07820", "#A83000"]

    # NCR baseline for normalisation
    cfg_ncr = VotingSystemConfig(
        weights=weights, epsilon=0.0, p_c=1.0, p_d=1.0, util_dists=util_dists,
    )
    ncr_vals  = compute_coco(cfg_ncr, p_vals)
    ncr_valid = np.isfinite(ncr_vals) & (ncr_vals > 1e-9)

    fig, axes = plt.subplots(2, 2, figsize=(12, 9), sharey=False)
    fig.suptitle(
        r"Study 7: $\gamma$ sweep at fixed $\alpha{-}\beta$  "
        r"[$n$=100, 25% pro-yes, $p_c$=1]",
        fontsize=13,
    )

    for ax, ab in zip(axes.flat, ab_levels):
        ax.set_axisbelow(True)
        ax.yaxis.grid(True, linestyle="--", alpha=0.4)

        # NCR reference
        ax.axhline(1.0, color="#000000", linestyle="solid", linewidth=2.0,
                   alpha=0.4, label=r"NCR")

        # Cast Iron analytical flat at 1/(α−β)
        det_color = "#CC79A7"
        ax.axhline(1.0 / ab, color=det_color, linestyle="solid", linewidth=2.0,
                   alpha=0.7, label=fr"Cast Iron ($\gamma$=1, $1/(\alpha{{-}}\beta)$={1/ab:.0f})")

        for gamma, color in zip(gammas, gamma_colors):
            p_d = 1.0 - ab
            cfg = VotingSystemConfig(
                weights=weights, epsilon=gamma, p_c=1.0, p_d=p_d,
                util_dists=util_dists,
            )
            vals   = compute_coco(cfg, p_vals)
            finite = np.isfinite(vals)
            valid  = finite & ncr_valid
            if not valid.any():
                continue
            ratio = _enforce_monotone(vals[valid] / ncr_vals[valid])
            ax.plot(p_vals[valid], ratio, linestyle="dashed", color=color,
                    linewidth=2.0, label=fr"$\gamma$={gamma}")
            if not finite.all():
                ax.axvline(p_vals[finite][-1], color=color,
                           linestyle=":", linewidth=1.5, alpha=0.7)

        ax.set_title(fr"$\alpha{{-}}\beta$ = {ab}", fontsize=11)
        ax.set_xlabel("Target win probability $p$", fontsize=11)
        ax.set_ylabel(r"$\mathsf{CoCo}(p)\,/\,\mathsf{CoCo}_{\mathrm{NCR}}(p)$", fontsize=11)
        ax.tick_params(labelsize=10)
        ax.legend(fontsize=9)
        ax.set_xlim(0, 1)
        ylo, yhi = ax.get_ylim()
        ax.set_ylim(max(0, ylo), yhi * 1.2)

    fig.tight_layout()
    fig.savefig("figures/study7_gamma_sweep.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  → study7_gamma_sweep.png")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    figure_paper()
    # study_gamma_sweep()
    # study_cast_iron_params()
    # study_n_voters()
    # study_weight_distributions()
    # study_revote_epsilon()
    # study_pivotality_fns()
    # study_voter_opposition()
    print("Done.")