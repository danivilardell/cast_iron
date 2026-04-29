import numpy as np
import matplotlib.pyplot as plt
from matplotlib.widgets import Slider


def expected_utilities(b, pivot0, pivot1, epsilon, p_c, p_d, u_no=1.0):
    """Compute expected utility for ignore, defect, cooperate.

    Parameters
    ----------
    b       : array-like – bribe values (in utility units)
    pivot0  : float      – Pr[no wins | voter votes no]   (pi(0))
    pivot1  : float      – Pr[no wins | voter votes yes]  (pi(1))
    epsilon : float      – defect success probability (varepsilon)
    p_c     : float      – Pr[adversary pays | cooperate]
    p_d     : float      – Pr[adversary pays | defect]
    u_no    : float      – utility of 'no' outcome (U^yes normalized to 0)
    """
    # E[U | ignore]    = pi(0) * U^no
    e_ignore = np.full_like(b, pivot0 * u_no)

    # E[U | defect]    = p_d * b + (eps * pi(0) + (1 - eps) * pi(1)) * U^no
    e_defect = p_d * b + (epsilon * pivot0 + (1 - epsilon) * pivot1) * u_no

    # E[U | cooperate] = p_c * b + pi(1) * U^no
    e_cooperate = p_c * b + pivot1 * u_no

    return e_ignore, e_defect, e_cooperate


def main():
    # --- defaults ---
    pivot0_init  = 0.55
    pivot1_init  = 0.45
    epsilon_init = 0.80
    p_c_init     = 0.80
    p_d_init     = 0.10
    u_no_init    = 1.00

    b_max = 5.0
    b = np.linspace(0, b_max, 500)

    # --- figure layout ---
    fig, ax = plt.subplots(figsize=(9, 6))
    fig.subplots_adjust(bottom=0.45)

    e_ign, e_def, e_coop = expected_utilities(
        b, pivot0_init, pivot1_init, epsilon_init, p_c_init, p_d_init, u_no_init
    )

    (line_ign,)  = ax.plot(b, e_ign,  label="Ignore",    lw=2)
    (line_def,)  = ax.plot(b, e_def,  label="Defect",    lw=2)
    (line_coop,) = ax.plot(b, e_coop, label="Cooperate", lw=2)

    ax.set_xlabel("Bribe  $b$  (utility units)")
    ax.set_ylabel("Expected utility")
    ax.set_title("Coercion game: voter expected utility")
    ax.legend(loc="upper left")
    ax.set_xlim(0, b_max)
    ax.grid(True, alpha=0.3)

    # text annotations for derived quantities
    info_str = (
        f"pi(0) = {pivot0_init:.2f}   pi(1) = {pivot1_init:.2f}\n"
        f"delta = {pivot0_init - pivot1_init:.2f}"
    )
    info_text = ax.text(
        0.98, 0.98, info_str,
        transform=ax.transAxes, ha="right", va="top",
        fontsize=10, family="monospace",
        bbox=dict(boxstyle="round,pad=0.3", fc="wheat", alpha=0.8),
    )

    # shaded region showing the rational choice
    shade = ax.fill_between(b, 0, 0, alpha=0.08, color="grey")

    def update_shade():
        nonlocal shade
        shade.remove()
        e_ign_v  = line_ign.get_ydata()
        e_def_v  = line_def.get_ydata()
        e_coop_v = line_coop.get_ydata()
        best = np.maximum(np.maximum(e_ign_v, e_def_v), e_coop_v)

        colors = []
        for i in range(len(b)):
            if best[i] == e_ign_v[i]:
                colors.append(line_ign.get_color())
            elif best[i] == e_def_v[i]:
                colors.append(line_def.get_color())
            else:
                colors.append(line_coop.get_color())

        prev_color = colors[0]
        start = 0
        for i in range(1, len(b)):
            if colors[i] != prev_color or i == len(b) - 1:
                end = i if colors[i] != prev_color else i + 1
                ax.axvspan(b[start], b[min(end, len(b) - 1)],
                           alpha=0.10, color=prev_color, zorder=0)
                start = i
                prev_color = colors[i]

        shade = ax.fill_between(b, 0, 0, alpha=0)

    def clear_bands():
        for p in list(ax.patches):
            p.remove()

    # --- sliders ---
    slider_kw = dict(valstep=0.01)
    ax_pivot0 = fig.add_axes([0.18, 0.33, 0.65, 0.03])
    ax_pivot1 = fig.add_axes([0.18, 0.28, 0.65, 0.03])
    ax_eps    = fig.add_axes([0.18, 0.23, 0.65, 0.03])
    ax_pc     = fig.add_axes([0.18, 0.18, 0.65, 0.03])
    ax_pd     = fig.add_axes([0.18, 0.13, 0.65, 0.03])
    ax_uno    = fig.add_axes([0.18, 0.08, 0.65, 0.03])
    ax_bmax   = fig.add_axes([0.18, 0.03, 0.65, 0.03])

    s_pivot0 = Slider(ax_pivot0, r"$\pi(0)$",              0,   1,    valinit=pivot0_init,  **slider_kw)
    s_pivot1 = Slider(ax_pivot1, r"$\pi(1)$",              0,   1,    valinit=pivot1_init,  **slider_kw)
    s_eps    = Slider(ax_eps,    r"$\varepsilon$",          0,   1,    valinit=epsilon_init, **slider_kw)
    s_pc     = Slider(ax_pc,     r"$p_c$ (pay|cooperate)", 0,   1,    valinit=p_c_init,     **slider_kw)
    s_pd     = Slider(ax_pd,     r"$p_d$ (pay|defect)",    0,   1,    valinit=p_d_init,     **slider_kw)
    s_uno    = Slider(ax_uno,    r"$U^{\mathsf{no}}$",     0,   5,    valinit=u_no_init,    **slider_kw)
    s_bmax   = Slider(ax_bmax,   r"$b_{\max}$",            0.5, 20,   valinit=b_max,        valstep=0.5)

    def update(_=None):
        pivot0  = s_pivot0.val
        pivot1  = s_pivot1.val
        epsilon = s_eps.val
        p_c     = s_pc.val
        p_d     = s_pd.val
        u_no    = s_uno.val
        bmax    = s_bmax.val

        # enforce constraint: pi(1) <= pi(0)
        if pivot1 > pivot0:
            s_pivot1.set_val(pivot0)
            return

        # enforce constraint: p_d <= p_c
        if p_d > p_c:
            s_pd.set_val(p_c)
            return

        info_text.set_text(
            f"pi(0) = {pivot0:.2f}   pi(1) = {pivot1:.2f}\n"
            f"delta = {pivot0 - pivot1:.2f}"
        )

        bvals = np.linspace(0, bmax, 500)
        e_ign, e_def, e_coop = expected_utilities(
            bvals, pivot0, pivot1, epsilon, p_c, p_d, u_no
        )

        line_ign.set_data(bvals, e_ign)
        line_def.set_data(bvals, e_def)
        line_coop.set_data(bvals, e_coop)

        ax.set_xlim(0, bmax)
        ymin = min(e_ign.min(), e_def.min(), e_coop.min())
        ymax = max(e_ign.max(), e_def.max(), e_coop.max())
        margin = max(0.05, (ymax - ymin) * 0.1)
        ax.set_ylim(ymin - margin, ymax + margin)

        clear_bands()
        update_shade()
        fig.canvas.draw_idle()

    for s in (s_pivot0, s_pivot1, s_eps, s_pc, s_pd, s_uno, s_bmax):
        s.on_changed(update)

    update()
    plt.show()


if __name__ == "__main__":
    main()