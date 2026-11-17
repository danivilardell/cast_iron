"""Figure 7: Cast Iron's normalised CoCo as a function of the anonymity-set
size (cover traffic within the registration window), CoCo = sqrt(2*pi*lambda)
(paper Appendix B).  Closed form, no simulation.

    uv run python anonymity_set_curve.py     # -> figures/coco_curve.{pdf,png}
"""
import os

import numpy as np
import matplotlib.pyplot as plt

lam = np.logspace(0, 6, 1000)
coco = np.sqrt(2 * np.pi * lam)

# Color-blind-safe palette (Wong 2011 / Tol bright) + distinct markers
points = [
    (5,      '3 seconds (1 block)', '#D55E00', 'o'),    # vermillion, circle
    (100,    '1 minute',          '#E69F00', 's'),    # orange, square
    (144000, '1 day',                '#009E73', '^'),   # green, triangle
]

fig, ax = plt.subplots(figsize=(5.5, 3.8))

ax.plot(lam, coco, color='#0072B2', linewidth=1.8, zorder=2)

for lam_val, label, color, marker in points:
    y_val = np.sqrt(2 * np.pi * lam_val)
    ax.scatter(
        [lam_val], [y_val],
        color=color, marker=marker,
        zorder=5, s=70, clip_on=False, label=label,
        edgecolor='black', linewidth=0.6,
    )

    # Anchor annotations to the left for the rightmost point so they don't run off
    if lam_val >= 10000:
        ax.text(
            lam_val / 1.5, y_val,
            f'($\\lambda={lam_val}$, $\\mathsf{{CoCo}}={y_val:.1f}$)',
            fontsize=11, color=color, va='center', ha='right',
        )
    else:
        ax.text(
            lam_val * 1.5, y_val,
            f'($\\lambda={lam_val}$, $\\mathsf{{CoCo}}={y_val:.1f}$)',
            fontsize=11, color=color, va='center', ha='left',
        )

ax.legend(fontsize=11, framealpha=0.9, loc='lower right')
ax.set_xscale('log')
ax.set_yscale('log')
ax.set_xlim(0.5, 3e6)
ax.set_ylim(1.5, 5e3)
ax.set_xlabel(r'$\lambda$ (anonymity set size)', fontsize=12)
ax.set_ylabel(r'$\overline{\mathsf{CoCo}}$', fontsize=12)
ax.tick_params(axis='both', labelsize=11)
ax.grid(True, which='major', linestyle='--', linewidth=0.4, color='gray', alpha=0.4)
ax.minorticks_off()
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

fig.tight_layout()
os.makedirs('figures', exist_ok=True)
fig.savefig('figures/coco_curve.pdf', bbox_inches='tight')
fig.savefig('figures/coco_curve.png', dpi=300, bbox_inches='tight')
