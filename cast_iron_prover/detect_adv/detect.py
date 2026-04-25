import numpy as np
import matplotlib.pyplot as plt

mu = np.logspace(0, 6, 1000)
ab = 1 / np.sqrt(2 * np.pi * mu)

points = [
    (12,  'FTR $< 1$ USDT'),
    (40, 'FTR $< 10$ USDT'),
    (2000, 'All transactions'),
]
colors = ['#C0392B', '#E67E22', '#27AE60']

fig, ax = plt.subplots(figsize=(5.5, 3.8))
ax.plot(mu, ab, color='#2271B3', linewidth=1.8, zorder=2)

for (mu_val, label), color in zip(points, colors):
    y_val = 1 / np.sqrt(2 * np.pi * mu_val)
    ax.scatter([mu_val], [y_val], color=color, zorder=5, s=45, clip_on=False, label=label)
    ax.text(
        mu_val * 1.5, y_val,
        f'($\\mu={mu_val}$, $\\alpha-\\beta={y_val:.3f}$)',
        fontsize=11,
        color=color,
        va='center',
        ha='left',
    )

ax.legend(fontsize=11, framealpha=0.9, loc='lower left')
ax.set_xscale('log')
ax.set_yscale('log')
ax.set_xlim(0.5, 3e6)
ax.set_ylim(2e-4, 0.7)
ax.set_xlabel(r'$\mu$ (cover traffic volume)', fontsize=12)
ax.set_ylabel(r'$\alpha - \beta$', fontsize=12)
ax.tick_params(axis='both', labelsize=11)
ax.grid(True, which='major', linestyle='--', linewidth=0.4, color='gray', alpha=0.4)
ax.minorticks_off()
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
fig.tight_layout()
fig.savefig('coco_alpha_beta.pdf', bbox_inches='tight')
fig.savefig('coco_alpha_beta.png', dpi=300, bbox_inches='tight')