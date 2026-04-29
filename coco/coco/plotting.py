from __future__ import annotations

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.axes import Axes
from numpy.typing import NDArray


def plot_coco_curves(
    curves: list[tuple[NDArray, NDArray, str]],
    *,
    title: str = "Cost of Coercion",
    xlabel: str = "Win probability $p$",
    ylabel: str = "CoCo$(p)$ — total bribe",
    figsize: tuple[float, float] = (8, 5),
    log_y: bool = False,
    show_markers: bool = False,
    ax: Axes | None = None,
) -> tuple[Figure, Axes]:
    """Plot multiple CoCo(p) curves on a single axes.

    Parameters
    ----------
    curves : list of (p_values, coco_values, label)
        Each entry is a curve to plot. ``np.inf`` entries are silently dropped.
    title, xlabel, ylabel : str
        Axis labels and title.
    figsize : tuple
        Figure size (ignored if ax is provided).
    log_y : bool
        Use log scale on the y-axis.
    show_markers : bool
        Draw markers at each data point.
    ax : Axes, optional
        Existing axes to draw into. If None, a new figure is created.

    Returns
    -------
    fig, ax
    """
    if ax is None:
        fig, ax = plt.subplots(figsize=figsize)
    else:
        fig = ax.get_figure()

    marker = "o" if show_markers else None

    for p_vals, coco_vals, label in curves:
        p_arr = np.asarray(p_vals)
        c_arr = np.asarray(coco_vals)

        finite_mask = np.isfinite(c_arr)
        p_finite = p_arr[finite_mask]
        c_finite = c_arr[finite_mask]

        ax.plot(p_finite, c_finite, label=label, lw=2, marker=marker)

        # Dashed vertical line at the feasibility boundary
        if finite_mask.any() and not finite_mask.all():
            boundary = p_arr[finite_mask][-1]
            ax.axvline(boundary, linestyle="--", color="grey", alpha=0.5)

    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend()
    ax.grid(True, alpha=0.3)
    if log_y:
        ax.set_yscale("log")

    return fig, ax
