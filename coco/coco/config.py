from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

PivotalityFn = Callable[[float, float], float]


def linear_pivotality(scale: float = 1.0) -> PivotalityFn:
    """phi_i = min(1, scale * 2 * w_i / W).  Reaches 1 at the majority threshold."""
    def fn(w_i: float, W: float) -> float:
        return min(1.0, scale * 2.0 * w_i / W)
    return fn


def sqrt_pivotality(scale: float = 1.0) -> PivotalityFn:
    """phi_i = min(1, scale * 2 * sqrt(w_i / W)).  Concave — boosts small voters."""
    def fn(w_i: float, W: float) -> float:
        return min(1.0, scale * 2.0 * (w_i / W) ** 0.5)
    return fn


def quadratic_pivotality(scale: float = 1.0) -> PivotalityFn:
    """phi_i = min(1, scale * (2 * w_i / W)^2).  Convex — concentrates on large voters."""
    def fn(w_i: float, W: float) -> float:
        return min(1.0, scale * (2.0 * w_i / W) ** 2)
    return fn


@dataclass
class VotingSystemConfig:
    """Configuration for a weighted voting system."""

    weights: list[float]
    epsilon: float
    p_c: float
    p_d: float
    util_dists: list[Any]
    pivotality_fn: PivotalityFn = field(default_factory=linear_pivotality)

    def __post_init__(self) -> None:
        if len(self.weights) != len(self.util_dists):
            raise ValueError("weights and util_dists must have the same length")
        if any(w <= 0 for w in self.weights):
            raise ValueError("all weights must be positive")
        if not (0 <= self.p_d <= self.p_c <= 1):
            raise ValueError("must have 0 <= p_d <= p_c <= 1")
        if not (0 <= self.epsilon <= 1):
            raise ValueError("epsilon must be in [0, 1]")

    @property
    def n(self) -> int:
        return len(self.weights)

    @property
    def W(self) -> float:
        return sum(self.weights)

    def pivotalities(self) -> list[float]:
        W = self.W
        return [self.pivotality_fn(w, W) for w in self.weights]

    def baseline_win_probability(self) -> float:
        """Win probability with zero bribes: each voter votes Yes iff u_no < 0."""
        from .probability import winning_probability_clt
        import numpy as np
        q0 = np.array([float(d.cdf(0)) for d in self.util_dists])
        return winning_probability_clt(q0, self.weights, self.W / 2.0)
