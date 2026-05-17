from __future__ import annotations

import numpy as np
from numpy.typing import NDArray
from scipy.optimize import minimize

from .config import VotingSystemConfig
from .probability import (
    yes_probability,
    winning_probability,
    winning_probability_clt_grad,
    winning_probability_hybrid,
    winning_probability_hybrid_grad,
    dyes_probability_db,
    dominant_voters,
)


def _b_for_q(target_q: float, phi: float, dist: object,
             epsilon: float, p_c: float, p_d: float) -> float:
    """Find b such that yes_probability(b, ...) ≈ target_q via bisection.

    yes_probability is monotone increasing in b, so bisection is exact and
    avoids the need to replicate regime logic from yes_probability.
    """
    if phi <= 0:
        return 0.1
    f0 = float(dist.cdf(0))
    if target_q <= f0:
        return 1e-6

    fn = lambda b: yes_probability(b, phi, dist, epsilon, p_c, p_d)

    # Find upper bracket: start near phi (natural scale) and double
    hi = max(0.1, phi)
    for _ in range(60):
        if fn(hi) >= target_q:
            break
        hi *= 2.0
    else:
        return hi  # best effort if target_q is unreachable

    lo = 0.0
    for _ in range(50):
        mid = (lo + hi) / 2.0
        if fn(mid) >= target_q:
            hi = mid
        else:
            lo = mid
    return hi


def _cold_start(config: VotingSystemConfig) -> NDArray:
    """Starting point: b_i that gives q_i ≈ 0.5 under the correct regime formula.

    Uses per-voter bribe scales so each voter starts near the active region of
    their own distribution.  Pro-yes voters (negative _b_for_q) start at ~0.
    """
    pivots = config.pivotalities()
    return np.array([
        max(1e-6, _b_for_q(0.5, pivots[i], config.util_dists[i],
                            config.epsilon, config.p_c, config.p_d))
        for i in range(config.n)
    ])


def _rescale_init(
    b_init: NDArray,
    p_target: float,
    win_prob_fn,
) -> NDArray:
    """Scale b_init so that win_prob(scale * b_init) ≈ p_target.

    Rescales both up and down so that SLSQP starts in the active region
    of each voter's distribution regardless of where b_init came from.
    """
    wp = win_prob_fn(b_init)
    if abs(wp - p_target) < min(0.02, p_target * 0.1):
        return b_init  # already close enough

    if wp > p_target:
        # Scale down
        lo, hi = 0.0, 1.0
        for _ in range(25):
            mid = (lo + hi) / 2.0
            if win_prob_fn(b_init * mid) >= p_target:
                hi = mid
            else:
                lo = mid
        return b_init * hi
    else:
        # Scale up: double until we overshoot, then binary search back down
        hi = 2.0
        for _ in range(20):
            if win_prob_fn(b_init * hi) >= p_target:
                break
            hi *= 2.0
        else:
            return b_init  # can't reach p_target; return unscaled so caller handles infeasibility
        lo = 1.0
        for _ in range(25):
            mid = (lo + hi) / 2.0
            if win_prob_fn(b_init * mid) >= p_target:
                hi = mid
            else:
                lo = mid
        return b_init * hi


def _constraint_jac(
    b: NDArray,
    q: NDArray,
    config: VotingSystemConfig,
    pivots: list[float],
    threshold: float,
    conditioned: list[int],
) -> NDArray:
    """Analytical Jacobian of the winning-probability constraint."""
    if conditioned:
        dP_dq = winning_probability_hybrid_grad(q, config.weights, threshold, conditioned)
    else:
        dP_dq = winning_probability_clt_grad(q, config.weights, threshold)
    dq_db = np.array([
        dyes_probability_db(
            b[i], pivots[i], config.util_dists[i],
            config.epsilon, config.p_c, config.p_d,
        )
        for i in range(config.n)
    ])
    return dP_dq * dq_db


def compute_coco(
    config: VotingSystemConfig,
    p_values: list[float] | NDArray,
    backend: str = "auto",
    n_samples: int = 100_000,
    rng: np.random.Generator | None = None,
) -> NDArray:
    """Compute CoCo(p) for each p in p_values.

    Solves:
        min  sum(b_i)
        s.t. Pr[sum Y_i(b_i)*w_i > W/2] >= p
             b_i >= 0

    Returns an array of the same length as p_values. Infeasible entries are np.inf.
    """
    p_arr = np.asarray(p_values, dtype=float)
    results = np.full(len(p_arr), np.nan)

    threshold = config.W / 2.0
    pivots = config.pivotalities()
    n = config.n

    sorted_indices = list(np.argsort(p_arr))

    # --- Conditioning set for hybrid backend ---
    # Also handles the majority voter case (w_i > W/2): dominant_voters returns [i],
    # the hybrid reduces to P(win) = q_i exactly, and SLSQP finds the right b_i.
    # Voters with w_i²/Σw_j² > tau are conditioned on exactly; CLT applied to the rest.
    conditioned: list[int] = (
        dominant_voters(config.weights) if backend in ("auto", "clt") else []
    )

    def _compute_q(b: NDArray) -> NDArray:
        return np.array([
            yes_probability(
                b[i], pivots[i], config.util_dists[i],
                config.epsilon, config.p_c, config.p_d
            )
            for i in range(n)
        ])

    # Cache last (b, q) pair so the constraint function and its Jacobian
    # don't recompute q separately when SLSQP evaluates them at the same b.
    _q_cache: list = [None, None]  # [b.tobytes(), q]

    def _compute_q_cached(b: NDArray) -> NDArray:
        key = b.tobytes()
        if _q_cache[0] != key:
            _q_cache[0] = key
            _q_cache[1] = _compute_q(b)
        return _q_cache[1]

    def _win_prob(b: NDArray) -> float:
        q = _compute_q_cached(b)
        if conditioned:
            return winning_probability_hybrid(q, config.weights, threshold, conditioned)
        return winning_probability(
            q, config.weights, threshold,
            backend=backend, n_samples=n_samples, rng=rng
        )

    objective = lambda b: np.sum(b)
    jac_obj = lambda b: np.ones(n)

    bounds = [(0.0, None)] * n
    prev_b = None
    infeasible_from = np.inf  # once we hit infeasibility, skip higher p values

    for idx in sorted_indices:
        p = p_arr[idx]

        if p <= 0.0:
            results[idx] = 0.0
            continue

        if p >= infeasible_from:
            results[idx] = np.inf
            continue

        # Build warm start
        if prev_b is not None:
            b_init = prev_b * 1.1
        else:
            b_init = _cold_start(config)
        # Rescale to sit near win_prob ≈ p so SLSQP starts in the region
        # where dq/db is non-zero.  Applies to both cold and warm starts.
        if backend == "auto" or backend == "clt":
            b_init = _rescale_init(b_init, p, _win_prob)

        use_analytical_jac = backend in ("auto", "clt")
        constraint = {
            "type": "ineq",
            "fun": lambda b, _p=p: _win_prob(b) - _p,
            **({"jac": lambda b: _constraint_jac(
                    b, _compute_q_cached(b), config, pivots, threshold, conditioned
                )} if use_analytical_jac else {}),
        }

        def _try_solve(b_start: NDArray) -> tuple[bool, NDArray, float]:
            res = minimize(
                objective,
                b_start,
                jac=jac_obj,
                method="SLSQP",
                bounds=bounds,
                constraints=[constraint],
                options={"ftol": 1e-8, "maxiter": 1000},
            )
            if res.success or res.status == 0:
                wp = _win_prob(res.x)
                if wp >= p - 1e-6:
                    return True, res.x, np.sum(res.x)
            return False, res.x, np.inf

        # If b_init is already feasible, record it as a candidate.
        # SLSQP can only improve on it; if it fails (e.g. near-degenerate
        # Jacobian for linear pivotality + power-law weights) we fall back here.
        init_feasible = _win_prob(b_init) >= p - 1e-6
        best_val = float(np.sum(b_init)) if init_feasible else np.inf
        best_x = b_init.copy() if init_feasible else None

        ok, sx, sv = _try_solve(b_init)
        if ok and sv < best_val:
            best_x, best_val = sx, sv

        # If warm-start solve failed or is infeasible, always retry from a fresh
        # cold start — this breaks cascade propagation when prev_b was bad.
        need_retry = best_x is None or not ok or not init_feasible
        if need_retry:
            b_cold = _cold_start(config)
            if backend in ("auto", "clt"):
                b_cold = _rescale_init(b_cold, p, _win_prob)
            cold_feasible = _win_prob(b_cold) >= p - 1e-6
            if cold_feasible and np.sum(b_cold) < best_val:
                best_x, best_val = b_cold.copy(), float(np.sum(b_cold))
            ok_c, xc, vc = _try_solve(b_cold)
            if ok_c and vc < best_val:
                best_x, best_val = xc, vc
            if not ok_c:
                for scale in (2.0, 5.0, 10.0, 20.0):
                    ok2, x, val = _try_solve(b_cold * scale)
                    if ok2 and val < best_val:
                        best_x, best_val = x, val
                        break

        success = best_x is not None

        if not success:
            results[idx] = np.inf
            infeasible_from = p
        else:
            # Post-hoc feasibility check
            wp = _win_prob(best_x)
            if wp < p - 1e-3:
                results[idx] = np.inf
                infeasible_from = p
            else:
                results[idx] = best_val
                prev_b = best_x.copy()

    # Enforce monotonicity: CoCo(p) is non-decreasing by construction
    # (any bribe achieving p is feasible for p' < p), so non-monotone points
    # are optimizer failures — fix by taking cumulative max in ascending p order.
    prev_val = 0.0
    for idx in sorted_indices:
        if np.isfinite(results[idx]):
            results[idx] = max(results[idx], prev_val)
            prev_val = results[idx]

    return results
