from __future__ import annotations

import warnings
import numpy as np
from numpy.typing import NDArray
from scipy.stats import norm as _norm

MAX_INT_TOTAL = 8192


def yes_probability(
    b_i: float,
    phi_i: float,
    dist: object,
    epsilon: float,
    p_c: float,
    p_d: float,
) -> float:
    """Compute q_i = Pr[voter i votes yes] given bribe b_i.

    Implements the Proposition from the paper.
    """
    if phi_i <= 0:
        return 0.0
    if b_i <= 0:
        # No bribe: voter votes Yes only if they already prefer Yes (u_no < 0).
        # All regime formulas converge to F(0) as b→0+, so use that as the limit.
        return float(dist.cdf(0))

    # Regime A: cooperating dominates defecting
    if p_c * (1 - epsilon) > p_d:
        threshold = p_c * b_i / phi_i
        return float(dist.cdf(threshold))
    else:
        # Regime B
        if epsilon == 0:
            # pure defect regime, no randomisation
            threshold = p_d * b_i / phi_i
            return float(dist.cdf(threshold))
        elif epsilon == 1:
            threshold = (p_c - p_d) * b_i / phi_i
            return float(dist.cdf(threshold))
        else:
            t1 = (p_c - p_d) * b_i / (epsilon * phi_i)
            t2 = p_d * b_i / ((1 - epsilon) * phi_i)
            return epsilon * float(dist.cdf(t1)) + (1 - epsilon) * float(dist.cdf(t2))


def winning_probability_dft(
    q: NDArray,
    weights: list[float],
    threshold: float,
) -> float:
    """Exact Pr[sum_i Y_i * w_i > threshold] via FFT convolution."""
    n = len(q)
    W = sum(weights)
    r = W / MAX_INT_TOTAL
    k_vals = [max(1, round(w / r)) for w in weights]
    K_total = sum(k_vals) + 1

    # Pad to next power of 2
    N = 1
    while N < K_total:
        N <<= 1

    pgf = np.ones(N, dtype=complex)
    for i in range(n):
        f = np.zeros(N, dtype=complex)
        f[0] = 1 - q[i]
        f[k_vals[i]] = q[i]
        pgf *= np.fft.fft(f)

    pmf = np.fft.ifft(pgf).real
    pmf = np.clip(pmf, 0, None)

    # Sum bins where bin_index * r > threshold
    threshold_bin = threshold / r
    prob = float(np.sum(pmf[np.arange(N) > threshold_bin]))
    return float(np.clip(prob, 0.0, 1.0))


def winning_probability_mc(
    q: NDArray,
    weights: list[float],
    threshold: float,
    n_samples: int = 100_000,
    rng: np.random.Generator | None = None,
) -> float:
    """Monte Carlo estimate of Pr[sum_i Y_i * w_i > threshold]."""
    if rng is None:
        rng = np.random.default_rng()
    q_arr = np.asarray(q)
    w_arr = np.asarray(weights)
    # Draw Bernoulli samples: shape (n_samples, n)
    samples = rng.random((n_samples, len(q_arr))) < q_arr[np.newaxis, :]
    weighted_sums = samples @ w_arr
    return float(np.mean(weighted_sums > threshold))


def winning_probability_clt(
    q: NDArray,
    weights: list[float],
    threshold: float,
) -> float:
    """CLT approximation of Pr[sum_i Y_i * w_i > threshold].

    Treats the weighted sum of independent Bernoullis as normally distributed:
      mu  = sum q_i * w_i
      var = sum q_i*(1-q_i) * w_i^2
      P   ~ Phi((mu - threshold) / sqrt(var))

    Accurate when no single voter dominates (Lindeberg condition holds).
    """
    w = np.asarray(weights, dtype=float)
    q = np.asarray(q, dtype=float)
    mu = float(q @ w)
    var = float((q * (1.0 - q)) @ (w ** 2))
    if var <= 0.0:
        return 1.0 if mu > threshold else 0.0
    z = (mu - threshold) / np.sqrt(var)
    return float(_norm.cdf(z))


def winning_probability_clt_grad(
    q: NDArray,
    weights: list[float],
    threshold: float,
) -> NDArray:
    """Gradient d P_clt / d q_i for each voter i.

    Returns an array of the same length as q.
    """
    w = np.asarray(weights, dtype=float)
    q = np.asarray(q, dtype=float)
    mu = q @ w
    var = (q * (1.0 - q)) @ (w ** 2)
    if var <= 0.0:
        return np.zeros(len(q))
    sig = np.sqrt(var)
    z = (mu - threshold) / sig
    phi_z = _norm.pdf(z)
    # dz/dq_i = w_i/sig  -  z*(1-2*q_i)*w_i^2 / (2*var)
    dz_dqi = w / sig - z * (1.0 - 2.0 * q) * w ** 2 / (2.0 * var)
    return phi_z * dz_dqi


def dyes_probability_db(
    b_i: float,
    phi_i: float,
    dist: object,
    epsilon: float,
    p_c: float,
    p_d: float,
) -> float:
    """d q_i / d b_i — derivative of yes_probability w.r.t. the bribe amount."""
    if phi_i <= 0:
        return 0.0
    if b_i <= 0:
        # One-sided derivative at 0: use the regime formula evaluated at 0+.
        # yes_probability returns dist.cdf(0) for b=0, but the slope from the
        # right is the PDF at 0 scaled by the regime coefficient.
        b_i = 0.0

    if p_c * (1 - epsilon) > p_d:
        # Regime A: q = F(p_c * b / phi)
        x = p_c * b_i / phi_i
        return float(dist.pdf(x)) * p_c / phi_i  # type: ignore[attr-defined]
    else:
        if epsilon == 0:
            x = p_d * b_i / phi_i
            return float(dist.pdf(x)) * p_d / phi_i  # type: ignore[attr-defined]
        elif epsilon == 1:
            diff = p_c - p_d
            if diff <= 0:
                return 0.0
            x = diff * b_i / phi_i
            return float(dist.pdf(x)) * diff / phi_i  # type: ignore[attr-defined]
        else:
            t1 = (p_c - p_d) * b_i / (epsilon * phi_i)
            t2 = p_d * b_i / ((1 - epsilon) * phi_i)
            # q = eps*F(t1) + (1-eps)*F(t2)
            # dq/db = f(t1)*(p_c-p_d)/phi + f(t2)*p_d/phi
            return (  # type: ignore[attr-defined]
                float(dist.pdf(t1)) * (p_c - p_d) + float(dist.pdf(t2)) * p_d
            ) / phi_i


def majority_voter(weights: list[float]) -> int | None:
    """Return index of a voter with w_i > W/2 (their vote alone decides the outcome), or None."""
    W = sum(weights)
    for i, w in enumerate(weights):
        if w > W / 2.0:
            return i
    return None


def dominant_voters(weights: list[float], tau: float = 0.1) -> list[int]:
    """Indices to condition on exactly (greedy: remove largest w_i²/Σw_j² until max share < tau).

    The remaining voters satisfy max(w_i²/Σw_j²) < tau, making CLT accurate on them.
    """
    w2 = np.asarray(weights, dtype=float) ** 2
    remaining = list(range(len(weights)))
    conditioned: list[int] = []
    while remaining:
        total = sum(w2[i] for i in remaining)
        if total <= 0:
            break
        best = max(remaining, key=lambda i: w2[i])
        if w2[best] / total > tau:
            conditioned.append(best)
            remaining.remove(best)
        else:
            break
    return conditioned


def winning_probability_hybrid(
    q: NDArray,
    weights: list[float],
    threshold: float,
    conditioned: list[int],
) -> float:
    """Pr[win] via exact conditioning on `conditioned` voters, CLT on the rest.

    Sums over all 2^|conditioned| binary assignments, weighting by Bernoulli probability
    and evaluating CLT on the residual voters at the adjusted threshold.
    """
    if not conditioned:
        return winning_probability_clt(q, weights, threshold)
    w = np.asarray(weights, dtype=float)
    q = np.asarray(q, dtype=float)
    K = conditioned
    rest = [i for i in range(len(q)) if i not in set(K)]
    q_rest = q[rest] if rest else np.empty(0)
    w_rest = w[rest] if rest else np.empty(0)
    total = 0.0
    for bits in range(1 << len(K)):
        bern = 1.0
        adj = threshold
        for j, k in enumerate(K):
            y_j = (bits >> j) & 1
            bern *= q[k] if y_j else (1.0 - q[k])
            adj -= y_j * w[k]
        if bern == 0.0:
            continue
        if not rest:
            total += bern * (1.0 if adj < 0 else 0.0)
        else:
            total += bern * winning_probability_clt(q_rest, w_rest, adj)
    return float(np.clip(total, 0.0, 1.0))


def winning_probability_hybrid_grad(
    q: NDArray,
    weights: list[float],
    threshold: float,
    conditioned: list[int],
) -> NDArray:
    """Gradient dP/dq_i for the hybrid (conditioning + CLT) backend.

    For residual voters i not in K: sum of CLT gradients weighted by Bernoulli probability.
    For conditioned voters k in K: product rule — bern/f_k * df_k/dq_k * P_CLT, where
      f_k = q_k (if y_k=1) or 1-q_k (if y_k=0), and bern/f_k is the product over K minus k.
    """
    if not conditioned:
        return winning_probability_clt_grad(q, weights, threshold)
    w = np.asarray(weights, dtype=float)
    q = np.asarray(q, dtype=float)
    K = conditioned
    K_set = set(K)
    rest = [i for i in range(len(q)) if i not in K_set]
    q_rest = q[rest] if rest else np.empty(0)
    w_rest = w[rest] if rest else np.empty(0)
    grad = np.zeros(len(q))
    for bits in range(1 << len(K)):
        y_K = [(bits >> j) & 1 for j in range(len(K))]
        bern = 1.0
        adj = threshold
        for j, k in enumerate(K):
            bern *= q[k] if y_K[j] else (1.0 - q[k])
            adj -= y_K[j] * w[k]
        if bern == 0.0:
            continue
        if rest:
            clt_val = winning_probability_clt(q_rest, w_rest, adj)
            clt_grad_rest = winning_probability_clt_grad(q_rest, w_rest, adj)
            for local_i, i in enumerate(rest):
                grad[i] += bern * clt_grad_rest[local_i]
        else:
            clt_val = 1.0 if adj < 0 else 0.0
        # Gradient for conditioned voters: bern/f_k * df_k/dq_k * P_CLT
        # bern/f_k recovers the product over K\{k} without recomputing
        for j, k in enumerate(K):
            f_k = q[k] if y_K[j] else (1.0 - q[k])
            if f_k > 0:
                df_k = 1.0 if y_K[j] else -1.0
                grad[k] += (bern / f_k) * df_k * clt_val
    return grad


def winning_probability(
    q: NDArray,
    weights: list[float],
    threshold: float,
    backend: str = "auto",
    n_samples: int = 100_000,
    rng: np.random.Generator | None = None,
) -> float:
    """Dispatch to CLT, exact DFT, or Monte Carlo backend."""
    if backend == "auto":
        backend = "clt"

    if backend == "clt":
        return winning_probability_clt(q, weights, threshold)
    elif backend == "exact":
        return winning_probability_dft(q, weights, threshold)
    elif backend == "montecarlo":
        return winning_probability_mc(q, weights, threshold, n_samples=n_samples, rng=rng)
    else:
        raise ValueError(f"Unknown backend: {backend!r}")
