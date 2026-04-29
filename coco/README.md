# CoCo — Cost of Coercion

Computes the minimum total bribe an adversary must pay to achieve a target win probability in a weighted voting system, and studies how coercion-resistant voting protocols raise that cost.

## The problem

A weighted voting system has $n$ voters with weights $w_i$ (total weight $W$). A proposal passes when the weighted yes-vote exceeds $W/2$. An adversary can bribe voter $i$ with amount $b_i \geq 0$, which shifts their vote distribution. The **Cost of Coercion** at target win probability $p$ is:

$$\text{CoCo}(p) = \min_{b_i \geq 0} \sum_i b_i \quad \text{s.t.} \quad \Pr\!\left[\sum_i Y_i(b_i)\,w_i > W/2\right] \geq p$$

The figure in the paper plots $\overline{\text{CoCo}}(p)$ (normalised by a non coercion-resistant baseline), so a value of $k$ means the protocol forces the adversary to spend $k\times$ more than an undetectable bribe.

## Parameters

Each voter $i$ has a private utility draw $u_i \sim F_i$. Under bribe $b_i$, voter $i$ votes yes with probability $q_i(b_i)$. The protocol parameters are:

| Parameter | Meaning |
|-----------|---------|
| $\gamma$ (`epsilon`) | Coercion success rate — fraction of bribed voters who follow instructions |
| $\alpha$ (`p_c`) | Detection probability given a bribe was offered |
| $\beta$ (`p_d`) | False-positive detection probability |
| $\alpha - \beta$ | Net detection differential |

**Pivotality** $\phi_i = \min(1,\,2w_i/W)$ scales the effective bribe by how likely voter $i$ is to be pivotal. Default: linear pivotality.

## Computation

The optimisation is solved with SLSQP. The win probability $\Pr[\cdot]$ is computed via a CLT approximation to the weighted sum $\sum_i Y_i w_i$, with exact conditioning on any dominant voter ($w_i^2/\sum w_j^2 > 0.1$).

## Quickstart

```bash
# Install (requires Python ≥ 3.13)
uv sync

# Generate the paper figure (PNG + PDF → figures/)
uv run python coco_sim.py
```

To compute CoCo programmatically:

```python
from scipy.stats import norm
from coco import VotingSystemConfig, compute_coco
import numpy as np

n = 100
cfg = VotingSystemConfig(
    weights=[1.0] * n,
    epsilon=0.8,      # 80% coercion success rate
    p_c=1.0,          # adversary minimises capital: p_c = 1
    p_d=0.96,         # 4% net detection differential
    util_dists=[norm(loc=1, scale=1)] * n,
)

p_vals = np.linspace(0.05, 0.95, 20)
coco = compute_coco(cfg, p_vals)   # array of minimum total bribes
```