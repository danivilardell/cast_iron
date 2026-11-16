"""
Poseidon2 commitment / nonce derivation for the CTC (paper Fig. 2, App. C).

The CTC commitment is the ECDSA nonce itself:

    h1 = Poseidon(m ‖ r)
    h2 = Poseidon(m ‖ r ‖ WIDE_HASH_TAG)
    c  = (h1 · 2^254 + h2) mod n          (n = secp256k1 group order)

and the on-chain signature has r_sigma = x([c]G).  This mirrors
``voteropening.ComputeOpening`` in the Go prover, which the tallying circuit
re-evaluates, so a registration produced here can be opened in-circuit.

``m`` is a sequence of BN254 scalar-field elements.  In Cast Iron
m = (pk_i, sigma_reg) (paper Sec. 5.1), see :func:`encode_message`;
``r`` is a single scalar-field element.

"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Sequence

from ecdsa import SECP256k1

from ctc.poseidon import FR_MODULUS, poseidon_md

SECP256K1_ORDER: int = SECP256k1.order
_G = SECP256k1.generator

# Must match voteropening.WideHashTag / FixedBaseGadget (fixedbase.go).
WIDE_HASH_TAG = 1
FR_BITS = 254
# Must match shared.EntryDomainTag.
ENTRY_DOMAIN_TAG = 1


class ResampleError(Exception):
    """
    The derived nonce is unusable (c == 0, or x([c]G) >= n).  Probability
    ~2^-128 each; the committer simply draws fresh randomness r.
    """


@dataclass(frozen=True)
class Opening:
    """Everything derived from (m, r); mirrors ``voteropening.Opening``."""

    h1: int
    h2: int
    c: int  # nonce / commitment, in [1, n-1]
    rsig: int  # x([c]G) < n, the ECDSA r-component on chain
    rsig_hi: int  # rsig = rsig_hi * 2^128 + rsig_lo (in-circuit witness form)
    rsig_lo: int


def nonce_point_x(c: int) -> int:
    """x-coordinate of [c]G (not reduced mod n)."""
    if not 0 < c < SECP256K1_ORDER:
        raise ValueError("nonce out of range")
    return (c * _G).x()


def sample_randomness() -> int:
    """Uniform element of the BN254 scalar field."""
    return secrets.randbelow(FR_MODULUS)


def encode_message(pk_i: int | Sequence[int], sigma_reg: Sequence[int]) -> tuple[int, ...]:
    """
    m = (pk_i, sigma_reg) as field elements.  ``pk_i`` is a single element or a
    sequence (e.g. an (x, y) point); ``sigma_reg`` is (Rx, Ry, S).
    """
    pk = (pk_i,) if isinstance(pk_i, int) else tuple(pk_i)
    return pk + tuple(sigma_reg)


def compute_opening(m: Sequence[int], r: int) -> Opening:
    """
    Derive the nonce and r_sigma from (m, r).  Raises :class:`ResampleError`
    if the (negligible-probability) bad cases occur.
    """
    if not 0 <= r < FR_MODULUS:
        raise ValueError("r is not a BN254 scalar-field element")
    m = tuple(m)
    h1 = poseidon_md(m + (r,))
    h2 = poseidon_md(m + (r, WIDE_HASH_TAG))
    c = ((h1 << FR_BITS) + h2) % SECP256K1_ORDER
    if c == 0:
        raise ResampleError("c == 0")
    x = nonce_point_x(c)
    if x >= SECP256K1_ORDER:
        raise ResampleError("x([c]G) >= n")
    return Opening(h1, h2, c, x, x >> 128, x & ((1 << 128) - 1))


def commit(m: Sequence[int], r: int) -> int:
    """c = Com(m; r), the ECDSA nonce embedded on chain."""
    return compute_opening(m, r).c


def verify(m: Sequence[int], r: int, c: int) -> bool:
    try:
        return commit(m, r) == c
    except (ResampleError, ValueError):
        return False


def entry_commitment(pos_reg: int, rsig: int) -> int:
    """
    Record-tree leaf Poseidon(EntryDomainTag, posReg, rsig_hi, rsig_lo)
    (``shared.EntryCommitmentNative``).  How a chain position t maps to the
    field element ``pos_reg`` is up to the record-tree builder.
    """
    return poseidon_md((ENTRY_DOMAIN_TAG, pos_reg, rsig >> 128, rsig & ((1 << 128) - 1)))
