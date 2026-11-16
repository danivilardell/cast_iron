"""
Poseidon2 over the BN254 scalar field, bit-compatible with
gnark-crypto's ``ecc/bn254/fr/poseidon2`` (the instance used by the Cast Iron
tallying circuit, see ``cast_iron_prover/shared/shared.go``).

Parameters (paper, Appendix C): width t = 2, 6 full rounds, 50 partial rounds,
S-box x^5.  The round keys are derived deterministically exactly like gnark's
``initRC`` from the seed ``Poseidon2-BN254[t=2,rF=6,rP=50,d=5]`` with the
legacy Keccak-256, so no constants table is needed.

``poseidon_md`` is the Merkle–Damgård hash used everywhere in Cast Iron:
initial state 0, one permutation (compression) per absorbed field element,

    state <- block + Perm(state, block)[1]
"""

from __future__ import annotations

from functools import lru_cache
from typing import Iterable

from eth_hash.auto import keccak

# BN254 scalar field modulus.
FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617

WIDTH = 2
FULL_ROUNDS = 6
PARTIAL_ROUNDS = 50
_SEED = f"Poseidon2-BN254[t={WIDTH},rF={FULL_ROUNDS},rP={PARTIAL_ROUNDS},d=5]"


@lru_cache(maxsize=1)
def _round_keys() -> tuple[tuple[int, ...], ...]:
    """Port of gnark-crypto ``Parameters.initRC``."""
    rnd = keccak(_SEED.encode())  # "pre hash"

    def nxt() -> int:
        nonlocal rnd
        rnd = keccak(rnd)
        return int.from_bytes(rnd, "big") % FR_MODULUS

    half = FULL_ROUNDS // 2
    keys: list[tuple[int, ...]] = []
    for _ in range(half):
        keys.append(tuple(nxt() for _ in range(WIDTH)))
    for _ in range(PARTIAL_ROUNDS):
        keys.append((nxt(),))
    for _ in range(half):
        keys.append(tuple(nxt() for _ in range(WIDTH)))
    return tuple(keys)


def _sbox(x: int) -> int:
    return pow(x, 5, FR_MODULUS)


def _mat_external(s: list[int]) -> None:
    # circ(2, 1)
    tmp = (s[0] + s[1]) % FR_MODULUS
    s[0] = (tmp + s[0]) % FR_MODULUS
    s[1] = (tmp + s[1]) % FR_MODULUS


def _mat_internal(s: list[int]) -> None:
    # [[2, 1], [1, 3]]
    total = (s[0] + s[1]) % FR_MODULUS
    s[0] = (s[0] + total) % FR_MODULUS
    s[1] = (2 * s[1] + total) % FR_MODULUS


def permutation(state: list[int]) -> list[int]:
    """Poseidon2 permutation on a width-2 state (returns a new list)."""
    if len(state) != WIDTH:
        raise ValueError("state must have exactly 2 field elements")
    keys = _round_keys()
    s = [v % FR_MODULUS for v in state]
    half = FULL_ROUNDS // 2

    _mat_external(s)
    for i in range(half):
        s = [_sbox((s[j] + keys[i][j]) % FR_MODULUS) for j in range(WIDTH)]
        _mat_external(s)
    for i in range(half, half + PARTIAL_ROUNDS):
        s[0] = _sbox((s[0] + keys[i][0]) % FR_MODULUS)
        _mat_internal(s)
    for i in range(half + PARTIAL_ROUNDS, FULL_ROUNDS + PARTIAL_ROUNDS):
        s = [_sbox((s[j] + keys[i][j]) % FR_MODULUS) for j in range(WIDTH)]
        _mat_external(s)
    return s


def compress(left: int, right: int) -> int:
    out = permutation([left, right])
    return (right + out[1]) % FR_MODULUS


def poseidon_md(values: Iterable[int], state: int = 0) -> int:
    """
    Merkle–Damgård Poseidon2 of a sequence of field elements, matching
    ``shared.PoseidonMD`` in the Go prover.  Each value must lie in [0, p).
    ``state`` allows continuing a hash from a chaining value (the circuit
    continues from Poseidon(sigma_reg), see ``NewPoseidonHasherFromState``).
    """
    for v in values:
        if not 0 <= v < FR_MODULUS:
            raise ValueError("input is not a BN254 scalar-field element")
        state = compress(state, v)
    return state
