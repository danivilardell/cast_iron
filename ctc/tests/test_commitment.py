import json
from pathlib import Path

import pytest

from ctc import commitment as com
from ctc.poseidon import FR_MODULUS, poseidon_md

VECTORS = json.loads((Path(__file__).parent / "vectors.json").read_text())
# Vectors come from the Go prover (tests/gen_vectors): shared.PoseidonMD,
# voteropening.ComputeOpening, shared.EntryCommitmentNative.


@pytest.mark.parametrize("v", VECTORS["poseidon_md"], ids=lambda v: f"len{len(v['in'])}")
def test_poseidon_md_matches_gnark(v):
    assert poseidon_md([int(x) for x in v["in"]]) == int(v["out"])


@pytest.mark.parametrize("v", VECTORS["openings"])
def test_opening_matches_go_prover(v):
    m = (int(v["rx"]), int(v["ry"]), int(v["s"]))  # sigma_reg only (Go variant)
    o = com.compute_opening(m, int(v["r"]))
    assert (o.h1, o.h2, o.c) == (int(v["h1"]), int(v["h2"]), int(v["c"]))
    assert (o.rsig, o.rsig_hi, o.rsig_lo) == (int(v["rsig"]), int(v["rsig_hi"]), int(v["rsig_lo"]))
    assert com.entry_commitment(int(v["pos"]), o.rsig) == int(v["leaf"])


def test_poseidon_rejects_non_field_element():
    with pytest.raises(ValueError):
        poseidon_md([FR_MODULUS])


M = com.encode_message(12345, (1, 2, 3))


def test_verify_valid():
    r = com.sample_randomness()
    assert com.verify(M, r, com.commit(M, r))


def test_nonce_in_range():
    c = com.commit(M, com.sample_randomness())
    assert 0 < c < com.SECP256K1_ORDER


def test_binding_wrong_message():
    r = com.sample_randomness()
    c = com.commit(M, r)
    assert not com.verify(com.encode_message(12345, (1, 2, 4)), r, c)
    assert not com.verify(com.encode_message(54321, (1, 2, 3)), r, c)


def test_binding_wrong_randomness():
    r = com.sample_randomness()
    c = com.commit(M, r)
    assert not com.verify(M, (r + 1) % FR_MODULUS, c)


def test_hiding_randomization():
    assert com.commit(M, com.sample_randomness()) != com.commit(M, com.sample_randomness())


def test_resample_on_zero_nonce(monkeypatch):
    monkeypatch.setattr(com, "poseidon_md", lambda vals, state=0: 0)
    with pytest.raises(com.ResampleError):
        com.compute_opening(M, 1)


def test_resample_on_large_x(monkeypatch):
    monkeypatch.setattr(com, "nonce_point_x", lambda c: com.SECP256K1_ORDER)
    with pytest.raises(com.ResampleError):
        com.compute_opening(M, 1)
