import pytest

from ctc import commitment as com
from ctc.adapters.mock_blockchain import MockBlockchain
from ctc.ctc import CTC

M = com.encode_message(777, (11, 22, 33))  # (pk_i, sigma_reg)


@pytest.fixture
def ctc():
    return CTC(MockBlockchain())


def test_commit_open_roundtrip(ctc):
    t = ctc.commit(M)
    assert ctc.open_local(t) is True
    m, r = ctc.get_opening(t)
    assert ctc.open(m, r, t) is True


def test_explicit_randomness(ctc):
    r = com.sample_randomness()
    t = ctc.commit(M, r)
    assert ctc.open(M, r, t) is True


def test_binding_wrong_message(ctc):
    t = ctc.commit(M)
    _, r = ctc.get_opening(t)
    assert ctc.open(com.encode_message(778, (11, 22, 33)), r, t) is False


def test_binding_wrong_randomness(ctc):
    t = ctc.commit(M)
    assert ctc.open(M, 12345, t) is False


def test_binding_wrong_seq_id(ctc):
    t = ctc.commit(M)
    m, r = ctc.get_opening(t)
    assert ctc.open(m, r, t + 999) is False


def test_ordering(ctc):
    t0 = ctc.commit(M)
    t1 = ctc.commit(com.encode_message(1, (2, 3, 4)))
    assert t0 < t1


def test_commit_resamples_internally(ctc, monkeypatch):
    real = com.commit
    calls = []

    def flaky(m, r):
        calls.append(r)
        if len(calls) == 1:
            raise com.ResampleError("forced")
        return real(m, r)

    monkeypatch.setattr(com, "commit", flaky)
    t = ctc.commit(M)
    assert len(calls) == 2 and ctc.open_local(t)
