import pytest
from ctc.commitment import SHA256Commitment
from ctc.adapters.mock_blockchain import MockBlockchain
from ctc.ctc import CTC


@pytest.fixture
def ctc():
    instance = CTC(SHA256Commitment(), MockBlockchain())
    instance.setup()
    return instance


def test_commit_open_roundtrip(ctc):
    m = b"vote:Alice"
    t = ctc.commit(m)
    assert ctc.open_local(t) is True
    # Also verify open() accepts the explicit (m, r) stored locally
    record = ctc._store[t]
    assert ctc.open(m, record.r, t) is True


def test_binding_wrong_message(ctc):
    t = ctc.commit(b"vote:Alice")
    assert ctc.open(b"vote:Bob", ctc._store[t].r, t) is False


def test_binding_wrong_randomness(ctc):
    m = b"vote:Alice"
    t = ctc.commit(m)
    assert ctc.open(m, b"\xff" * 16, t) is False


def test_binding_wrong_seq_id(ctc):
    t = ctc.commit(b"vote:Alice")
    record = ctc._store[t]
    assert ctc.open(record.m, record.r, t + 999) is False


def test_leak_anonymity_set(ctc):
    assert ctc.leak() == []
    ctc.commit(b"vote:Alice")
    ctc.commit(b"vote:Bob")
    leaked = ctc.leak()
    assert len(leaked) == 2
    # Addresses must not equal the plaintext messages
    messages = {b"vote:Alice".hex(), b"vote:Bob".hex()}
    for tx in leaked:
        assert tx["to"] not in messages


def test_ordering(ctc):
    t0 = ctc.commit(b"vote:Alice")
    t1 = ctc.commit(b"vote:Bob")
    assert t0 < t1
