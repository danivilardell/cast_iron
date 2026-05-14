from ctc.commitment import SHA3Commitment

scheme = SHA3Commitment()
pp = scheme.setup()


def test_verify_valid():
    r = SHA3Commitment.sample_randomness()
    c = scheme.commit(pp, b"vote:Alice", r)
    assert scheme.verify(pp, b"vote:Alice", r, c)


def test_binding_wrong_message():
    r = SHA3Commitment.sample_randomness()
    c = scheme.commit(pp, b"vote:Alice", r)
    assert not scheme.verify(pp, b"vote:Bob", r, c)


def test_binding_wrong_randomness():
    r = SHA3Commitment.sample_randomness()
    c = scheme.commit(pp, b"vote:Alice", r)
    assert not scheme.verify(pp, b"vote:Alice", SHA3Commitment.sample_randomness(), c)


def test_hiding_different_messages():
    r = SHA3Commitment.sample_randomness()
    assert scheme.commit(pp, b"vote:Alice", r) != scheme.commit(pp, b"vote:Bob", r)


def test_hiding_randomization():
    # Same message, fresh randomness each time → different commitments
    m = b"vote:Alice"
    assert (
        scheme.commit(pp, m, SHA3Commitment.sample_randomness())
        != scheme.commit(pp, m, SHA3Commitment.sample_randomness())
    )
