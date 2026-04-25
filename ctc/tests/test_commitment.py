from ctc.commitment import SHA256Commitment

scheme = SHA256Commitment()
pp = scheme.setup()


def test_verify_valid():
    r = SHA256Commitment.sample_randomness()
    c = scheme.commit(pp, b"vote:Alice", r)
    assert scheme.verify(pp, b"vote:Alice", r, c)


def test_binding_wrong_message():
    r = SHA256Commitment.sample_randomness()
    c = scheme.commit(pp, b"vote:Alice", r)
    assert not scheme.verify(pp, b"vote:Bob", r, c)


def test_binding_wrong_randomness():
    r = SHA256Commitment.sample_randomness()
    c = scheme.commit(pp, b"vote:Alice", r)
    assert not scheme.verify(pp, b"vote:Alice", SHA256Commitment.sample_randomness(), c)


def test_hiding_different_messages():
    r = SHA256Commitment.sample_randomness()
    assert scheme.commit(pp, b"vote:Alice", r) != scheme.commit(pp, b"vote:Bob", r)


def test_hiding_randomization():
    # Same message, fresh randomness each time → different commitments
    m = b"vote:Alice"
    assert (
        scheme.commit(pp, m, SHA256Commitment.sample_randomness())
        != scheme.commit(pp, m, SHA256Commitment.sample_randomness())
    )
