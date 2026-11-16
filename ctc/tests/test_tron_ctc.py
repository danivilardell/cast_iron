"""
Integration tests for the Tron ECDSA-nonce blockchain adapter.

Skipped unless the following variables are set (env or .env file):

    TRON_TESTNET_NETWORK  — TronPy network name, typically "nile" or "shasta"
    TRON_TESTNET_NODE     — Full HTTP RPC URL for a live TRON node
  TRON_PRIVATE_KEY      — 64-hex-char private key for a funded testnet account
  TRON_RECIPIENT        — Any valid TRON base58check address to receive the
                           1-SUN commitment transactions
"""

import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env", override=True)

TRON_NETWORK = os.environ.get("TRON_TESTNET_NETWORK", "nile")
TRON_NODE = os.environ.get("TRON_TESTNET_NODE")
TRON_KEY = os.environ.get("TRON_PRIVATE_KEY")
TRON_RECIPIENT = os.environ.get("TRON_RECIPIENT")

tron_required = pytest.mark.skipif(
    not all([TRON_NODE, TRON_KEY, TRON_RECIPIENT]),
    reason="TRON_TESTNET_NODE, TRON_PRIVATE_KEY, TRON_RECIPIENT not set",
)


@pytest.fixture(scope="module")
def tron_ctc():
    try:
        from tronpy import Tron
        from tronpy.providers import HTTPProvider
        from ctc.adapters.tron_blockchain import TronNonceBlockchain
        from ctc.ctc import CTC
    except ModuleNotFoundError as exc:
        pytest.skip(f"tronpy is not installed: {exc}")

    client = Tron(HTTPProvider(endpoint_uri=TRON_NODE), network=TRON_NETWORK)

    chain = TronNonceBlockchain(
        client,
        signing_key_bytes=bytes.fromhex(TRON_KEY),
        recipient=TRON_RECIPIENT,
    )
    return CTC(chain)


M = (777, 11, 22, 33)  # (pk_i, sigma_reg) as field elements


@tron_required
def test_tron_commit_and_open(tron_ctc):
    m = M
    t = tron_ctc.commit(m)
    assert tron_ctc.open_local(t) is True


@tron_required
def test_tron_open_tampered_message_fails(tron_ctc):
    t = tron_ctc.commit(M)
    _, r = tron_ctc.get_opening(t)
    assert tron_ctc.open((778, 11, 22, 33), r, t) is False


@tron_required
def test_tron_seq_ids_are_ordered(tron_ctc):
    t0 = tron_ctc.commit((1, 2, 3, 4))
    t1 = tron_ctc.commit((5, 6, 7, 8))
    assert isinstance(t0, str)
    assert isinstance(t1, str)
    assert t0 != t1