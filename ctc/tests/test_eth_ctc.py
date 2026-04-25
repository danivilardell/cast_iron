"""
Integration tests for the Ethereum ECDSA-nonce blockchain adapter.

Skipped unless the following variables are set (env or .env file):

  ETH_TESTNET_NODE   — HTTP RPC URL (e.g. https://sepolia.infura.io/v3/<key>)
  ETH_PRIVATE_KEY    — 64-hex-char private key for a funded testnet account
  ETH_RECIPIENT      — Any valid address to receive the 1-wei commitment txs
                       (can be the same as the sender)

Example .env:
  ETH_TESTNET_NODE=https://sepolia.infura.io/v3/<key>
  ETH_PRIVATE_KEY=<your key>
  ETH_RECIPIENT=<any address>
"""

import os
import pytest
from dotenv import load_dotenv

load_dotenv()

ETH_NODE      = os.environ.get("ETH_TESTNET_NODE")
ETH_KEY       = os.environ.get("ETH_PRIVATE_KEY")
ETH_RECIPIENT = os.environ.get("ETH_RECIPIENT")

eth_required = pytest.mark.skipif(
    not all([ETH_NODE, ETH_KEY, ETH_RECIPIENT]),
    reason="ETH_TESTNET_NODE, ETH_PRIVATE_KEY, ETH_RECIPIENT not set",
)


@pytest.fixture(scope="module")
def eth_ctc():
    from web3 import Web3
    from ctc.commitment import SHA256Commitment
    from ctc.adapters.eth_blockchain import EthereumNonceBlockchain
    from ctc.ctc import CTC

    w3 = Web3(Web3.HTTPProvider(ETH_NODE))
    chain = EthereumNonceBlockchain(
        w3,
        signing_key_bytes=bytes.fromhex(ETH_KEY),
        recipient=ETH_RECIPIENT,
    )
    instance = CTC(SHA256Commitment(), chain)
    instance.setup()
    return instance


@eth_required
def test_eth_commit_and_open(eth_ctc):
    """Round-trip: commit a message and successfully open it."""
    m = b"vote:Alice"
    t = eth_ctc.commit(m)
    assert eth_ctc.open_local(t) is True


@eth_required
def test_eth_open_tampered_message_fails(eth_ctc):
    t = eth_ctc.commit(b"vote:Alice")
    record = eth_ctc._store[t]
    assert eth_ctc.open(b"vote:Eve", record.r, t) is False


@eth_required
def test_eth_leak_returns_transactions(eth_ctc):
    eth_ctc.commit(b"vote:Bob")
    leaked = eth_ctc.leak()
    assert isinstance(leaked, list)
    assert len(leaked) >= 1


@eth_required
def test_eth_seq_ids_are_ordered(eth_ctc):
    t0 = eth_ctc.commit(b"vote:Carol")
    t1 = eth_ctc.commit(b"vote:Dave")
    assert t0[0] <= t1[0]
