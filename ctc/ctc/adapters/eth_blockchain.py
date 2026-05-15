"""
Ethereum blockchain adapter for the CTC protocol.

ECDSA-nonce embedding:
  - Commitment c is embedded as the ECDSA signature nonce k in a minimal
    ETH transfer (1 wei to a configurable recipient address).
    - k = first SHA3-256 iteration of c that produces a nonzero scalar mod n.
  - On-chain, the signature r = (k*G).x mod n encodes c invisibly; an
    observer cannot distinguish this from any other transaction.
  - At opening, the verifier (tallier) recomputes k from c and checks
    that the on-chain r equals (k*G).x mod n.

Anonymity set = all transactions in a configurable block window.

Key compromise note:
  Revealing k (implicit in opening c) allows recovery of the signing
  private key d from the public (r, s, z). Mitigated by:
    (a) opening is encrypted to the tallier only;
    (b) the signing address should hold only gas funds — the natural
        pattern is a "rotating address" where this transaction sweeps
        all funds to a fresh key, leaving the old address empty.

Usage:
    from web3 import Web3
    from ctc.adapters.eth_blockchain import EthereumNonceBlockchain

    w3 = Web3(Web3.HTTPProvider("https://sepolia.infura.io/v3/<key>"))
    chain = EthereumNonceBlockchain(
        w3,
        signing_key_bytes=bytes.fromhex("<64-hex private key>"),
        recipient="0x<any address>",
    )
"""

from __future__ import annotations

import hashlib
from typing import Any

import rlp
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_string
from eth_account import Account
from eth_hash.auto import keccak
from web3 import Web3

from ctc.blockchain import Blockchain, SeqId, Tx

_N = SECP256k1.order
_G = SECP256k1.generator


def _commitment_to_k(c: bytes) -> int:
    """Derive a nonzero ECDSA nonce k from commitment bytes."""
    digest = c
    while True:
        k = int.from_bytes(hashlib.sha3_256(digest).digest(), "big") % _N
        if k != 0:
            return k
        digest = hashlib.sha3_256(digest).digest()


def _i2b(n: int) -> bytes:
    """Encode a non-negative integer as minimal big-endian bytes (RLP convention)."""
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _eip1559_fields(
    chain_id: int,
    nonce: int,
    max_priority_fee: int,
    max_fee: int,
    gas: int,
    to: bytes,
    value: int,
    data: bytes,
) -> list:
    return [_i2b(chain_id), _i2b(nonce), _i2b(max_priority_fee), _i2b(max_fee), _i2b(gas), to, _i2b(value), data, []]


def _eip1559_signing_hash(*args) -> bytes:
    """keccak256(0x02 || RLP([chain_id, nonce, max_priority_fee, max_fee, gas, to, value, data, access_list]))"""
    return keccak(b"\x02" + rlp.encode(_eip1559_fields(*args)))


def _encode_signed_eip1559(*args, y_parity: int, r: int, s: int) -> bytes:
    """Encode a fully signed EIP-1559 transaction as raw bytes."""
    return b"\x02" + rlp.encode(_eip1559_fields(*args) + [_i2b(y_parity), _i2b(r), _i2b(s)])


def _extract_r(raw_tx: Any) -> int:
    """Extract the r component of the ECDSA signature from a web3 tx dict."""
    r = raw_tx["r"]
    if isinstance(r, int):
        return r
    return int.from_bytes(bytes(r), "big")


class EthereumNonceBlockchain(Blockchain):
    """
    Blockchain adapter backed by a live Ethereum node via web3.py.

    Parameters
    ----------
    w3:
        A Web3 instance connected to the desired network.
    signing_key_bytes:
        32-byte raw private key. Should be a minimal-funds burner key;
        opening a commitment to the tallier reveals this key.
    recipient:
        Address that receives the 1-wei commitment transaction.
        Can be the sender's own address (self-transfer) or any other address.
    poll_interval:
        Seconds between confirmation polls after broadcasting.
    """

    def __init__(
        self,
        w3: Web3,
        signing_key_bytes: bytes,
        recipient: str,
        poll_interval: float = 2.0,
    ) -> None:
        self._w3 = w3
        self._sk = SigningKey.from_string(signing_key_bytes, curve=SECP256k1)
        self._address = Account.from_key(signing_key_bytes).address
        self._recipient_bytes = bytes.fromhex(Web3.to_checksum_address(recipient)[2:])
        self._chain_id = w3.eth.chain_id
        self._poll_interval = poll_interval

    # ------------------------------------------------------------------
    # Blockchain interface
    # ------------------------------------------------------------------

    def embed(self, pp: bytes, c: bytes) -> Tx:
        k = _commitment_to_k(c)
        return {"_k": k}

    def post(self, tx: Tx) -> Tx:
        """Sign with commitment-derived nonce k and broadcast; wait for confirmation."""
        k = tx.pop("_k")

        account_nonce = self._w3.eth.get_transaction_count(self._address)
        latest = self._w3.eth.get_block("latest")
        base_fee = latest["baseFeePerGas"]
        max_priority_fee = self._w3.eth.max_priority_fee
        max_fee = base_fee * 2 + max_priority_fee
        tx_args = (self._chain_id, account_nonce, max_priority_fee, max_fee, 21000, self._recipient_bytes, 1, b"")

        signing_hash = _eip1559_signing_hash(*tx_args)

        sig_bytes = self._sk.sign_digest(signing_hash, sigencode=sigencode_string, k=k)
        r_int = int.from_bytes(sig_bytes[:32], "big")
        s_int = int.from_bytes(sig_bytes[32:], "big")

        R = k * _G
        y_parity = R.y() % 2

        if s_int > _N // 2:
            s_int = _N - s_int
            y_parity ^= 1

        raw_tx = _encode_signed_eip1559(*tx_args, y_parity=y_parity, r=r_int, s=s_int)
        txhash = self._w3.eth.send_raw_transaction(raw_tx)

        receipt = self._w3.eth.wait_for_transaction_receipt(
            txhash, poll_latency=self._poll_interval
        )
        block_num = receipt["blockNumber"]
        block = self._w3.eth.get_block(block_num, full_transactions=True)
        tx_index = next(
            i for i, t in enumerate(block["transactions"])
            if t["hash"] == txhash
        )

        return {**tx, "txhash": txhash.hex(), "sig_r": r_int, "seq": (block_num, tx_index)}

    def seq(self, tx: Tx) -> SeqId:
        return tx["seq"]

    def lookup(self, t: SeqId) -> Tx:
        if isinstance(t, str):
            raw = self._w3.eth.get_transaction(t)
        elif isinstance(t, tuple) and len(t) == 2:
            block_num, tx_index = t
            block = self._w3.eth.get_block(block_num, full_transactions=True)
            raw = block["transactions"][tx_index]
        else:
            raise ValueError(f"Unsupported seq id format: {t!r}")

        return {
            "txhash": raw["hash"].hex(),
            "sig_r": _extract_r(raw),
            "seq": t,
        }

    def verify_embedding(self, c: bytes, tx: Tx) -> bool:
        """Check that the commitment c is embedded as the nonce in tx's signature."""
        k = _commitment_to_k(c)
        R = k * _G
        expected_r = R.x() % _N
        return tx["sig_r"] == expected_r
