"""
Tron blockchain adapter for the CTC protocol.

ECDSA-nonce embedding:
  - Commitment c is embedded as the ECDSA signature nonce k in a minimal
    TRX transfer (1 SUN to a configurable recipient address).
  - k = first SHA3-256 iteration of c that produces a nonzero scalar mod n.
  - The transaction is built offline, signed with the commitment-derived nonce,
    and then broadcast through TronPy.
  - At opening, the verifier recomputes k from c and checks that the on-chain
    signature's r value equals (k*G).x mod n.

Anonymity set = all transactions in a configurable block window.
"""

# pyright: reportMissingImports=false

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from ctc.blockchain import Blockchain, SeqId, Tx

if TYPE_CHECKING:
    from tronpy import Tron


def _secp256k1() -> tuple[int, object]:
    from ecdsa import SECP256k1

    return SECP256k1.order, SECP256k1.generator


def _commitment_to_k(c: bytes) -> int:
    """Derive a nonzero ECDSA nonce k from commitment bytes."""
    n, _ = _secp256k1()
    digest = c
    while True:
        k = int.from_bytes(hashlib.sha3_256(digest).digest(), "big") % n
        if k != 0:
            return k
        digest = hashlib.sha3_256(digest).digest()


def _signature_hex_from_k(signing_key_bytes: bytes, message_hash: bytes, k: int) -> str:
    """Sign a digest with an explicit nonce and return TronPy-compatible hex."""
    from ecdsa import SECP256k1, SigningKey
    from ecdsa.util import sigencode_string
    from tronpy.keys import Signature

    n, generator = _secp256k1()
    signing_key = SigningKey.from_string(signing_key_bytes, curve=SECP256k1)
    signature_bytes = signing_key.sign_digest(message_hash, sigencode=sigencode_string, k=k)
    r = int.from_bytes(signature_bytes[:32], "big")
    s = int.from_bytes(signature_bytes[32:], "big")
    point = k * generator
    recid = point.y() & 1

    if s > n // 2:
        s = n - s
        recid ^= 1

    return Signature(r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([recid])).hex()


class TronNonceBlockchain(Blockchain):
    """
    Blockchain adapter backed by a live Tron node via TronPy.

    Parameters
    ----------
    client:
        A TronPy client connected to the desired network.
    signing_key_bytes:
        32-byte raw private key. Should be a minimal-funds burner key.
    recipient:
        Address that receives the 1-SUN commitment transaction.
    block_window:
        Number of recent blocks to scan in filter().
    """

    def __init__(
        self,
        client: "Tron",
        signing_key_bytes: bytes,
        recipient: str,
        block_window: int = 20,
    ) -> None:
        self._client = client
        from tronpy.keys import PrivateKey, to_base58check_address

        self._signing_key_bytes = signing_key_bytes
        self._address = PrivateKey(signing_key_bytes).public_key.to_base58check_address()
        self._recipient = to_base58check_address(recipient)
        self._block_window = block_window

    def embed(self, pp: bytes, c: bytes) -> Tx:
        k = _commitment_to_k(c)
        return {"_k": k}

    def post(self, tx: Tx) -> Tx:
        k = tx.pop("_k")
        ref_block_id = self._client.get_latest_solid_block_id()
        txn = self._client.trx.transfer(self._address, self._recipient, 1).build(offline=True, ref_block_id=ref_block_id)
        txn = type(txn).from_json(txn.to_json(), client=self._client)

        signature_hex = _signature_hex_from_k(self._signing_key_bytes, bytes.fromhex(txn.txid), k)
        txn.set_signature([signature_hex])
        broadcast_result = txn.broadcast().wait()

        return {
            **tx,
            "txid": txn.txid,
            "signature": txn.to_json()["signature"],
            "seq": txn.txid,
            "broadcast": broadcast_result,
        }

    def seq(self, tx: Tx) -> SeqId:
        return tx["seq"]

    def lookup(self, t: SeqId) -> Tx:
        if not isinstance(t, str):
            raise ValueError(f"Unsupported seq id format for Tron: {t!r}")

        raw = self._client.get_transaction(t)
        return {
            "txid": raw["txID"],
            "signature": raw.get("signature", []),
            "seq": t,
        }

    def filter(self, pp: bytes) -> list[Tx]:
        latest = self._client.get_latest_block_number()
        results: list[Tx] = []
        for block_num in range(max(0, latest - self._block_window), latest + 1):
            block = self._client.get_block(block_num)
            for raw_tx in block.get("transactions", []):
                results.append({"txid": raw_tx["txID"], "signature": raw_tx.get("signature", []), "seq": raw_tx["txID"]})
        return results

    def verify_embedding(self, c: bytes, tx: Tx) -> bool:
        k = _commitment_to_k(c)
        n, generator = _secp256k1()
        expected_r = (k * generator).x() % n
        signatures = tx.get("signature", [])
        if not signatures:
            return False
        signature_hex = signatures[0][2:] if signatures[0].startswith("0x") else signatures[0]
        from tronpy.keys import Signature

        return Signature.fromhex(signature_hex).r == expected_r