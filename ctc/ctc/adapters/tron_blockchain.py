"""
Tron blockchain adapters for the CTC protocol.

ECDSA-nonce embedding (shared by both adapters):
  - The Poseidon2 commitment c = H(m || r) (see ctc.commitment) IS the ECDSA
    signature nonce, used directly.
  - The transaction is built, signed with nonce c, and broadcast through TronPy.
  - At opening, the verifier recomputes c from (m, r) and checks that the
    on-chain signature's r value equals x(c*G).

Two adapters are provided:
  TronNonceBlockchain  — TRX transfer 
  TronTRC20Blockchain  — TRC-20 transfer

Rotating-address pattern (paper Sec. 4.1):
  Opening reveals the signing key, so the caller must use a single-use key and
  set amount to that address's full balance, so the commitment transaction
  sweeps all funds to the recipient. The adapter does NOT generate keys, fund
  them, or compute the balance; that is the caller's responsibility.
"""

# pyright: reportMissingImports=false

from __future__ import annotations

from typing import TYPE_CHECKING

from ctc.blockchain import Blockchain, SeqId

if TYPE_CHECKING:
    from tronpy import Tron


def _secp256k1() -> tuple[int, object]:
    from ecdsa import SECP256k1

    return SECP256k1.order, SECP256k1.generator


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


class _TronBase(Blockchain):
    """Shared constructor and protocol methods for Tron adapters."""

    def __init__(
        self,
        client: "Tron",
        signing_key_bytes: bytes,
        recipient: str,
    ) -> None:
        self._client = client
        self._signing_key_bytes = signing_key_bytes
        from tronpy.keys import PrivateKey, to_base58check_address

        self._address = PrivateKey(signing_key_bytes).public_key.to_base58check_address()
        self._recipient = to_base58check_address(recipient)

    def read(self, t: SeqId) -> int:
        if not isinstance(t, str):
            raise ValueError(f"Unsupported seq id format for Tron: {t!r}")
        signatures = self._client.get_transaction(t).get("signature", [])
        if not signatures:
            raise KeyError(f"No signature on transaction {t!r}")
        sig_hex = signatures[0]
        if sig_hex.startswith("0x"):
            sig_hex = sig_hex[2:]
        from tronpy.keys import Signature

        return Signature.fromhex(sig_hex).r


class TronNonceBlockchain(_TronBase):
    """
    Tron adapter that posts a TRX transfer.

    Parameters
    ----------
    amount:
        Transfer value in SUN (1 TRX = 1 000 000 SUN). For the rotating-address
        pattern, set this to the signing address's full TRX balance.
    """

    def __init__(
        self,
        client: "Tron",
        signing_key_bytes: bytes,
        recipient: str,
        amount: int = 1,
    ) -> None:
        super().__init__(client, signing_key_bytes, recipient)
        self._amount = amount

    def post(self, nonce: int) -> SeqId:
        k = nonce
        ref_block_id = self._client.get_latest_solid_block_id()
        txn = self._client.trx.transfer(self._address, self._recipient, self._amount).build(
            offline=True, ref_block_id=ref_block_id
        )
        txn = type(txn).from_json(txn.to_json(), client=self._client)

        signature_hex = _signature_hex_from_k(
            self._signing_key_bytes, bytes.fromhex(txn.txid), k
        )
        txn.set_signature([signature_hex])
        txn.broadcast().wait()

        return txn.txid


class TronTRC20Blockchain(_TronBase):
    """
    Tron adapter that posts a TRC-20 transfer (e.g. USDT).

    Parameters
    ----------
    contract_address:
        TRC-20 contract in base58check format.
        USDT mainnet : TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
        Set via env var TRON_TRC20_CONTRACT or pass directly.
    amount:
        Transfer value in the token's smallest unit (USDT has 6 decimals, so
        1_000_000 = 1 USDT). For the rotating-address pattern, set this to the
        signing address's full token balance.
    fee_limit:
        Maximum TRX (in sun) to spend on Energy. 
    """

    def __init__(
        self,
        client: "Tron",
        signing_key_bytes: bytes,
        recipient: str,
        contract_address: str,
        amount: int = 1,
        fee_limit: int = 30_000_000,
    ) -> None:
        super().__init__(client, signing_key_bytes, recipient)
        self._contract_address = contract_address
        self._amount = amount
        self._fee_limit = fee_limit

    def post(self, nonce: int) -> SeqId:
        k = nonce
        contract = self._client.get_contract(self._contract_address)
        txn = (
            contract.functions.transfer(self._recipient, self._amount)
            .with_owner(self._address)
            .fee_limit(self._fee_limit)
            .build()
        )

        signature_hex = _signature_hex_from_k(
            self._signing_key_bytes, bytes.fromhex(txn.txid), k
        )
        txn.set_signature([signature_hex])
        txn.broadcast().wait()

        return txn.txid