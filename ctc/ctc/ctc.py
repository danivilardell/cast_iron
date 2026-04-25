"""
CTC protocol: Π_CTC^Com(B)

Implements the real CTC protocol from the paper:
  Setup  → pp
  Commit(m) → t          (stores (m, r, t) locally; posts tx anonymously)
  Leak()    → [tx, ...]  (adversary's view: B.Filter(pp))
  Open(m, r, t) → bool  (verify commitment at position t)

The CTC is instantiated by injecting a CommitmentScheme and a Blockchain.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ctc.blockchain import Blockchain, SeqId, Tx
from ctc.commitment import CommitmentScheme


@dataclass
class _LocalRecord:
    """Voter's local state for a single commitment."""
    m: bytes
    r: bytes


class CTC:
    """
    Covert Timestamped Commitment protocol.

    Parameters
    ----------
    commitment_scheme:
        Instantiated CommitmentScheme (e.g. SHA256Commitment()).
    blockchain:
        Instantiated Blockchain adapter (MockBlockchain or EthereumNonceBlockchain).
    security_param:
        Security parameter λ in bits; governs randomness length.
    """

    def __init__(
        self,
        commitment_scheme: CommitmentScheme,
        blockchain: Blockchain,
        security_param: int = 128,
    ) -> None:
        self._com = commitment_scheme
        self._chain = blockchain
        self._security_param = security_param
        self._pp: bytes | None = None
        # Local storage: seq_id → LocalRecord
        self._store: dict[SeqId, _LocalRecord] = {}

    # ------------------------------------------------------------------
    # Protocol operations
    # ------------------------------------------------------------------

    def setup(self) -> bytes:
        """
        Generate and broadcast public parameters.

        In the real protocol pp is broadcast to all parties; here we simply
        store it locally and return it so the caller can share it.
        """
        self._pp = self._com.setup(self._security_param)
        return self._pp

    def commit(self, m: bytes) -> SeqId:
        """
        Commit to message m.

        1. Sample fresh randomness r.
        2. Compute c = Com(pp, m; r).
        3. Embed c in a blockchain transaction and post anonymously.
        4. Record (m, r, t) in local storage.
        5. Return sequence id t.
        """
        if self._pp is None:
            raise RuntimeError("Call setup() before commit().")

        r = os.urandom(self._security_param // 8)
        c = self._com.commit(self._pp, m, r)

        tx = self._chain.embed(self._pp, c)
        tx = self._chain.post(tx)
        t = self._chain.seq(tx)

        self._store[t] = _LocalRecord(m=m, r=r)
        return t

    def leak(self) -> list[Tx]:
        """
        Return the adversary's view: all transactions in the anonymity set.

        Corresponds to B.Filter(pp) in the real protocol.
        """
        if self._pp is None:
            raise RuntimeError("Call setup() before leak().")
        return self._chain.filter(self._pp)

    def open(self, m: bytes, r: bytes, t: SeqId) -> bool:
        """
        Verify a commitment.

        Recomputes c = Com(pp, m; r), retrieves the transaction at position t,
        and checks that the embedded commitment matches.

        Returns True iff the commitment is valid.
        """
        if self._pp is None:
            raise RuntimeError("Call setup() before open().")

        c = self._com.commit(self._pp, m, r)

        try:
            tx = self._chain.lookup(t)
        except KeyError:
            return False

        return self._chain.verify_embedding(c, tx)

    # ------------------------------------------------------------------
    # Convenience: open using locally stored (m, r) for a given t
    # ------------------------------------------------------------------

    def open_local(self, t: SeqId) -> bool:
        """Open the commitment at t using locally stored (m, r)."""
        record = self._store.get(t)
        if record is None:
            raise KeyError(f"No local record for seq id {t!r}.")
        return self.open(record.m, record.r, t)

    @property
    def pp(self) -> bytes | None:
        """Public parameters (None until setup() is called)."""
        return self._pp
