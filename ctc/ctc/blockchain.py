"""
Timestamping oracle TS (paper Sec. 4), realised by a blockchain.

The paper's TS exposes Post(m) → t and Read() → M.  Here:

  post(nonce) → t   build a single-use, balance-emptying transaction, sign it
                    with ECDSA nonce `nonce` (the CTC commitment c) and Post it.
                    Building/hashing (Htx) is chain-specific, hence done here.
  read(t) → r       TS.Read()[t]: the r-component of the record's ECDSA
                    signature, which is all Open needs (r == x([c]G)).

Positions are t = (round, index) in the paper; on Tron the txid.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

SeqId = int | tuple[int, int] | str


class Blockchain(ABC):
    @abstractmethod
    def post(self, nonce: int) -> SeqId:
        """Sign a transaction with ECDSA nonce `nonce`, post it, return its position t."""

    @abstractmethod
    def read(self, t: SeqId) -> int:
        """Return the signature r of the record at t. Raises KeyError if absent."""
