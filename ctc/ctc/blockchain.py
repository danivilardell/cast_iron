"""
Abstract Blockchain interface for the CTC protocol.

Maps directly to the paper's blockchain API:
  B.Embed(pp, c)         → tx
  B.Post(tx)             → (posts to chain via anonymous channel)
  B.Seq(tx)              → t   (sequence identifier)
  B.Lookup(t)            → tx
  B.Filter(pp)           → [tx, ...]  (anonymity set)
  B.VerifyEmbedding(c, tx) → bool

A "transaction" is a plain dict; adapters add chain-specific fields.
The minimum required field after posting is "seq".
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

Tx = dict[str, Any]
SeqId = int | tuple[int, int] | str


class Blockchain(ABC):
    @abstractmethod
    def embed(self, pp: bytes, c: bytes) -> Tx:
        """Encode commitment c as a transaction object (not yet posted)."""

    @abstractmethod
    def post(self, tx: Tx) -> Tx:
        """
        Submit tx to the chain via an anonymous channel.
        Returns the tx enriched with its assigned seq id.
        """

    @abstractmethod
    def seq(self, tx: Tx) -> SeqId:
        """Return the sequence identifier of a confirmed transaction."""

    @abstractmethod
    def lookup(self, t: SeqId) -> Tx:
        """Retrieve a transaction by its sequence identifier."""

    @abstractmethod
    def verify_embedding(self, c: bytes, tx: Tx) -> bool:
        """Return True iff commitment c is embedded in tx."""
