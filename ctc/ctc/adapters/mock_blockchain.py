"""
In-memory mock blockchain for testing and local simulation.

Embedding: tx["to"] = c[:20].hex()  (first 20 bytes of commitment)
Sequence ids: monotonically increasing integers starting at 0.
"""

from __future__ import annotations

from ctc.blockchain import Blockchain, SeqId, Tx


class MockBlockchain(Blockchain):
    def __init__(self) -> None:
        self._ledger: list[Tx] = []  # index == seq id

    # ------------------------------------------------------------------
    # Blockchain interface
    # ------------------------------------------------------------------

    def embed(self, pp: bytes, c: bytes) -> Tx:
        return {
            "to": c[:20].hex(),
            "value": 1,
        }

    def post(self, tx: Tx) -> Tx:
        seq_id = len(self._ledger)
        posted: Tx = {**tx, "seq": seq_id}
        self._ledger.append(posted)
        return posted

    def seq(self, tx: Tx) -> SeqId:
        return tx["seq"]

    def lookup(self, t: SeqId) -> Tx:
        if not isinstance(t, int) or t < 0 or t >= len(self._ledger):
            raise KeyError(f"No transaction at seq id {t!r}")
        return self._ledger[t]

    def verify_embedding(self, c: bytes, tx: Tx) -> bool:
        return tx["to"] == c[:20].hex()

    # ------------------------------------------------------------------
    # Test helpers
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Clear all state — useful between test cases."""
        self._ledger.clear()

    def ledger_size(self) -> int:
        return len(self._ledger)
