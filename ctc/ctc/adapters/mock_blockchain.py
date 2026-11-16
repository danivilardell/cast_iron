"""
In-memory mock blockchain for testing and local simulation.

The record at each position is the ECDSA r-component a real chain would carry,
x([c]G); no actual signature is produced.  Positions are integers from 0.
"""

from __future__ import annotations

from ctc.blockchain import Blockchain, SeqId
from ctc.commitment import nonce_point_x


class MockBlockchain(Blockchain):
    def __init__(self) -> None:
        self._ledger: list[int] = []  # index == position

    def post(self, nonce: int) -> SeqId:
        self._ledger.append(nonce_point_x(nonce))
        return len(self._ledger) - 1

    def read(self, t: SeqId) -> int:
        if not isinstance(t, int) or t < 0 or t >= len(self._ledger):
            raise KeyError(f"No record at position {t!r}")
        return self._ledger[t]

    def reset(self) -> None:
        self._ledger.clear()

    def ledger_size(self) -> int:
        return len(self._ledger)
