"""
Covert Timestamped Commitment (CTC), paper Sec. 4 / Fig. 2.

  Commit(m; r) → t       TS.Post a balance-emptying tx whose ECDSA nonce is
                         c = H(m ‖ r); return its position t
  Open(m, r, t) → bool   recompute c and check r_sigma == x([c]G) at M[t]

"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ctc import commitment
from ctc.blockchain import Blockchain, SeqId
from ctc.commitment import ResampleError, nonce_point_x


@dataclass
class _LocalRecord:
    """Voter's local state for a single commitment."""
    m: tuple[int, ...]
    r: int


class CTC:
    """
    Parameters
    ----------
    blockchain:
        Blockchain adapter (MockBlockchain, TronNonceBlockchain or
        TronTRC20Blockchain).
    """

    def __init__(self, blockchain: Blockchain) -> None:
        self._chain = blockchain
        self._store: dict[SeqId, _LocalRecord] = {}

    def commit(self, m: Sequence[int], r: int | None = None) -> SeqId:
        """
        Commit to m (field elements, e.g. ``encode_message(pk_i, sigma_reg)``).

        If ``r`` is None, fresh randomness is drawn and resampled in the
        negligible-probability event that the nonce is unusable (nothing has
        been posted at that point).  If ``r`` is given and unusable,
        :class:`ResampleError` is raised.  Returns the position t; (m, r) are
        stored locally.
        """
        m = tuple(m)
        if r is None:
            while True:
                r = commitment.sample_randomness()
                try:
                    c = commitment.commit(m, r)
                    break
                except ResampleError:
                    continue
        else:
            c = commitment.commit(m, r)

        t = self._chain.post(c)
        self._store[t] = _LocalRecord(m=m, r=r)
        return t

    def open(self, m: Sequence[int], r: int, t: SeqId) -> bool:
        """True iff the record at position t embeds Com(m; r)."""
        try:
            c = commitment.commit(m, r)
        except (ResampleError, ValueError):
            return False
        try:
            sig_r = self._chain.read(t)
        except KeyError:
            return False
        return sig_r == nonce_point_x(c)

    def get_opening(self, t: SeqId) -> tuple[tuple[int, ...], int]:
        """Return (m, r) for position t — the data the circuit/tallier opens."""
        record = self._store.get(t)
        if record is None:
            raise KeyError(f"No local record for seq id {t!r}.")
        return record.m, record.r

    def open_local(self, t: SeqId) -> bool:
        """Open the commitment at t using locally stored (m, r)."""
        m, r = self.get_opening(t)
        return self.open(m, r, t)
