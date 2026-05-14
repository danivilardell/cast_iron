"""
Commitment scheme interface and SHA3-256 instantiation.

Com.Commit(pp, m, r) = SHA3-256(len(pp) || pp || len(m) || m || len(r) || r)

4-byte big-endian length prefixes for each field prevent collisions between
different-length inputs that would otherwise produce the same concatenation.

pp  : bytes  — domain-separation tag (public parameters)
m   : bytes  — message to commit to
r   : bytes  — randomness (blinding factor)
c   : bytes  — 32-byte commitment
"""

from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod


class CommitmentScheme(ABC):
    @abstractmethod
    def setup(self, security_param: int = 128) -> bytes:
        """Return public parameters pp."""

    @abstractmethod
    def commit(self, pp: bytes, m: bytes, r: bytes) -> bytes:
        """Return commitment c = Com(pp, m; r)."""

    @abstractmethod
    def verify(self, pp: bytes, m: bytes, r: bytes, c: bytes) -> bool:
        """Return True iff Com(pp, m; r) == c."""


class SHA3Commitment(CommitmentScheme):
    """c = SHA3-256(len(pp) || pp || len(m) || m || len(r) || r)"""

    _DOMAIN = b"CTC-SHA3-256-v1"

    def setup(self, security_param: int = 128) -> bytes:
        # pp is a fixed domain-separation tag; security_param is unused here
        # but kept in the interface for future schemes.
        return self._DOMAIN

    def commit(self, pp: bytes, m: bytes, r: bytes) -> bytes:
        h = hashlib.sha3_256()
        for field in (pp, m, r):
            h.update(len(field).to_bytes(4, "big"))
            h.update(field)
        return h.digest()

    def verify(self, pp: bytes, m: bytes, r: bytes, c: bytes) -> bool:
        return self.commit(pp, m, r) == c

    @staticmethod
    def sample_randomness(security_param: int = 128) -> bytes:
        """Sample fresh randomness of `security_param` bits."""
        return os.urandom(security_param // 8)


SHA256Commitment = SHA3Commitment
