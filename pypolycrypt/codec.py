"""Ciphertext <-> bytes (compact, no pickle) and SHA-256 integrity hashing."""

from __future__ import annotations

import hashlib
import zlib

import numpy as np

from .he import DEFAULT_PARAMS, Ciphertext, Params


def to_blob(ct: Ciphertext) -> bytes:
    """Serialize as little-endian uint16 (ct0 || ct1), then zlib-compress."""
    raw = np.concatenate([ct.ct0, ct.ct1]).astype("<u2").tobytes()
    return zlib.compress(raw, 9)


def from_blob(blob: bytes, p: Params = DEFAULT_PARAMS) -> Ciphertext:
    raw = zlib.decompress(blob)
    if len(raw) != 4 * p.n:
        raise ValueError("ciphertext blob has the wrong size")
    arr = np.frombuffer(raw, dtype="<u2").astype(np.int64)
    return Ciphertext(arr[: p.n], arr[p.n:])


def sha256_hex(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()
