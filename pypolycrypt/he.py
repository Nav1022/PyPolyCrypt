"""Polynomial (RLWE-style) additively homomorphic encryption.

Educational implementation of a BFV-like scheme over the ring
R_q = Z_q[x] / (x^n + 1), written from scratch with NumPy.

    secret key   s  : binary polynomial
    public key   (b, a) with a uniform and b = -(a*s) - e   (e small error)
    encrypt(m)   u binary, e1/e2 small errors
                 ct0 = b*u + e1 + delta*m,   ct1 = a*u + e2,   delta = q/t
    decrypt      v = ct1*s + ct0 = delta*m + (e1 + e2*s - e*u);  m = round(v/delta) mod t

Supported homomorphic operations: ciphertext + ciphertext, ciphertext + plaintext
constant. Multiplication is intentionally not implemented.

NOT FOR PRODUCTION: parameters are tiny (n=256, q=2^15) and give nowhere near
standard security levels. Use a vetted library (Microsoft SEAL, OpenFHE, ...)
for real data.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

import numpy as np

RandBytes = Callable[[int], bytes]


@dataclass(frozen=True)
class Params:
    n: int = 256      # polynomial degree (power of two)
    q: int = 1 << 15  # ciphertext modulus (power of two, <= 2^16)
    t: int = 256      # plaintext modulus (must divide q)

    def __post_init__(self) -> None:
        if self.n & (self.n - 1) or self.n < 2:
            raise ValueError("n must be a power of two")
        if self.q & (self.q - 1) or self.q > 1 << 16:
            raise ValueError("q must be a power of two no larger than 2^16")
        if self.q % self.t or self.t < 2:
            raise ValueError("t must divide q")

    @property
    def delta(self) -> int:
        return self.q // self.t


DEFAULT_PARAMS = Params()


@dataclass(frozen=True)
class PublicKey:
    b: np.ndarray
    a: np.ndarray


@dataclass(frozen=True)
class SecretKey:
    s: np.ndarray


@dataclass(frozen=True)
class Ciphertext:
    ct0: np.ndarray
    ct1: np.ndarray


# --------------------------------------------------------------------------- #
# Sampling. Defaults to os.urandom (a CSPRNG); tests inject a seeded source.
# --------------------------------------------------------------------------- #
def _bits(randbytes: RandBytes, count: int) -> np.ndarray:
    raw = np.frombuffer(randbytes((count + 7) // 8), dtype=np.uint8)
    return np.unpackbits(raw)[:count].astype(np.int64)


def sample_binary(p: Params, randbytes: RandBytes = os.urandom) -> np.ndarray:
    return _bits(randbytes, p.n)


def sample_error(p: Params, randbytes: RandBytes = os.urandom) -> np.ndarray:
    """Centered binomial (eta=1): values in {-1, 0, 1}, variance 1/2."""
    bits = _bits(randbytes, 2 * p.n)
    return bits[: p.n] - bits[p.n:]


def sample_uniform(p: Params, randbytes: RandBytes = os.urandom) -> np.ndarray:
    raw = np.frombuffer(randbytes(2 * p.n), dtype="<u2").astype(np.int64)
    return raw & (p.q - 1)  # q is a power of two, so this is unbiased


# --------------------------------------------------------------------------- #
# Ring arithmetic in Z_q[x]/(x^n + 1)
# --------------------------------------------------------------------------- #
def polymul(x: np.ndarray, y: np.ndarray, p: Params) -> np.ndarray:
    full = np.convolve(x % p.q, y % p.q)  # exact in int64 for these sizes
    padded = np.zeros(2 * p.n, dtype=np.int64)
    padded[: full.size] = full
    return (padded[: p.n] - padded[p.n:]) % p.q  # x^n = -1


def polyadd(x: np.ndarray, y: np.ndarray, p: Params) -> np.ndarray:
    return (x + y) % p.q


# --------------------------------------------------------------------------- #
# Scheme
# --------------------------------------------------------------------------- #
def keygen(p: Params = DEFAULT_PARAMS, randbytes: RandBytes = os.urandom):
    s = sample_binary(p, randbytes)
    a = sample_uniform(p, randbytes)
    e = sample_error(p, randbytes)
    b = (-polymul(a, s, p) - e) % p.q
    return PublicKey(b, a), SecretKey(s)


def encrypt(pk: PublicKey, m: int, p: Params = DEFAULT_PARAMS,
            randbytes: RandBytes = os.urandom) -> Ciphertext:
    if not 0 <= m < p.t:
        raise ValueError(f"plaintext must be in [0, {p.t - 1}]")
    u = sample_binary(p, randbytes)
    e1 = sample_error(p, randbytes)
    e2 = sample_error(p, randbytes)
    ct0 = (polymul(pk.b, u, p) + e1) % p.q
    ct0[0] = (ct0[0] + p.delta * m) % p.q
    ct1 = (polymul(pk.a, u, p) + e2) % p.q
    return Ciphertext(ct0, ct1)


def _phase(sk: SecretKey, ct: Ciphertext, p: Params) -> np.ndarray:
    return (polymul(ct.ct1, sk.s, p) + ct.ct0) % p.q


def decrypt(sk: SecretKey, ct: Ciphertext, p: Params = DEFAULT_PARAMS) -> int:
    c0 = int(_phase(sk, ct, p)[0])
    return ((c0 + p.delta // 2) // p.delta) % p.t


def add_plain(ct: Ciphertext, k: int, p: Params = DEFAULT_PARAMS) -> Ciphertext:
    """Return Enc(m + k mod t) without any key. Adds no noise."""
    ct0 = ct.ct0.copy()
    ct0[0] = (ct0[0] + p.delta * (k % p.t)) % p.q
    return Ciphertext(ct0, ct.ct1.copy())


def add(c1: Ciphertext, c2: Ciphertext, p: Params = DEFAULT_PARAMS) -> Ciphertext:
    """Return Enc(m1 + m2 mod t). Noise of the two inputs adds up."""
    return Ciphertext(polyadd(c1.ct0, c2.ct0, p), polyadd(c1.ct1, c2.ct1, p))


def noise(sk: SecretKey, ct: Ciphertext, expected: int,
          p: Params = DEFAULT_PARAMS) -> int:
    """Centered noise in the constant coefficient (needs the secret key).

    Decryption is correct while |noise| < delta/2.
    """
    c0 = int(_phase(sk, ct, p)[0]) - p.delta * expected
    return (c0 + p.q // 2) % p.q - p.q // 2
