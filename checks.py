"""Security checks: integrity (SHA-256), CPA-style randomization, timing statistics.

    python checks.py

Exits non-zero if a check fails. Note: these are sanity checks for a teaching
project, not a security proof.
"""

from __future__ import annotations

import math
import secrets
import statistics
import sys
import time

from pypolycrypt import DEFAULT_PARAMS as P
from pypolycrypt import decrypt, encrypt, keygen
from pypolycrypt.codec import sha256_hex, to_blob

pk, sk = keygen(P)


def check_integrity(records: int = 10, tamper_index: int = 3) -> bool:
    print("\n[1] Data integrity (SHA-256 over stored ciphertext)")
    stored = []
    for _ in range(records):
        value = 100 + secrets.randbelow(41)
        blob = to_blob(encrypt(pk, value, P))
        stored.append((value, blob, sha256_hex(blob)))
    blob = bytearray(stored[tamper_index][1])
    blob[10] ^= 0x01  # flip one bit
    stored[tamper_index] = (stored[tamper_index][0], bytes(blob), stored[tamper_index][2])

    ok = True
    print(f"    {'rec':>3} {'value':>5}  status")
    for i, (value, blob, digest) in enumerate(stored):
        intact = sha256_hex(blob) == digest
        print(f"    {i:>3} {value:>5}  {'INTACT' if intact else 'TAMPERED'}")
        ok &= intact == (i != tamper_index)
    print(f"    -> tampering detected exactly where expected: {ok}")
    return ok


def check_cpa(plaintext: int = 120, trials: int = 100) -> bool:
    print(f"\n[2] Randomized encryption: {trials} encryptions of the same plaintext ({plaintext})")
    hashes = {sha256_hex(to_blob(encrypt(pk, plaintext, P))) for _ in range(trials)}
    ok = len(hashes) == trials
    print(f"    unique ciphertexts: {len(hashes)}/{trials} -> {'PASS' if ok else 'FAIL'}")
    print("    (necessary for IND-CPA, not sufficient: it shows encryption is not deterministic)")
    return ok


def _time_ms(fn, samples: int) -> list[float]:
    out = []
    for _ in range(samples):
        start = time.perf_counter()
        fn()
        out.append((time.perf_counter() - start) * 1000)
    return out


def _welch_t(a: list[float], b: list[float]) -> float:
    va, vb = statistics.variance(a), statistics.variance(b)
    return (statistics.mean(a) - statistics.mean(b)) / math.sqrt(va / len(a) + vb / len(b))


def _crop(values: list[float], keep: float = 0.95) -> list[float]:
    """Drop the slowest samples (scheduler noise), as dudect-style tests do."""
    return sorted(values)[: int(len(values) * keep)]


def _interleaved(fn_a, fn_b, samples: int) -> tuple[list[float], list[float]]:
    """Alternate the two classes so clock drift hits both equally."""
    for _ in range(50):  # warm-up
        fn_a(); fn_b()
    a, b = [], []
    for _ in range(samples):
        for fn, out in ((fn_a, a), (fn_b, b)):
            start = time.perf_counter()
            fn()
            out.append((time.perf_counter() - start) * 1000)
    return _crop(a), _crop(b)


def check_timing(samples: int = 1000) -> bool:
    print(f"\n[3] Timing analysis ({samples} samples per class)")
    ct_lo, ct_hi = encrypt(pk, 0, P), encrypt(pk, 255, P)
    enc = _time_ms(lambda: encrypt(pk, 120, P), samples)
    dec = _time_ms(lambda: decrypt(sk, ct_lo, P), samples)
    print(f"    {'op':<8} {'mean ms':>9} {'std ms':>9} {'min ms':>9} {'max ms':>9}")
    for name, v in (("encrypt", enc), ("decrypt", dec)):
        print(f"    {name:<8} {statistics.mean(v):>9.4f} {statistics.stdev(v):>9.4f} {min(v):>9.4f} {max(v):>9.4f}")

    # Fixed-vs-fixed Welch t-test (dudect-style): does run time depend on the plaintext?
    t_enc = _welch_t(*_interleaved(lambda: encrypt(pk, 0, P), lambda: encrypt(pk, 255, P), samples))
    t_dec = _welch_t(*_interleaved(lambda: decrypt(sk, ct_lo, P), lambda: decrypt(sk, ct_hi, P), samples))
    ok = abs(t_dec) < 4.5 and abs(t_enc) < 4.5
    print(f"    Welch t (plaintext 0 vs 255): encrypt {t_enc:+.2f}, decrypt {t_dec:+.2f} "
          f"(|t| < 4.5 -> no evidence of plaintext-dependent timing) -> {'PASS' if ok else 'FAIL'}")
    print("    (pure-Python/NumPy timing is noisy and this says nothing about hardware side channels)")
    return ok


def main() -> int:
    results = {"integrity": check_integrity(), "cpa": check_cpa(), "timing": check_timing()}
    print("\nSummary:", ", ".join(f"{k}={'PASS' if v else 'FAIL'}" for k, v in results.items()))
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
