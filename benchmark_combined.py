"""Benchmark: PyPolyCrypt vs AES-256-CBC (PyCryptodome) vs TenSEAL CKKS.

    pip install -r requirements-bench.txt
    python benchmark_combined.py --records 200

Writes docs/benchmark_results.csv and docs/benchmark.png.
Methods whose library is missing are skipped.
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics
import time
from pathlib import Path

from pypolycrypt import DEFAULT_PARAMS as P
from pypolycrypt import decrypt, encrypt, keygen
from pypolycrypt.codec import from_blob, to_blob

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    AES = None
try:
    import tenseal as ts
except ImportError:
    ts = None


def timed(fn, *args):
    start = time.perf_counter()
    result = fn(*args)
    return result, (time.perf_counter() - start) * 1000


def bench_poly(values):
    pk, sk = keygen(P)
    enc, dec, size = [], [], []
    for v in values:
        blob, t1 = timed(lambda: to_blob(encrypt(pk, v, P)))
        out, t2 = timed(lambda: decrypt(sk, from_blob(blob, P), P))
        assert out == v
        enc.append(t1); dec.append(t2); size.append(len(blob))
    return enc, dec, size


def bench_aes(values):
    key, iv = os.urandom(32), os.urandom(16)
    enc, dec, size = [], [], []
    for v in values:
        ct, t1 = timed(lambda: AES.new(key, AES.MODE_CBC, iv).encrypt(pad(str(v).encode(), 16)))
        pt, t2 = timed(lambda: unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16))
        assert int(pt) == v
        enc.append(t1); dec.append(t2); size.append(len(ct))
    return enc, dec, size


def bench_tenseal(values):
    ctx = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    ctx.global_scale = 2 ** 40
    enc, dec, size = [], [], []
    for v in values:
        blob, t1 = timed(lambda: ts.ckks_vector(ctx, [float(v)]).serialize())
        out, t2 = timed(lambda: ts.ckks_vector_from(ctx, blob).decrypt()[0])
        assert abs(out - v) < 0.01
        enc.append(t1); dec.append(t2); size.append(len(blob))
    return enc, dec, size


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=int, default=200)
    ap.add_argument("--out", type=Path, default=Path("docs"))
    args = ap.parse_args()
    values = [100 + (i * 7) % 41 for i in range(args.records)]

    methods = {"PyPolyCrypt": bench_poly}
    if AES:
        methods["AES-256-CBC"] = bench_aes
    if ts:
        methods["TenSEAL (CKKS)"] = bench_tenseal

    results = {}
    for name, fn in methods.items():
        fn(values[:5])  # warm-up
        results[name] = fn(values)

    print(f"{'method':<16} {'enc mean ms':>12} {'enc std':>9} {'dec mean ms':>12} {'dec std':>9} {'bytes':>9}")
    args.out.mkdir(exist_ok=True)
    with open(args.out / "benchmark_results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method", "enc_mean_ms", "enc_std_ms", "dec_mean_ms", "dec_std_ms", "mean_bytes"])
        for name, (enc, dec, size) in results.items():
            row = [name, statistics.mean(enc), statistics.stdev(enc),
                   statistics.mean(dec), statistics.stdev(dec), statistics.mean(size)]
            w.writerow(row)
            print(f"{name:<16} {row[1]:>12.4f} {row[2]:>9.4f} {row[3]:>12.4f} {row[4]:>9.4f} {row[5]:>9.0f}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    names = list(results)
    fig, axes = plt.subplots(1, 3, figsize=(14, 4))
    for ax, (title, idx, unit, scale) in zip(axes, [("Mean encryption time", 0, "ms", 1),
                                                    ("Mean decryption time", 1, "ms", 1),
                                                    ("Mean ciphertext size", 2, "bytes", 1)]):
        vals = [statistics.mean(results[n][idx]) for n in names]
        bars = ax.bar(names, vals, color=["#2E86AB", "#A23B72", "#F18F01"][: len(names)])
        ax.set_yscale("log"); ax.set_title(title); ax.set_ylabel(f"{unit} (log scale)")
        ax.bar_label(bars, labels=[f"{v:.3g}" for v in vals], padding=2)
        ax.tick_params(axis="x", labelrotation=15)
    fig.tight_layout()
    fig.savefig(args.out / "benchmark.png", dpi=150)
    print(f"Saved {args.out / 'benchmark_results.csv'} and {args.out / 'benchmark.png'}")


if __name__ == "__main__":
    main()
