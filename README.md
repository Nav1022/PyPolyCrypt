# PyPolyCrypt - Polynomial Homomorphic Encryption for Databases

![tests](https://github.com/Nav1022/PyPolyCrypt/actions/workflows/ci.yml/badge.svg)

PyPolyCrypt is a from-scratch, **additively homomorphic encryption** scheme built on polynomial ring
arithmetic (`Z_q[x]/(x^n + 1)`), wired into a Python + MySQL workflow. It lets a database operator
apply a salary raise to **encrypted** records without ever seeing the original or resulting value.
It also ships a security-check suite and a benchmark against AES-256 and TenSEAL (CKKS).

> **Educational project - not production cryptography.** Parameters are deliberately tiny
> (see [Limitations](#limitations)). Use Microsoft SEAL / OpenFHE for real data.

## How it works

```
 Data owner (secret key)                 DB operator (no key)                 MySQL
 -----------------------                 --------------------                 -----
 encrypt(value) --pickle-free blob-----> store BLOB + SHA-256 --------------> data_table
                                         raise --amount 50:
                                           ct0[0] += delta * 50  (no key) --> updated BLOB + new hash
 decrypt(blob) <---verify hash first---- fetch BLOB
```

| Step | Definition |
|------|------------|
| Keygen | `s` binary; `a` uniform in `Z_q`; `e` small error; `pk = (b, a)`, `b = -(a*s) - e` |
| Encrypt `m` | `u` binary, `e1, e2` small; `ct0 = b*u + e1 + delta*m`, `ct1 = a*u + e2`, `delta = q/t` |
| Decrypt | `v = ct1*s + ct0 = delta*m + noise`; `m = round(v / delta) mod t` |
| Add plaintext `k` | `ct0[0] += delta*k` - needs no key, adds **no** noise |
| Add ciphertexts | component-wise add - noise of both inputs adds up |

Default parameters: `n = 256`, `q = 2^15 = 32768`, `t = 256` (plaintexts `0..255`, results wrap mod 256).

## Quick start

```bash
git clone https://github.com/Nav1022/PyPolyCrypt.git && cd PyPolyCrypt
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# zero-setup demo with SQLite
export DB_BACKEND=sqlite
python main.py setup            # schema + 20 demo "salaries" + keys in ./keys
python main.py encrypt          # encrypt every row, store BLOB + SHA-256
python main.py raise --amount 50
python main.py decrypt          # verify hashes, decrypt, show original vs decrypted
```

Sample output:

```
  id  original  decrypted  diff  integrity
   1       114        164    50  OK
   2       131        181    50  OK
```

### Using MySQL

```bash
export DB_BACKEND=mysql DB_HOST=localhost DB_USER=root DB_PASSWORD='...' DB_NAME=project_data
python main.py setup
```

Credentials are read from the environment only (see `.env.example`); nothing is hard-coded.
The reference schema is in `project_data.sql`. The `number_data` plaintext column exists only so the
demo can show original vs decrypted - drop it in any real use.

## Security checks

```bash
python checks.py
```

1. **Integrity** - SHA-256 of each stored ciphertext; a single flipped bit is detected.
2. **Randomized encryption** - 100 encryptions of the same plaintext give 100 distinct ciphertexts
   (necessary for IND-CPA, not a proof of it).
3. **Timing** - mean/std of encrypt and decrypt, plus a fixed-vs-fixed Welch t-test
   (plaintext 0 vs 255, interleaved, dudect-style threshold `|t| < 4.5`). This is a software-level sanity
   check only; it says nothing about hardware side channels.

## Tests and benchmark

```bash
pip install pytest && pytest -q          # 19 tests: correctness of every plaintext, noise, ring math, DB flow
pip install -r requirements-bench.txt
python benchmark_combined.py --records 300
```

Results from one run (CPython 3.12, single core, 300 records; yours will differ):

| Method | Encrypt (ms) | Decrypt (ms) | Ciphertext (bytes) |
|--------|-------------:|-------------:|-------------------:|
| PyPolyCrypt | 0.234 | 0.089 | 1,035 |
| AES-256-CBC | 0.013 | 0.013 | 16 |
| TenSEAL (CKKS, N=8192) | 8.142 | 2.418 | 331,393 |

Plots: `docs/benchmark.png`, raw data: `docs/benchmark_results.csv`.
This is **not** an apples-to-apples comparison: TenSEAL uses far larger parameters (a 128-bit-security
target, SIMD batching, floating-point CKKS) than this toy scheme, and AES is not homomorphic at all.

## Limitations

- **Toy parameters.** `n = 256, q = 2^15` is far below standard security levels (>= 128-bit needs
  roughly `n >= 1024` with a much larger `q`). Do not protect real data with it.
- **Only addition.** No ciphertext multiplication, no relinearization, no bootstrapping.
- **Noise budget.** Fresh ciphertexts have noise std ~11 against a failure threshold of `delta/2 = 64`
  (failure probability ~1e-8). Adding plaintext constants is free, but each ciphertext + ciphertext
  addition adds variance: keep to a handful of them (about 4 inputs gives ~0.5% decryption failures,
  about 8 gives ~5%).
- **Small plaintext space.** Integers `0..255`; sums wrap modulo 256. No negatives or decimals.
- **Integrity != authentication.** A SHA-256 hash stored next to the data detects accidental
  corruption; an attacker who can rewrite both blob and hash is not stopped (use an HMAC with a
  separate key or authenticated encryption for that).
- **Keys are stored in `./keys` as plain files** - fine for a demo, not for production (use a KMS/HSM).

## Project layout

```
pypolycrypt/he.py      keygen / encrypt / decrypt / add / add_plain / noise, ring arithmetic
pypolycrypt/codec.py   ciphertext <-> compressed bytes (no pickle), SHA-256
pypolycrypt/db.py      MySQL and SQLite storage layer
pypolycrypt/keys.py    key files
main.py                setup / encrypt / raise / decrypt CLI
checks.py              integrity, randomization and timing checks
benchmark_combined.py  PyPolyCrypt vs AES-256 vs TenSEAL, CSV + chart
tests/                 pytest suite
```

## Differences from the original design

Compared with the original B.Tech design, this implementation uses a small centered-binomial error
(the original's wider Gaussian noise made decryption fail roughly 5% of the time at these parameters),
a compact uint16 + zlib ciphertext format instead of `pickle` (unsafe to load from untrusted storage),
a CSPRNG (`os.urandom`) for all sampling, environment-based DB credentials, and a SQLite backend.

## Credits

The design follows the B.Tech project report *PyPolyCrypt (Python Polynomial Cryptography)* by
Samyak Jain, Akshat Kumar Gupta and Rohit Shrivastava (guide: Shrreyansh Mishra), JECRC University,
2025-26. This repository is an independent re-implementation of that design.

## License

MIT
