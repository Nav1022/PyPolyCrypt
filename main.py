"""PyPolyCrypt command-line workflow.

    python main.py setup            create schema, seed demo data, generate keys
    python main.py encrypt          encrypt every row, store compressed ciphertext + SHA-256
    python main.py raise --amount 50   add a raise to every ciphertext (public parameters only)
    python main.py decrypt          verify hashes, then decrypt with the secret key

Backend: DB_BACKEND=mysql (default) or DB_BACKEND=sqlite. See README.
"""

from __future__ import annotations

import argparse
import sys

from pypolycrypt import DEFAULT_PARAMS as P
from pypolycrypt import add_plain, decrypt, encrypt, keygen
from pypolycrypt.codec import from_blob, sha256_hex, to_blob
from pypolycrypt.db import Database
from pypolycrypt.keys import KEY_DIR, load_public_key, load_secret_key, save_keys


def cmd_setup(db: Database, _args) -> None:
    db.init_schema()
    added = db.seed_demo()
    print(f"Schema ready; {added} demo rows inserted." if added else "Schema ready; table already has data.")
    if (KEY_DIR / "secret_key.npz").exists():
        print(f"Keys already exist in ./{KEY_DIR}; keeping them.")
    else:
        pk, sk = keygen(P)
        save_keys(pk, sk)
        print(f"Keys written to ./{KEY_DIR} (keep secret_key.npz private).")


def cmd_encrypt(db: Database, _args) -> None:
    pk = load_public_key()
    rows = db.plain_rows()
    for data_id, value in rows:
        blob = to_blob(encrypt(pk, value, P))
        db.save_ciphertext(data_id, blob, sha256_hex(blob))
    db.commit()
    print(f"Encrypted {len(rows)} rows (n={P.n}, q={P.q}, t={P.t}).")


def cmd_raise(db: Database, args) -> None:
    """Runs as the untrusted DB operator: needs no key, never sees plaintext."""
    updated = 0
    for data_id, _plain, blob, digest in db.encrypted_rows():
        if blob is None:
            continue
        blob = bytes(blob)
        if sha256_hex(blob) != digest:
            print(f"  row {data_id}: stored hash mismatch, skipping")
            continue
        new_blob = to_blob(add_plain(from_blob(blob, P), args.amount, P))
        db.save_ciphertext(data_id, new_blob, sha256_hex(new_blob))
        updated += 1
    db.commit()
    print(f"Added {args.amount} homomorphically to {updated} ciphertexts. "
          f"Plaintexts wrap modulo {P.t}.")


def cmd_decrypt(db: Database, _args) -> int:
    sk = load_secret_key()
    print(f"{'id':>4} {'original':>9} {'decrypted':>10} {'diff':>5}  integrity")
    bad = 0
    for data_id, original, blob, digest in db.encrypted_rows():
        if blob is None:
            print(f"{data_id:>4} {original:>9} {'-':>10} {'-':>5}  not encrypted")
            continue
        blob = bytes(blob)
        if sha256_hex(blob) != digest:
            bad += 1
            print(f"{data_id:>4} {original:>9} {'-':>10} {'-':>5}  TAMPERED (hash mismatch)")
            continue
        value = decrypt(sk, from_blob(blob, P), P)
        print(f"{data_id:>4} {original:>9} {value:>10} {(value - original) % P.t:>5}  OK")
    return 1 if bad else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("setup")
    sub.add_parser("encrypt")
    r = sub.add_parser("raise")
    r.add_argument("--amount", type=int, required=True)
    sub.add_parser("decrypt")
    args = parser.parse_args()

    db = Database()
    try:
        handler = {"setup": cmd_setup, "encrypt": cmd_encrypt,
                   "raise": cmd_raise, "decrypt": cmd_decrypt}[args.command]
        return handler(db, args) or 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
