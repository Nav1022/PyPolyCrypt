"""Key persistence. Keys live in ./keys (gitignored)."""

from __future__ import annotations

from pathlib import Path

import numpy as np

from .he import PublicKey, SecretKey

KEY_DIR = Path("keys")


def save_keys(pk: PublicKey, sk: SecretKey, directory: Path = KEY_DIR) -> None:
    directory.mkdir(exist_ok=True)
    np.savez(directory / "public_key.npz", b=pk.b, a=pk.a)
    sk_path = directory / "secret_key.npz"
    np.savez(sk_path, s=sk.s)
    try:
        sk_path.chmod(0o600)
    except OSError:  # e.g. Windows
        pass


def load_public_key(directory: Path = KEY_DIR) -> PublicKey:
    with np.load(directory / "public_key.npz") as f:
        return PublicKey(f["b"], f["a"])


def load_secret_key(directory: Path = KEY_DIR) -> SecretKey:
    with np.load(directory / "secret_key.npz") as f:
        return SecretKey(f["s"])
