import itertools
import secrets

import numpy as np
import pytest

from pypolycrypt import (DEFAULT_PARAMS as P, Params, add, add_plain, decrypt,
                         encrypt, keygen, noise)
from pypolycrypt.codec import from_blob, sha256_hex, to_blob
from pypolycrypt.he import polymul


@pytest.fixture(scope="module")
def keys():
    return keygen(P)


def seeded(seed):
    return np.random.default_rng(seed).bytes


def test_roundtrip_every_plaintext(keys):
    pk, sk = keys
    for m in range(P.t):
        assert decrypt(sk, encrypt(pk, m, P), P) == m


def test_roundtrip_many_random_trials(keys):
    pk, sk = keys
    for _ in range(2000):
        m = secrets.randbelow(P.t)
        assert decrypt(sk, encrypt(pk, m, P), P) == m


def test_encryption_is_randomized(keys):
    pk, _ = keys
    blobs = {to_blob(encrypt(pk, 120, P)) for _ in range(50)}
    assert len(blobs) == 50


def test_deterministic_with_seeded_source():
    pk, sk = keygen(P, seeded(1))
    c1 = encrypt(pk, 7, P, seeded(2))
    c2 = encrypt(pk, 7, P, seeded(2))
    assert np.array_equal(c1.ct0, c2.ct0) and np.array_equal(c1.ct1, c2.ct1)


def test_add_plain_matches_report_example(keys):
    pk, sk = keys
    assert decrypt(sk, add_plain(encrypt(pk, 120, P), 50, P), P) == 170


def test_add_plain_wraps_modulo_t(keys):
    pk, sk = keys
    assert decrypt(sk, add_plain(encrypt(pk, 250, P), 10, P), P) == 4


def test_ciphertext_addition(keys):
    pk, sk = keys
    assert decrypt(sk, add(encrypt(pk, 100, P), encrypt(pk, 27, P), P), P) == 127


def test_plaintext_additions_add_no_noise(keys):
    pk, sk = keys
    ct = encrypt(pk, 10, P)
    before = noise(sk, ct, 10, P)
    for _ in range(200):
        ct = add_plain(ct, 1, P)
    assert decrypt(sk, ct, P) == 210
    assert noise(sk, ct, 210, P) == before


def test_fresh_noise_is_well_below_failure_threshold(keys):
    pk, sk = keys
    worst = max(abs(noise(sk, encrypt(pk, 99, P), 99, P)) for _ in range(500))
    assert worst < P.delta // 2 - 10   # decryption fails at delta/2 = 64


def test_ciphertext_noise_grows_with_additions(keys):
    pk, sk = keys
    one = [abs(noise(sk, encrypt(pk, 0, P), 0, P)) for _ in range(300)]
    acc_noise = []
    for _ in range(300):
        acc = encrypt(pk, 0, P)
        for _ in range(3):
            acc = add(acc, encrypt(pk, 0, P), P)
        acc_noise.append(abs(noise(sk, acc, 0, P)))
    assert sum(acc_noise) / 300 > 1.5 * sum(one) / 300   # ~2x expected (sqrt(4))


def test_out_of_range_plaintext_rejected(keys):
    pk, _ = keys
    with pytest.raises(ValueError):
        encrypt(pk, P.t, P)
    with pytest.raises(ValueError):
        encrypt(pk, -1, P)


def test_wrong_key_does_not_decrypt(keys):
    pk, _ = keys
    _, other_sk = keygen(P)
    ct = encrypt(pk, 42, P)
    hits = sum(decrypt(other_sk, encrypt(pk, 42, P), P) == 42 for _ in range(50))
    assert hits < 5


def test_polymul_is_negacyclic():
    p = Params(n=4, q=16, t=4)
    x = np.array([0, 1, 0, 0])      # x
    y = np.array([0, 0, 0, 1])      # x^3
    assert polymul(x, y, p).tolist() == [(-1) % 16, 0, 0, 0]   # x^4 = -1


def test_polymul_matches_schoolbook():
    p = Params(n=8, q=256, t=16)
    rng = np.random.default_rng(0)
    x, y = rng.integers(0, 256, 8), rng.integers(0, 256, 8)
    expect = np.zeros(8, dtype=np.int64)
    for i, j in itertools.product(range(8), range(8)):
        k, sign = (i + j, 1) if i + j < 8 else (i + j - 8, -1)
        expect[k] += sign * int(x[i]) * int(y[j])
    assert polymul(x, y, p).tolist() == (expect % 256).tolist()


def test_invalid_params():
    with pytest.raises(ValueError):
        Params(n=100)
    with pytest.raises(ValueError):
        Params(q=3000)
    with pytest.raises(ValueError):
        Params(t=100)


def test_blob_roundtrip_and_hash(keys):
    pk, sk = keys
    ct = encrypt(pk, 77, P)
    blob = to_blob(ct)
    assert decrypt(sk, from_blob(blob, P), P) == 77
    assert len(sha256_hex(blob)) == 64


def test_tampering_changes_hash(keys):
    pk, _ = keys
    blob = bytearray(to_blob(encrypt(pk, 5, P)))
    digest = sha256_hex(bytes(blob))
    blob[10] ^= 1
    assert sha256_hex(bytes(blob)) != digest
