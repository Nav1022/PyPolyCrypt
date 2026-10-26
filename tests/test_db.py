import pytest

from pypolycrypt import DEFAULT_PARAMS as P, add_plain, decrypt, encrypt, keygen
from pypolycrypt.codec import from_blob, sha256_hex, to_blob
from pypolycrypt.db import Database


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("SQLITE_PATH", str(tmp_path / "t.db"))
    d = Database("sqlite")
    d.init_schema()
    d.seed_demo(count=10)
    yield d
    d.close()


def test_encrypt_store_raise_decrypt(db):
    pk, sk = keygen(P)
    for data_id, value in db.plain_rows():
        blob = to_blob(encrypt(pk, value, P))
        db.save_ciphertext(data_id, blob, sha256_hex(blob))
    db.commit()

    for data_id, _, blob, digest in db.encrypted_rows():            # untrusted operator, no key
        new = to_blob(add_plain(from_blob(bytes(blob), P), 50, P))
        db.save_ciphertext(data_id, new, sha256_hex(new))
    db.commit()

    for data_id, original, blob, digest in db.encrypted_rows():
        assert sha256_hex(bytes(blob)) == digest
        assert decrypt(sk, from_blob(bytes(blob), P), P) == (original + 50) % P.t


def test_seed_is_idempotent(db):
    assert db.seed_demo(count=5) == 0
