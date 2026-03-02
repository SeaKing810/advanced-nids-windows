from nids.crypto import Crypto
from cryptography.fernet import Fernet


def test_crypto_roundtrip():
    key = Fernet.generate_key().decode()
    c = Crypto(key)
    payload = {"a": 1, "b": "x"}
    tok = c.encrypt_json(payload)
    out = c.decrypt_json(tok)
    assert out["a"] == 1
    assert out["b"] == "x"
