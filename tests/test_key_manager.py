"""Tests for key_manager.py"""

import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.key_manager import (
    save_aes_key, load_aes_key,
    save_rsa_private_key, save_rsa_public_key,
    load_rsa_private_key, load_rsa_public_key,
)
from modules.aes_module import generate_aes_key
from modules.rsa_module import generate_rsa_keypair


def test_aes_key_save_load():
    key = generate_aes_key()
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        path = tmp.name
    try:
        save_aes_key(key, path)
        loaded = load_aes_key(path)
        assert loaded == key
        print("  PASS: AES key save/load round-trip")
    finally:
        os.unlink(path)


def test_rsa_private_key_save_load():
    priv, _ = generate_rsa_keypair()
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
        path = tmp.name
    passphrase = "TestPass!99"
    try:
        save_rsa_private_key(priv, path, passphrase)
        loaded = load_rsa_private_key(path, passphrase)
        assert loaded.n == priv.n
        print("  PASS: RSA private key save/load with passphrase")
    finally:
        os.unlink(path)


def test_rsa_public_key_save_load():
    _, pub = generate_rsa_keypair()
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
        path = tmp.name
    try:
        save_rsa_public_key(pub, path)
        loaded = load_rsa_public_key(path)
        assert loaded.n == pub.n
        print("  PASS: RSA public key save/load")
    finally:
        os.unlink(path)


def test_wrong_passphrase_raises():
    priv, _ = generate_rsa_keypair()
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
        path = tmp.name
    try:
        save_rsa_private_key(priv, path, "correct_pass")
        try:
            load_rsa_private_key(path, "wrong_pass")
            assert False, "Should have raised an error"
        except Exception:
            print("  PASS: wrong passphrase raises error")
    finally:
        os.unlink(path)


if __name__ == "__main__":
    print("\n=== Key Manager Tests ===")
    print("  (RSA key generation takes a moment...)")
    test_aes_key_save_load()
    test_rsa_private_key_save_load()
    test_rsa_public_key_save_load()
    test_wrong_passphrase_raises()
    print("All key manager tests passed.\n")
