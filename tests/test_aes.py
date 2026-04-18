"""Tests for aes_module.py"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.aes_module import generate_aes_key, encrypt, decrypt


def test_key_is_16_bytes():
    key = generate_aes_key()
    assert len(key) == 16
    print("  PASS: AES key is 16 bytes")


def test_different_keys_generated():
    k1 = generate_aes_key()
    k2 = generate_aes_key()
    assert k1 != k2
    print("  PASS: each generated key is unique")


def test_encrypt_decrypt_roundtrip():
    key = generate_aes_key()
    plaintext = b"Hello, AES-EAX!"
    ciphertext, nonce, tag = encrypt(plaintext, key)
    result = decrypt(ciphertext, key, nonce, tag)
    assert result == plaintext
    print("  PASS: encrypt/decrypt round-trip produces original plaintext")


def test_ciphertext_differs_from_plaintext():
    key = generate_aes_key()
    plaintext = b"visible text"
    ciphertext, _, _ = encrypt(plaintext, key)
    assert ciphertext != plaintext
    print("  PASS: ciphertext differs from plaintext")


def test_nonce_is_random():
    key = generate_aes_key()
    _, nonce1, _ = encrypt(b"msg", key)
    _, nonce2, _ = encrypt(b"msg", key)
    assert nonce1 != nonce2
    print("  PASS: nonces are unique per encryption call")


def test_tampered_tag_raises():
    key = generate_aes_key()
    ciphertext, nonce, tag = encrypt(b"secure data", key)
    bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
    try:
        decrypt(ciphertext, key, nonce, bad_tag)
        assert False, "Should have raised ValueError"
    except ValueError:
        print("  PASS: tampered tag raises ValueError")


def test_wrong_key_raises():
    key = generate_aes_key()
    wrong_key = generate_aes_key()
    ciphertext, nonce, tag = encrypt(b"secret", key)
    try:
        decrypt(ciphertext, wrong_key, nonce, tag)
        assert False, "Should have raised ValueError"
    except ValueError:
        print("  PASS: wrong key raises ValueError")


def test_empty_plaintext():
    key = generate_aes_key()
    ciphertext, nonce, tag = encrypt(b"", key)
    result = decrypt(ciphertext, key, nonce, tag)
    assert result == b""
    print("  PASS: empty plaintext encrypts and decrypts correctly")


if __name__ == "__main__":
    print("\n=== AES Module Tests ===")
    test_key_is_16_bytes()
    test_different_keys_generated()
    test_encrypt_decrypt_roundtrip()
    test_ciphertext_differs_from_plaintext()
    test_nonce_is_random()
    test_tampered_tag_raises()
    test_wrong_key_raises()
    test_empty_plaintext()
    print("All AES tests passed.\n")
