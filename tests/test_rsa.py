"""Tests for rsa_module.py"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.rsa_module import (
    generate_rsa_keypair,
    encrypt_with_public_key,
    decrypt_with_private_key,
    export_public_key,
    import_public_key,
)


def test_keypair_generation():
    priv, pub = generate_rsa_keypair()
    assert priv.size_in_bits() == 2048
    assert pub.size_in_bits() == 2048
    print("  PASS: RSA 2048-bit keypair generated")


def test_encrypt_decrypt_roundtrip():
    priv, pub = generate_rsa_keypair()
    plaintext = b"RSA test payload"
    ciphertext = encrypt_with_public_key(plaintext, pub)
    result = decrypt_with_private_key(ciphertext, priv)
    assert result == plaintext
    print("  PASS: RSA encrypt/decrypt round-trip works")


def test_ciphertext_is_256_bytes():
    priv, pub = generate_rsa_keypair()
    ciphertext = encrypt_with_public_key(b"short msg", pub)
    assert len(ciphertext) == 256
    print("  PASS: RSA-2048 ciphertext is 256 bytes")


def test_encrypt_aes_key():
    priv, pub = generate_rsa_keypair()
    from modules.aes_module import generate_aes_key
    aes_key = generate_aes_key()
    encrypted_key = encrypt_with_public_key(aes_key, pub)
    recovered_key = decrypt_with_private_key(encrypted_key, priv)
    assert recovered_key == aes_key
    print("  PASS: AES key encrypted with RSA and recovered correctly")


def test_wrong_private_key_raises():
    priv1, pub1 = generate_rsa_keypair()
    priv2, _ = generate_rsa_keypair()
    ciphertext = encrypt_with_public_key(b"secret", pub1)
    try:
        decrypt_with_private_key(ciphertext, priv2)
        assert False, "Should have raised an error"
    except Exception:
        print("  PASS: decryption with wrong private key raises error")


def test_public_key_export_import():
    _, pub = generate_rsa_keypair()
    pem = export_public_key(pub)
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    reimported = import_public_key(pem)
    assert reimported.n == pub.n
    print("  PASS: public key PEM export/import round-trip OK")


if __name__ == "__main__":
    print("\n=== RSA Module Tests ===")
    print("  (RSA key generation takes a moment...)")
    test_keypair_generation()
    test_encrypt_decrypt_roundtrip()
    test_ciphertext_is_256_bytes()
    test_encrypt_aes_key()
    test_wrong_private_key_raises()
    test_public_key_export_import()
    print("All RSA tests passed.\n")
