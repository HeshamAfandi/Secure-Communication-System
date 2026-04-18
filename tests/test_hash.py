"""Tests for hash_module.py"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.hash_module import hash_message, verify_integrity, hash_file
import tempfile


def test_hash_produces_64_char_hex():
    digest = hash_message(b"hello")
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)
    print("  PASS: hash produces 64-char hex string")


def test_same_input_same_hash():
    msg = b"deterministic"
    assert hash_message(msg) == hash_message(msg)
    print("  PASS: same input produces same hash")


def test_different_inputs_different_hashes():
    assert hash_message(b"abc") != hash_message(b"abd")
    print("  PASS: different inputs produce different hashes")


def test_verify_integrity_correct():
    msg = b"integrity check"
    digest = hash_message(msg)
    assert verify_integrity(msg, digest) is True
    print("  PASS: verify_integrity returns True for correct hash")


def test_verify_integrity_tampered():
    msg = b"original"
    digest = hash_message(msg)
    assert verify_integrity(b"tampered", digest) is False
    print("  PASS: verify_integrity returns False for tampered message")


def test_hash_file():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"file content for hashing")
        tmp_path = tmp.name
    try:
        digest = hash_file(tmp_path)
        assert len(digest) == 64
        expected = hash_message(b"file content for hashing")
        assert digest == expected
        print("  PASS: hash_file matches hash_message for same content")
    finally:
        os.unlink(tmp_path)


if __name__ == "__main__":
    print("\n=== Hash Module Tests ===")
    test_hash_produces_64_char_hex()
    test_same_input_same_hash()
    test_different_inputs_different_hashes()
    test_verify_integrity_correct()
    test_verify_integrity_tampered()
    test_hash_file()
    print("All hash tests passed.\n")
