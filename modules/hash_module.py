import hashlib
from Crypto.Hash import SHA256


def hash_message(message: bytes) -> str:
    """
    Compute the SHA-256 hash of a message.
    """
    h = SHA256.new(message)
    return h.hexdigest()


def verify_integrity(message: bytes, expected_hash: str) -> bool:
    """
    Verify that a message matches an expected SHA-256 hash.
    """
    return hash_message(message) == expected_hash.lower()


def hash_file(filepath: str) -> str:
    """
    Compute the SHA-256 hash of a file's contents.
    """
    h = SHA256.new()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    msg = b"Hello, Network Security!"
    digest = hash_message(msg)
    print(f"[HASH] Message : {msg.decode()}")
    print(f"[HASH] SHA-256 : {digest}")
    print(f"[HASH] Verify OK  : {verify_integrity(msg, digest)}")
    print(f"[HASH] Verify BAD : {verify_integrity(b'tampered', digest)}")
