"""
aes_module.py — AES-128-EAX authenticated encryption.

EAX mode provides both confidentiality (encryption) and integrity (authentication
tag), making it suitable for secure message transmission without a separate MAC.
"""

import threading
import queue
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def generate_aes_key() -> bytes:
    """
    Generate a random 16-byte (128-bit) AES key.

    Returns:
        16 random bytes suitable for use as an AES-128 key.
    """
    return get_random_bytes(16)


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext using AES-128-EAX mode.

    Args:
        plaintext: Data to encrypt.
        key: 16-byte AES key.

    Returns:
        Tuple of (ciphertext, nonce, tag). All three are needed for decryption.
    """
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, cipher.nonce, tag


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt and verify ciphertext using AES-128-EAX mode.

    Args:
        ciphertext: Encrypted data.
        key: 16-byte AES key (must match the one used for encryption).
        nonce: Nonce generated during encryption.
        tag: Authentication tag generated during encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If the authentication tag is invalid (data was tampered).
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


# ---------------------------------------------------------------------------
# Threaded worker (from project spec skeleton) — useful for high-throughput
# pipelines where encryption runs in a dedicated background thread.
# ---------------------------------------------------------------------------

class EncryptionWorker(threading.Thread):
    """Background thread that encrypts messages from a queue."""

    def __init__(self, plaintext_queue: queue.Queue, ciphertext_queue: queue.Queue):
        """
        Args:
            plaintext_queue: Queue supplying plaintext bytes (None signals stop).
            ciphertext_queue: Queue that receives (ciphertext, nonce, tag) tuples.
        """
        threading.Thread.__init__(self)
        self.plaintext_queue = plaintext_queue
        self.ciphertext_queue = ciphertext_queue
        self.key = generate_aes_key()
        self.daemon = True

    def run(self):
        while True:
            plaintext = self.plaintext_queue.get()
            if plaintext is None:
                break
            ciphertext, nonce, tag = encrypt(plaintext, self.key)
            self.ciphertext_queue.put((ciphertext, nonce, tag))


if __name__ == "__main__":
    key = generate_aes_key()
    message = b"Secure message from CSE451!"
    ct, nonce, tag = encrypt(message, key)
    pt = decrypt(ct, key, nonce, tag)

    print(f"[AES] Original  : {message.decode()}")
    print(f"[AES] Encrypted : {ct.hex()}")
    print(f"[AES] Nonce     : {nonce.hex()}")
    print(f"[AES] Tag       : {tag.hex()}")
    print(f"[AES] Decrypted : {pt.decode()}")
    print(f"[AES] Match     : {message == pt}")
