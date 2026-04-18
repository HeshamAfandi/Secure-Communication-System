"""
key_manager.py — Secure key generation, storage, and loading.

AES keys are stored as raw binary files.
RSA private keys are stored as passphrase-protected PEM files (AES-256-CBC).
RSA public keys are stored as plain PEM files.
"""

import os
from Crypto.PublicKey import RSA


def save_aes_key(key: bytes, filepath: str) -> None:
    """
    Save a raw AES key to a file.

    Args:
        key: AES key bytes.
        filepath: Destination file path.
    """
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(key)


def load_aes_key(filepath: str) -> bytes:
    """
    Load a raw AES key from a file.

    Args:
        filepath: Path to the key file.

    Returns:
        AES key bytes.
    """
    with open(filepath, "rb") as f:
        return f.read()


def save_rsa_private_key(private_key, filepath: str, passphrase: str) -> None:
    """
    Save an RSA private key to a passphrase-protected PEM file.

    The key is encrypted with AES-256-CBC before writing to disk.

    Args:
        private_key: RSA private key object.
        filepath: Destination file path.
        passphrase: Password used to encrypt the key on disk.
    """
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    pem = private_key.export_key(
        format="PEM",
        passphrase=passphrase.encode("utf-8"),
        pkcs=8,
        protection="scryptAndAES256-CBC",
    )
    with open(filepath, "wb") as f:
        f.write(pem)


def save_rsa_public_key(public_key, filepath: str) -> None:
    """
    Save an RSA public key to a PEM file.

    Args:
        public_key: RSA public key object.
        filepath: Destination file path.
    """
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    pem = public_key.export_key(format="PEM")
    with open(filepath, "wb") as f:
        f.write(pem)


def load_rsa_private_key(filepath: str, passphrase: str):
    """
    Load and decrypt an RSA private key from a PEM file.

    Args:
        filepath: Path to the encrypted PEM file.
        passphrase: Password used when the key was saved.

    Returns:
        RSA private key object.
    """
    with open(filepath, "rb") as f:
        pem = f.read()
    return RSA.import_key(pem, passphrase=passphrase.encode("utf-8"))


def load_rsa_public_key(filepath: str):
    """
    Load an RSA public key from a PEM file.

    Args:
        filepath: Path to the PEM file.

    Returns:
        RSA public key object.
    """
    with open(filepath, "rb") as f:
        pem = f.read()
    return RSA.import_key(pem)


if __name__ == "__main__":
    import tempfile
    from Crypto.Random import get_random_bytes
    from modules.rsa_module import generate_rsa_keypair

    with tempfile.TemporaryDirectory() as tmpdir:
        # AES key round-trip
        aes_key = get_random_bytes(16)
        aes_path = os.path.join(tmpdir, "session.key")
        save_aes_key(aes_key, aes_path)
        loaded_aes = load_aes_key(aes_path)
        print(f"[KEY MANAGER] AES key round-trip OK: {aes_key == loaded_aes}")

        # RSA key round-trip
        priv, pub = generate_rsa_keypair()
        priv_path = os.path.join(tmpdir, "private.pem")
        pub_path = os.path.join(tmpdir, "public.pem")
        passphrase = "s3cur3P@ss!"

        save_rsa_private_key(priv, priv_path, passphrase)
        save_rsa_public_key(pub, pub_path)

        loaded_priv = load_rsa_private_key(priv_path, passphrase)
        loaded_pub = load_rsa_public_key(pub_path)

        print(f"[KEY MANAGER] RSA private key round-trip OK: {priv.n == loaded_priv.n}")
        print(f"[KEY MANAGER] RSA public key round-trip OK : {pub.n == loaded_pub.n}")
