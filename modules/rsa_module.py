from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_rsa_keypair(bits: int = 2048):
    """
    Generate an RSA key pair.
    """
    private_key = RSA.generate(bits)
    public_key = private_key.publickey()
    return private_key, public_key


def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    """
    Encrypt data with an RSA public key using OAEP padding.

    """
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)


def decrypt_with_private_key(ciphertext: bytes, private_key) -> bytes:
    """
    Decrypt RSA-OAEP ciphertext with a private key.
    """
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def export_public_key(public_key) -> str:
    """
    Export an RSA public key as a PEM-encoded string.
    """
    return public_key.export_key(format="PEM").decode("utf-8")


def import_public_key(pem: str):
    """
    Import an RSA public key from a PEM-encoded string.

    Args:
        pem: PEM string.

    Returns:
        RSA public key object.
    """
    return RSA.import_key(pem.encode("utf-8"))


if __name__ == "__main__":
    private_key, public_key = generate_rsa_keypair()
    message = b"AES-session-key-goes-here-16byte"

    ciphertext = encrypt_with_public_key(message, public_key)
    plaintext = decrypt_with_private_key(ciphertext, private_key)

    print(f"[RSA] Original  : {message}")
    print(f"[RSA] Encrypted : {ciphertext.hex()[:64]}...")
    print(f"[RSA] Decrypted : {plaintext}")
    print(f"[RSA] Match     : {message == plaintext}")

    pem = export_public_key(public_key)
    reimported = import_public_key(pem)
    print(f"[RSA] PEM export/import OK: {reimported.n == public_key.n}")
