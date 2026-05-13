import json
import socket
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.rsa_module import generate_rsa_keypair, decrypt_with_private_key, export_public_key
from modules.aes_module import decrypt, encrypt
from modules.hash_module import hash_message, verify_integrity
from modules.auth_module import load_user_db, register_user, save_user_db

HOST = "127.0.0.1"
PORT = 65432
DB_PATH = os.path.join(os.path.dirname(__file__), "users.json")


def send_framed(sock: socket.socket, data: bytes) -> None:
    """Send bytes with a 4-byte big-endian length prefix."""
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_framed(sock: socket.socket) -> bytes:
    """Receive a length-prefixed message."""
    raw_len = _recv_exact(sock, 4)
    length = struct.unpack(">I", raw_len)[0]
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        buf += chunk
    return buf


def send_secure(sock: socket.socket, aes_key: bytes, plaintext: bytes) -> None:
    """Encrypt plaintext and send over the socket with integrity check."""
    msg_hash = hash_message(plaintext)
    payload = json.dumps({"hash": msg_hash, "data": plaintext.decode("utf-8")}).encode()
    ciphertext, nonce, tag = encrypt(payload, aes_key)
    send_framed(sock, nonce)
    send_framed(sock, tag)
    send_framed(sock, ciphertext)


def recv_secure(sock: socket.socket, aes_key: bytes) -> bytes:
    """Receive, decrypt, and verify an encrypted message."""
    nonce = recv_framed(sock)
    tag = recv_framed(sock)
    ciphertext = recv_framed(sock)
    payload = decrypt(ciphertext, aes_key, nonce, tag)
    envelope = json.loads(payload.decode("utf-8"))
    data = envelope["data"].encode("utf-8")
    if not verify_integrity(data, envelope["hash"]):
        raise ValueError("Integrity check failed — message may be tampered.")
    return data


def main():
    # Ensure a demo user exists
    db = load_user_db(DB_PATH)
    if "Hossam" not in db:
        register_user("Hossam", "password67", db)
        save_user_db(db, DB_PATH)
        print("[SERVER] Created demo user: Hossam / password67")

    private_key, public_key = generate_rsa_keypair()
    print(f"[SERVER] RSA key pair generated ({private_key.size_in_bits()} bits).")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"[SERVER] Listening on {HOST}:{PORT} — waiting for client...")

        conn, addr = srv.accept()
        with conn:
            print(f"[SERVER] Connection from {addr}")

            # Step 1: Send RSA public key
            pem = export_public_key(public_key).encode("utf-8")
            send_framed(conn, pem)
            print("[SERVER] Sent RSA public key.")

            # Step 2: Receive encrypted credentials + AES key
            encrypted_bundle = recv_framed(conn)
            bundle_json = decrypt_with_private_key(encrypted_bundle, private_key)
            bundle = json.loads(bundle_json.decode("utf-8"))

            username = bundle["username"]
            password = bundle["password"]
            aes_key = bytes.fromhex(bundle["aes_key"])

            db = load_user_db(DB_PATH)
            if not (username in db and __import__("bcrypt").checkpw(
                password.encode(), db[username].encode()
            )):
                send_framed(conn, b"AUTH_FAIL")
                print(f"[SERVER] Authentication failed for '{username}'.")
                return

            send_framed(conn, b"AUTH_OK")
            print(f"[SERVER] User '{username}' authenticated. AES session established.")

            # Step 3: Secure messaging loop
            while True:
                try:
                    msg = recv_secure(conn, aes_key)
                    print(f"[SERVER] Received: {msg.decode('utf-8')}")
                    reply = f"Echo: {msg.decode('utf-8')}".encode()
                    send_secure(conn, aes_key, reply)
                except (ConnectionError, EOFError):
                    print("[SERVER] Client disconnected.")
                    break


if __name__ == "__main__":
    main()
