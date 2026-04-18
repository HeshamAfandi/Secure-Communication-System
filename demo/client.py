"""
client.py — Secure client demo.

Connects to the demo server, performs RSA handshake + AES session setup,
authenticates with username/password, then sends encrypted messages.
"""

import json
import socket
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.rsa_module import import_public_key, encrypt_with_public_key
from modules.aes_module import generate_aes_key, encrypt, decrypt
from modules.hash_module import hash_message, verify_integrity

HOST = "127.0.0.1"
PORT = 65432


def send_framed(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_framed(sock: socket.socket) -> bytes:
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
    msg_hash = hash_message(plaintext)
    payload = json.dumps({"hash": msg_hash, "data": plaintext.decode("utf-8")}).encode()
    ciphertext, nonce, tag = encrypt(payload, aes_key)
    send_framed(sock, nonce)
    send_framed(sock, tag)
    send_framed(sock, ciphertext)


def recv_secure(sock: socket.socket, aes_key: bytes) -> bytes:
    nonce = recv_framed(sock)
    tag = recv_framed(sock)
    ciphertext = recv_framed(sock)
    payload = decrypt(ciphertext, aes_key, nonce, tag)
    envelope = json.loads(payload.decode("utf-8"))
    data = envelope["data"].encode("utf-8")
    if not verify_integrity(data, envelope["hash"]):
        raise ValueError("Integrity check failed — message may be tampered.")
    return data


def main(username: str = "alice", password: str = "password123"):
    print(f"[CLIENT] Connecting to {HOST}:{PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print("[CLIENT] Connected.")

        # Step 1: Receive server's RSA public key
        pem = recv_framed(sock).decode("utf-8")
        server_pub_key = import_public_key(pem)
        print("[CLIENT] Received server RSA public key.")

        # Step 2: Generate AES session key, send credentials + key encrypted with RSA
        aes_key = generate_aes_key()
        bundle = json.dumps({
            "username": username,
            "password": password,
            "aes_key": aes_key.hex(),
        }).encode("utf-8")
        encrypted_bundle = encrypt_with_public_key(bundle, server_pub_key)
        send_framed(sock, encrypted_bundle)
        print("[CLIENT] Sent encrypted credentials + AES session key.")

        # Step 3: Check auth result
        result = recv_framed(sock)
        if result != b"AUTH_OK":
            print(f"[CLIENT] Authentication failed: {result.decode()}")
            return
        print(f"[CLIENT] Authenticated as '{username}'. Secure channel established.")

        # Step 4: Send messages
        messages = [
            "Hello, secure server!",
            "AES + RSA + SHA-256 working together.",
            "This is CSE451 Secure Communication Suite.",
        ]
        for msg in messages:
            send_secure(sock, aes_key, msg.encode())
            print(f"[CLIENT] Sent    : {msg}")
            reply = recv_secure(sock, aes_key)
            print(f"[CLIENT] Received: {reply.decode()}")


if __name__ == "__main__":
    main()
