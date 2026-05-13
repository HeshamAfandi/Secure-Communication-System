import sys
import os


def banner():
    print("=" * 55)
    print("  CSE451 — Secure Communication Suite")
    print("  Ain Shams University | Spring 2026")
    print("=" * 55)


def menu():
    print("\nSelect a module to demo:")
    print("  1. SHA-256 Hash Module")
    print("  2. AES-128-EAX Encryption Module")
    print("  3. RSA-2048 Asymmetric Encryption Module")
    print("  4. Key Manager Module")
    print("  5. Password Authentication Module")
    print("  6. Run All Tests")
    print("  7. Start Demo Server  (open a second terminal for the client)")
    print("  8. Start Demo Client  (server must be running first)")
    print("  0. Exit")
    return input("\nChoice: ").strip()


# ── Demo helpers ────────────────────────────────────────────────────────────

def demo_hash():
    from modules.hash_module import hash_message, verify_integrity
    print("\n--- SHA-256 Hash Demo ---")
    msg = input("Enter a message to hash: ").encode("utf-8")
    digest = hash_message(msg)
    print(f"SHA-256 : {digest}")
    print(f"Integrity check (original) : {verify_integrity(msg, digest)}")
    print(f"Integrity check (tampered) : {verify_integrity(msg + b'x', digest)}")


def demo_aes():
    from modules.aes_module import generate_aes_key, encrypt, decrypt
    print("\n--- AES-128-EAX Demo ---")
    key = generate_aes_key()
    msg = input("Enter a message to encrypt: ").encode("utf-8")
    ct, nonce, tag = encrypt(msg, key)
    print(f"Key       : {key.hex()}")
    print(f"Ciphertext: {ct.hex()}")
    print(f"Nonce     : {nonce.hex()}")
    print(f"Tag       : {tag.hex()}")
    pt = decrypt(ct, key, nonce, tag)
    print(f"Decrypted : {pt.decode('utf-8')}")
    print(f"Match     : {msg == pt}")


def demo_rsa():
    from modules.rsa_module import (
        generate_rsa_keypair, encrypt_with_public_key,
        decrypt_with_private_key, export_public_key,
    )
    print("\n--- RSA-2048-OAEP Demo ---")
    print("Generating RSA-2048 key pair (may take a moment)...")
    priv, pub = generate_rsa_keypair()
    print(f"Key size: {priv.size_in_bits()} bits")
    msg = input("Enter a short message to encrypt (max ~214 chars): ").encode("utf-8")
    ct = encrypt_with_public_key(msg, pub)
    print(f"Ciphertext ({len(ct)} bytes): {ct.hex()[:64]}...")
    pt = decrypt_with_private_key(ct, priv)
    print(f"Decrypted : {pt.decode('utf-8')}")
    print("\nPublic Key (PEM):")
    print(export_public_key(pub))


def demo_key_manager():
    import tempfile
    from modules.aes_module import generate_aes_key
    from modules.rsa_module import generate_rsa_keypair
    from modules.key_manager import (
        save_aes_key, load_aes_key,
        save_rsa_private_key, save_rsa_public_key,
        load_rsa_private_key, load_rsa_public_key,
    )
    print("\n--- Key Manager Demo ---")
    with tempfile.TemporaryDirectory() as d:
        # AES
        aes_key = generate_aes_key()
        aes_path = os.path.join(d, "session.key")
        save_aes_key(aes_key, aes_path)
        loaded_aes = load_aes_key(aes_path)
        print(f"AES key saved to: {aes_path}")
        print(f"AES round-trip OK: {aes_key == loaded_aes}")

        # RSA
        print("Generating RSA key pair...")
        priv, pub = generate_rsa_keypair()
        passphrase = input("Enter passphrase to protect the private key: ")
        priv_path = os.path.join(d, "private.pem")
        pub_path = os.path.join(d, "public.pem")
        save_rsa_private_key(priv, priv_path, passphrase)
        save_rsa_public_key(pub, pub_path)
        print(f"Private key saved (encrypted): {priv_path}")
        print(f"Public key saved: {pub_path}")

        loaded_priv = load_rsa_private_key(priv_path, passphrase)
        loaded_pub = load_rsa_public_key(pub_path)
        print(f"RSA private key round-trip OK: {priv.n == loaded_priv.n}")
        print(f"RSA public key round-trip OK : {pub.n == loaded_pub.n}")
        input("\n(Keys will be deleted when you press Enter...)")


def demo_auth():
    from modules.auth_module import register_user, authenticate_user
    print("\n--- Authentication Demo ---")
    db = {}
    username = input("Choose a username to register: ").strip()
    password = input("Choose a password: ").strip()
    register_user(username, password, db)
    print(f"User '{username}' registered.")

    test_pass = input("Enter password to verify (try correct and wrong): ").strip()
    result = authenticate_user(username, test_pass, db)
    print(f"Authentication result: {'SUCCESS' if result else 'FAILED'}")


def run_all_tests():
    import subprocess
    print("\n--- Running All Tests ---\n")
    test_files = [
        "tests/test_hash.py",
        "tests/test_aes.py",
        "tests/test_rsa.py",
        "tests/test_key_manager.py",
        "tests/test_auth.py",
    ]
    suite_dir = os.path.dirname(os.path.abspath(__file__))
    all_passed = True
    for tf in test_files:
        path = os.path.join(suite_dir, tf)
        print(f"Running {tf}...")
        result = subprocess.run([sys.executable, path], capture_output=True, text=True)
        print(result.stdout)
        if result.returncode != 0:
            print(f"FAILED:\n{result.stderr}")
            all_passed = False
    print("=" * 40)
    print("All tests PASSED!" if all_passed else "Some tests FAILED.")


def start_server():
    import subprocess
    server_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo", "server.py")
    print("\n[Starting server — press Ctrl+C to stop]")
    subprocess.run([sys.executable, server_path])


def start_client():
    import subprocess
    client_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo", "client.py")
    print("\n[Starting client]")
    subprocess.run([sys.executable, client_path])


# ── Entry point ─────────────────────────────────────────────────────────────

ACTIONS = {
    "1": demo_hash,
    "2": demo_aes,
    "3": demo_rsa,
    "4": demo_key_manager,
    "5": demo_auth,
    "6": run_all_tests,
    "7": start_server,
    "8": start_client,
}

if __name__ == "__main__":
    banner()
    while True:
        choice = menu()
        if choice == "0":
            print("Goodbye.")
            break
        action = ACTIONS.get(choice)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                print("\n(interrupted)")
            except Exception as e:
                print(f"Error: {e}")
        else:
            print("Invalid choice.")
