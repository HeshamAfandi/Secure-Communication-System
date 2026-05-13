import customtkinter as ctk
import tkinter.messagebox as messagebox
import threading
import subprocess
import tempfile
import sys
import os

# Import cryptographic modules
from modules.hash_module import hash_message, verify_integrity
from modules.aes_module import generate_aes_key, encrypt, decrypt
from modules.rsa_module import (
    generate_rsa_keypair, encrypt_with_public_key,
    decrypt_with_private_key, export_public_key
)
from modules.key_manager import (
    save_aes_key, load_aes_key,
    save_rsa_private_key, save_rsa_public_key,
    load_rsa_private_key, load_rsa_public_key
)
from modules.auth_module import register_user, authenticate_user

# Global UI Settings
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CSE451 — Secure Communication Suite")
        self.geometry("900x650")
        
        # Configure grid layout (1 row, 2 columns)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ================= Sidebar Frame =================
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(9, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="Security Suite", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        buttons = [
            
            ("SHA-256 Hash", self.demo_hash),
            ("AES Encryption", self.demo_aes),
            ("RSA Encryption", self.demo_rsa),
            ("Key Manager", self.demo_key_manager),
            ("Authentication", self.demo_auth),
            ("Run All Tests", self.run_tests),
            ("Start Server", self.start_server),
            ("Start Client", self.start_client),
        ]

        for i, (text, cmd) in enumerate(buttons):
            btn = ctk.CTkButton(self.sidebar_frame, text=text, command=cmd, anchor="w", fg_color="transparent", hover_color=("#gray70", "gray30"), text_color=("gray10", "gray90"))
            btn.grid(row=i+1, column=0, padx=20, pady=5, sticky="ew")

        # Clear output button at the bottom
        self.clear_btn = ctk.CTkButton(self.sidebar_frame, text="Clear Output", command=self.clear_log, fg_color="#C8504B", hover_color="#A0403C")
        self.clear_btn.grid(row=10, column=0, padx=20, pady=20, sticky="ew")

        # ================= Main Window =================
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.header_label = ctk.CTkLabel(self.main_frame, text="Console Output", font=ctk.CTkFont(size=16, weight="bold"))
        self.header_label.grid(row=0, column=0, padx=20, pady=10, sticky="w")

        # Textbox for output
        self.log_area = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Consolas", size=13), text_color="#33FF33", fg_color="#1E1E1E")
        self.log_area.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        
        self.log("==================================================")
        self.log("  CSE451 — Secure Communication Suite GUI")
        self.log("==================================================\n")
        self.log("Welcome! Select a module from the left menu to begin.")

    def log(self, message):
        self.log_area.insert(ctk.END, message + "\n")
        self.log_area.see(ctk.END)

    def clear_log(self):
        self.log_area.delete("1.0", ctk.END)

    def get_input(self, title, prompt, show=""):
        dialog = ctk.CTkInputDialog(text=prompt, title=title)
        return dialog.get_input()

    def demo_hash(self):
        msg = self.get_input("SHA-256 Hash", "Enter a message to hash:")
        if not msg: return
        msg_bytes = msg.encode("utf-8")
        digest = hash_message(msg_bytes)
        
        self.log("\n--- SHA-256 Hash Demo ---")
        self.log(f"Message: {msg}")
        self.log(f"SHA-256: {digest}")
        self.log(f"Integrity (original): {verify_integrity(msg_bytes, digest)}")
        self.log(f"Integrity (tampered): {verify_integrity(msg_bytes + b'x', digest)}")

    def demo_aes(self):
        msg = self.get_input("AES Encryption", "Enter a message to encrypt:")
        if not msg: return
        msg_bytes = msg.encode("utf-8")
        key = generate_aes_key()
        ct, nonce, tag = encrypt(msg_bytes, key)
        
        self.log("\n--- AES-128-EAX Demo ---")
        self.log(f"Key       : {key.hex()}")
        self.log(f"Ciphertext: {ct.hex()}")
        self.log(f"Nonce     : {nonce.hex()}")
        self.log(f"Tag       : {tag.hex()}")
        
        pt = decrypt(ct, key, nonce, tag)
        self.log(f"Decrypted : {pt.decode('utf-8')}")
        self.log(f"Match     : {msg_bytes == pt}")

    def demo_rsa(self):
        msg = self.get_input("RSA Encryption", "Enter a short message to encrypt:")
        if not msg: return
        
        self.log("\n--- RSA-2048-OAEP Demo ---")
        self.log("Generating RSA-2048 key pair...")
        
        def task():
            priv, pub = generate_rsa_keypair()
            msg_bytes = msg.encode("utf-8")
            ct = encrypt_with_public_key(msg_bytes, pub)
            pt = decrypt_with_private_key(ct, priv)
            
            self.log(f"Key size: {priv.size_in_bits()} bits")
            self.log(f"Ciphertext ({len(ct)} bytes): {ct.hex()[:64]}...")
            self.log(f"Decrypted: {pt.decode('utf-8')}")
            self.log("Public Key (PEM):\n" + export_public_key(pub))
            
        threading.Thread(target=task, daemon=True).start()

    def demo_key_manager(self):
        passphrase = self.get_input("Key Manager", "Enter passphrase to protect private key:")
        if not passphrase: return

        self.log("\n--- Key Manager Demo ---")
        def task():
            with tempfile.TemporaryDirectory() as d:
                aes_key = generate_aes_key()
                aes_path = os.path.join(d, "session.key")
                save_aes_key(aes_key, aes_path)
                loaded_aes = load_aes_key(aes_path)
                self.log(f"AES key saved & verified: {aes_key == loaded_aes}")

                self.log("Generating RSA key pair...")
                priv, pub = generate_rsa_keypair()
                priv_path = os.path.join(d, "private.pem")
                pub_path = os.path.join(d, "public.pem")
                
                save_rsa_private_key(priv, priv_path, passphrase)
                save_rsa_public_key(pub, pub_path)
                
                loaded_priv = load_rsa_private_key(priv_path, passphrase)
                loaded_pub = load_rsa_public_key(pub_path)
                
                self.log(f"RSA private key saved (encrypted) & verified: {priv.n == loaded_priv.n}")
                self.log(f"RSA public key saved & verified: {pub.n == loaded_pub.n}")
        threading.Thread(target=task, daemon=True).start()

    def demo_auth(self):
        username = self.get_input("Authenticate", "Choose a username:")
        if not username: return
        password = self.get_input("Authenticate", "Choose a password:")
        if not password: return
        
        db = {}
        register_user(username, password, db)
        self.log(f"\n--- Authentication Demo ---")
        self.log(f"User '{username}' registered locally.")

        test_pass = self.get_input("Verify", "Enter password to verify:")
        if not test_pass: return
        
        result = authenticate_user(username, test_pass, db)
        self.log(f"Authentication result: {'SUCCESS' if result else 'FAILED'}")

    def run_tests(self):
        self.log("\n--- Running All Tests ---")
        def task():
            test_files = [
                "tests/test_hash.py",
                "tests/test_aes.py",
                "tests/test_rsa.py",
                "tests/test_key_manager.py",
                "tests/test_auth.py",
            ]
            all_passed = True
            for tf in test_files:
                path = os.path.abspath(tf)
                self.log(f"Running {tf}...")
                result = subprocess.run([sys.executable, path], capture_output=True, text=True)
                self.log(result.stdout.strip())
                if result.returncode != 0:
                    self.log(f"FAILED:\n{result.stderr}")
                    all_passed = False
            self.log("\nAll tests PASSED!" if all_passed else "\nSome tests FAILED.")
        threading.Thread(target=task, daemon=True).start()

    def start_server(self):
        self.log("\nStarting Server in a new window...")
        server_path = os.path.abspath(os.path.join("demo", "server.py"))
        subprocess.Popen(["cmd.exe", "/c", "start", "cmd.exe", "/k", sys.executable, server_path])

    def start_client(self):
        self.log("\nStarting Client in a new window...")
        client_path = os.path.abspath(os.path.join("demo", "client.py"))
        subprocess.Popen(["cmd.exe", "/c", "start", "cmd.exe", "/k", sys.executable, client_path])

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()