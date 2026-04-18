# Secure Communication System

**CSE451 — Computer and Network Security | Ain Shams University | Spring 2026**

A fully working **Secure Communication Suite** built in Python that integrates AES symmetric encryption, RSA asymmetric key exchange, SHA-256 integrity hashing, key management, password authentication, and a live encrypted client-server demo.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Tech Stack](#tech-stack)
4. [Module Reference](#module-reference)
   - [Hash Module](#1-hash-module)
   - [AES Module](#2-aes-module)
   - [RSA Module](#3-rsa-module)
   - [Key Manager](#4-key-manager)
   - [Authentication Module](#5-authentication-module)
   - [Demo: Client & Server](#6-demo-client--server)
5. [Getting Started](#getting-started)
6. [Running the Tests](#running-the-tests)
7. [Running the Demo](#running-the-demo)
8. [Security Design Decisions](#security-design-decisions)
9. [Project Structure](#project-structure)
10. [Cryptography Quick Reference](#cryptography-quick-reference)

---

## Project Overview

The goal of this project is to demonstrate how multiple cryptographic primitives work together to build a secure communication channel — the same fundamental approach used in real-world protocols like TLS.

**Key capabilities:**

| Capability | Implementation |
|---|---|
| Confidentiality | AES-128-EAX (symmetric) + RSA-2048-OAEP (asymmetric) |
| Integrity | SHA-256 message hashing |
| Authentication | bcrypt password hashing |
| Secure key exchange | RSA-encrypted AES session key (hybrid encryption) |
| Key storage | Passphrase-protected PEM files |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   CLIENT                            │
│  1. Connect to server                               │
│  2. Receive server RSA public key                   │
│  3. Generate AES session key                        │
│  4. Encrypt {username, password, AES key} with RSA  │
│  5. Send encrypted bundle                           │
│  6. Exchange AES-encrypted + SHA-256 verified msgs  │
└────────────────────┬────────────────────────────────┘
                     │  TCP socket (127.0.0.1:65432)
┌────────────────────▼────────────────────────────────┐
│                   SERVER                            │
│  1. Send RSA public key (PEM)                       │
│  2. Decrypt bundle with RSA private key             │
│  3. Verify credentials against bcrypt user DB       │
│  4. Exchange AES-encrypted + SHA-256 verified msgs  │
└─────────────────────────────────────────────────────┘
```

### Hybrid Encryption Flow

```
Client                                    Server
  │                                          │
  │◄──────── RSA Public Key (PEM) ───────────│
  │                                          │
  │  Generate AES session key (random 16B)   │
  │  Encrypt {creds + AES key} with RSA pub  │
  │─────────── Encrypted Bundle ────────────►│
  │                                          │  Decrypt with RSA private key
  │                                          │  Verify password with bcrypt
  │◄──────────── AUTH_OK ────────────────────│
  │                                          │
  │══ All further messages: AES-EAX + SHA-256 integrity check ══│
```

---

## Tech Stack

```
Python 3.10+
pycryptodome    — AES-EAX, RSA-OAEP, SHA-256
bcrypt          — Password hashing with salt
socket          — TCP client-server networking
json            — Data serialization
os / secrets    — Secure random number generation
```

Install dependencies:

```bash
pip install pycryptodome bcrypt
```

---

## Module Reference

### 1. Hash Module

**File:** `modules/hash_module.py`

Provides SHA-256 hashing for data integrity verification. Used after every AES-decrypted message to detect tampering.

| Function | Description |
|---|---|
| `hash_message(message: bytes) → str` | Returns the 64-character SHA-256 hex digest of a byte string |
| `verify_integrity(message: bytes, expected_hash: str) → bool` | Returns `True` only if the message hash matches the expected digest |
| `hash_file(filepath: str) → str` | Streams a file in chunks and returns its SHA-256 digest |

**Why SHA-256?** MD5 and SHA-1 are broken for collision resistance. SHA-256 is the current standard and is not known to be vulnerable to practical attacks.

**Example:**
```python
from modules.hash_module import hash_message, verify_integrity

msg = b"Hello, World!"
digest = hash_message(msg)
print(digest)  # 64-char hex string

verify_integrity(msg, digest)       # True
verify_integrity(b"tampered", digest)  # False
```

---

### 2. AES Module

**File:** `modules/aes_module.py`

Implements AES-128 in **EAX mode** — an authenticated encryption mode that provides both confidentiality (encryption) and integrity (authentication tag) in a single operation, removing the need for a separate HMAC.

| Function | Description |
|---|---|
| `generate_aes_key() → bytes` | Returns 16 cryptographically random bytes |
| `encrypt(plaintext, key) → (ciphertext, nonce, tag)` | Encrypts and produces an authentication tag |
| `decrypt(ciphertext, key, nonce, tag) → bytes` | Decrypts and verifies; raises `ValueError` on tag mismatch |

Also includes `EncryptionWorker` — a background thread (from the project spec skeleton) that reads plaintexts from a queue and writes `(ciphertext, nonce, tag)` tuples to an output queue, useful for high-throughput pipelines.

**Why EAX mode?** Unlike CBC or CTR alone, EAX simultaneously ensures confidentiality and integrity. A tampered ciphertext raises an exception before any data is returned, preventing padding oracle and bit-flipping attacks.

**Why 128-bit keys?** AES-128 is computationally unbreakable with current technology, and is faster than AES-256 on hardware without AES-NI. The NIST-recommended minimum is 128 bits.

**Example:**
```python
from modules.aes_module import generate_aes_key, encrypt, decrypt

key = generate_aes_key()
ct, nonce, tag = encrypt(b"secret message", key)
pt = decrypt(ct, key, nonce, tag)  # b"secret message"
```

---

### 3. RSA Module

**File:** `modules/rsa_module.py`

Implements RSA-2048 with **PKCS1-OAEP** padding for secure asymmetric encryption. Used exclusively to encrypt the AES session key during the handshake (hybrid encryption pattern).

| Function | Description |
|---|---|
| `generate_rsa_keypair(bits=2048) → (private_key, public_key)` | Generates an RSA key pair |
| `encrypt_with_public_key(data, public_key) → bytes` | OAEP-encrypts up to ~214 bytes |
| `decrypt_with_private_key(ciphertext, private_key) → bytes` | OAEP-decrypts |
| `export_public_key(public_key) → str` | Serializes to PEM string |
| `import_public_key(pem) → public_key` | Deserializes from PEM string |

**Why OAEP padding?** RSA without padding (textbook RSA) is deterministic and malleable, meaning the same plaintext always produces the same ciphertext and an attacker can manipulate ciphertexts algebraically. OAEP adds randomness and prevents these attacks.

**Why only use RSA for the key exchange?** RSA is orders of magnitude slower than AES. Encrypting bulk data with RSA is impractical. The hybrid approach — RSA for key exchange, AES for data — combines the key distribution advantage of asymmetric crypto with the speed of symmetric crypto. This is exactly how TLS works.

**Example:**
```python
from modules.rsa_module import generate_rsa_keypair, encrypt_with_public_key, decrypt_with_private_key

priv, pub = generate_rsa_keypair()
ct = encrypt_with_public_key(b"16-byte-aes-key!", pub)
pt = decrypt_with_private_key(ct, priv)
```

---

### 4. Key Manager

**File:** `modules/key_manager.py`

Handles persistent, secure storage of cryptographic keys to disk.

| Function | Description |
|---|---|
| `save_aes_key(key, filepath)` | Writes raw AES key bytes to a file |
| `load_aes_key(filepath) → bytes` | Reads raw AES key bytes from a file |
| `save_rsa_private_key(key, filepath, passphrase)` | Saves private key as AES-256-CBC encrypted PEM |
| `save_rsa_public_key(key, filepath)` | Saves public key as plain PEM |
| `load_rsa_private_key(filepath, passphrase) → key` | Decrypts and loads private key |
| `load_rsa_public_key(filepath) → key` | Loads public key from PEM |

**Key security properties:**
- RSA private keys are **never stored in plaintext**. They are encrypted with the user's passphrase using AES-256-CBC via pycryptodome's `scryptAndAES256-CBC` protection scheme, which derives the encryption key from the passphrase using scrypt (a memory-hard KDF).
- Public keys are stored as standard PEM files — no encryption needed since they are public by definition.

**Example:**
```python
from modules.key_manager import save_rsa_private_key, load_rsa_private_key

save_rsa_private_key(private_key, "keys/private.pem", passphrase="mypassword")
loaded = load_rsa_private_key("keys/private.pem", passphrase="mypassword")
```

---

### 5. Authentication Module

**File:** `modules/auth_module.py`

Password-based user authentication using **bcrypt** — a deliberately slow, salted hashing algorithm designed to resist brute-force and rainbow table attacks.

| Function | Description |
|---|---|
| `register_user(username, password, db)` | Hashes the password with bcrypt and stores it in the db dict |
| `authenticate_user(username, password, db) → bool` | Verifies a password against the stored bcrypt hash |
| `save_user_db(db, filepath)` | Persists the user DB to a JSON file |
| `load_user_db(filepath) → dict` | Loads the user DB from a JSON file |

**Why bcrypt instead of SHA-256 for passwords?**

SHA-256 is fast — a modern GPU can compute billions of SHA-256 hashes per second, making brute-force attacks trivial. bcrypt is intentionally slow (configurable cost factor) and includes a random salt per password, meaning:
1. Each password hash is unique even if two users choose the same password.
2. Attackers cannot use precomputed rainbow tables.
3. Each guess requires significant computation time.

**Example:**
```python
from modules.auth_module import register_user, authenticate_user

db = {}
register_user("alice", "password123", db)
authenticate_user("alice", "password123", db)  # True
authenticate_user("alice", "wrongpass", db)    # False
```

---

### 6. Demo: Client & Server

**Files:** `demo/server.py`, `demo/client.py`

A working TCP client-server pair that ties all modules together into a complete secure communication channel.

#### Wire Protocol

After the handshake, every message is framed as three length-prefixed fields:

```
[4 bytes: nonce length][nonce (16 bytes)]
[4 bytes: tag length][tag (16 bytes)]
[4 bytes: ciphertext length][ciphertext (variable)]
```

Each encrypted payload contains a JSON envelope:
```json
{ "hash": "<sha256-hex>", "data": "<plaintext>" }
```

The receiver decrypts with AES-EAX, then verifies the SHA-256 hash before accepting the message. This provides both **confidentiality** and **integrity**.

#### Handshake Sequence

```
Step 1  Server → Client   RSA public key (PEM, length-prefixed)
Step 2  Client → Server   RSA-OAEP({ username, password, aes_key })
Step 3  Server → Client   "AUTH_OK" or "AUTH_FAIL"
Step 4  Both              AES-EAX encrypted messages with SHA-256 integrity checks
```

---

## Getting Started

### Prerequisites

- Python 3.10 or higher
- pip

### Install

```bash
# Clone or download the project, then:
pip install pycryptodome bcrypt
```

### Run the interactive CLI

```bash
python main.py
```

The menu lets you demo each module individually, run all tests, or launch the client/server demo.

---

## Running the Tests

Run each test module individually:

```bash
python tests/test_hash.py
python tests/test_aes.py
python tests/test_rsa.py
python tests/test_key_manager.py
python tests/test_auth.py
```

Or run all tests from the CLI (`python main.py` → option **6**).

**Test coverage:**

| Module | Tests | What's covered |
|---|---|---|
| hash_module | 6 | Determinism, uniqueness, verify correct/tampered, file hashing |
| aes_module | 8 | Key size, uniqueness, round-trip, ciphertext differs, nonce uniqueness, tampered tag, wrong key, empty input |
| rsa_module | 6 | Key generation, round-trip, ciphertext size, AES key encryption, wrong key error, PEM export/import |
| key_manager | 4 | AES save/load, RSA private save/load with passphrase, RSA public save/load, wrong passphrase error |
| auth_module | 7 | Register+auth, wrong password, unknown user, no plaintext storage, duplicate error, DB save/load, missing DB |

**Total: 31 tests, all passing.**

---

## Running the Demo

Open **two separate terminals** in the project folder.

**Terminal 1 — Start the server:**
```bash
python demo/server.py
# or via the CLI: python main.py → option 7
```

**Terminal 2 — Start the client:**
```bash
python demo/client.py
# or via the CLI: python main.py → option 8
```

**Expected server output:**
```
[SERVER] Created demo user: alice / password123
[SERVER] RSA key pair generated (2048 bits).
[SERVER] Listening on 127.0.0.1:65432 — waiting for client...
[SERVER] Connection from ('127.0.0.1', ...)
[SERVER] Sent RSA public key.
[SERVER] User 'alice' authenticated. AES session established.
[SERVER] Received: Hello, secure server!
[SERVER] Received: AES + RSA + SHA-256 working together.
[SERVER] Received: This is CSE451 Secure Communication Suite.
```

**Expected client output:**
```
[CLIENT] Connecting to 127.0.0.1:65432...
[CLIENT] Connected.
[CLIENT] Received server RSA public key.
[CLIENT] Sent encrypted credentials + AES session key.
[CLIENT] Authenticated as 'alice'. Secure channel established.
[CLIENT] Sent    : Hello, secure server!
[CLIENT] Received: Echo: Hello, secure server!
...
```

---

## Security Design Decisions

| Decision | Rationale |
|---|---|
| AES-EAX over AES-CBC | EAX provides authenticated encryption — no separate MAC needed; CBC alone is malleable |
| RSA-OAEP over textbook RSA | OAEP is randomized and prevents chosen-ciphertext attacks |
| bcrypt over SHA-256 for passwords | Intentionally slow + per-user salt; defeats GPU brute-force and rainbow tables |
| Hybrid encryption (RSA + AES) | RSA is too slow for bulk data; AES is fast but needs a secure key exchange |
| scrypt-protected private key files | Key derivation from passphrase is memory-hard, resisting hardware-accelerated attacks |
| Fresh nonce per AES encryption | Reusing a nonce with the same key in EAX mode leaks the keystream |
| SHA-256 integrity check inside AES payload | Detects data corruption or tampering even after successful decryption |

---

## Project Structure

```
Secure-Communication-System/
├── modules/
│   ├── __init__.py
│   ├── hash_module.py       # SHA-256 hashing and integrity verification
│   ├── aes_module.py        # AES-128-EAX authenticated encryption
│   ├── rsa_module.py        # RSA-2048-OAEP asymmetric encryption
│   ├── key_manager.py       # Secure key file storage and loading
│   └── auth_module.py       # bcrypt password authentication
├── demo/
│   ├── server.py            # Secure TCP server with RSA handshake
│   ├── client.py            # Secure TCP client
│   └── users.json           # Auto-created on first server run
├── tests/
│   ├── test_hash.py
│   ├── test_aes.py
│   ├── test_rsa.py
│   ├── test_key_manager.py
│   └── test_auth.py
├── main.py                  # Interactive CLI entry point
├── requirements.txt
└── README.md
```

---

## Cryptography Quick Reference

| Primitive | Algorithm | Key/Output Size | Mode/Padding | Library |
|---|---|---|---|---|
| Symmetric cipher | AES | 128-bit key | EAX (AEAD) | pycryptodome |
| Asymmetric cipher | RSA | 2048-bit key | OAEP | pycryptodome |
| Hash function | SHA-256 | 256-bit / 64 hex chars | — | pycryptodome |
| Password hash | bcrypt | auto-salted | cost factor 12 | bcrypt |
| Key derivation (PEM) | scrypt | — | AES-256-CBC | pycryptodome |

---

*CSE451 Project — Spring 2026 | Ain Shams University, Faculty of Engineering*
