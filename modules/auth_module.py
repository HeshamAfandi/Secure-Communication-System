"""
auth_module.py — Password-based user authentication with bcrypt.

Passwords are never stored in plaintext. bcrypt salts and stretches each
password, making offline brute-force attacks computationally expensive.
"""

import json
import os
import bcrypt


def register_user(username: str, password: str, db: dict) -> None:
    """
    Register a new user by storing their bcrypt-hashed password in the db.

    Args:
        username: Unique username string.
        password: Plaintext password (never stored).
        db: In-memory user database dict (modified in place).

    Raises:
        ValueError: If the username already exists.
    """
    if username in db:
        raise ValueError(f"User '{username}' already exists.")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    db[username] = hashed.decode("utf-8")


def authenticate_user(username: str, password: str, db: dict) -> bool:
    """
    Verify a username/password pair against the stored hash.

    Args:
        username: Username to look up.
        password: Plaintext password to verify.
        db: In-memory user database dict.

    Returns:
        True if credentials are valid, False otherwise.
    """
    if username not in db:
        return False
    stored_hash = db[username].encode("utf-8")
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)


def save_user_db(db: dict, filepath: str) -> None:
    """
    Persist the user database to a JSON file.

    Args:
        db: User database dict mapping usernames to hashed passwords.
        filepath: Destination file path.
    """
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


def load_user_db(filepath: str) -> dict:
    """
    Load the user database from a JSON file.

    Args:
        filepath: Path to the JSON file.

    Returns:
        Dict mapping usernames to bcrypt-hashed passwords.
        Returns an empty dict if the file does not exist.
    """
    if not os.path.exists(filepath):
        return {}
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    import tempfile

    db = {}
    register_user("alice", "password123", db)
    register_user("bob", "s3cur3!", db)

    print(f"[AUTH] alice correct password : {authenticate_user('alice', 'password123', db)}")
    print(f"[AUTH] alice wrong password   : {authenticate_user('alice', 'wrongpass', db)}")
    print(f"[AUTH] unknown user           : {authenticate_user('eve', 'password123', db)}")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        path = tmp.name

    save_user_db(db, path)
    loaded_db = load_user_db(path)
    print(f"[AUTH] DB save/load OK        : {authenticate_user('alice', 'password123', loaded_db)}")
    os.unlink(path)
