import json
import os
import bcrypt


def register_user(username: str, password: str, db: dict) -> None:
    """
    Register a new user by storing their bcrypt-hashed password in the db.
    """
    if username in db:
        raise ValueError(f"User '{username}' already exists.")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    db[username] = hashed.decode("utf-8")


def authenticate_user(username: str, password: str, db: dict) -> bool:
    """
    Verify a username/password pair against the stored hash.
    """
    if username not in db:
        return False
    stored_hash = db[username].encode("utf-8")
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)


def save_user_db(db: dict, filepath: str) -> None:
    """
    Persist the user database to a JSON file.
    """
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


def load_user_db(filepath: str) -> dict:
    """
    Load the user database from a JSON file.
    """
    if not os.path.exists(filepath):
        return {}
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    import tempfile

    db = {}
    register_user("Hossam", "password67", db)
    register_user("AAA", "password123", db)

    print(f"[AUTH] Hossam correct password : {authenticate_user('Hossam', 'password67', db)}")
    print(f"[AUTH] Hossam wrong password   : {authenticate_user('Hossam', 'wrongpass', db)}")
    print(f"[AUTH] unknown user           : {authenticate_user('Hoss', 'password123', db)}")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        path = tmp.name

    save_user_db(db, path)
    loaded_db = load_user_db(path)
    print(f"[AUTH] DB save/load OK        : {authenticate_user('Hossam', 'password67', loaded_db)}")
    os.unlink(path)
