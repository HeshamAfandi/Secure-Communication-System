"""Tests for auth_module.py"""

import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.auth_module import register_user, authenticate_user, save_user_db, load_user_db


def test_register_and_authenticate():
    db = {}
    register_user("Hassan", "InspiredMawlana", db)
    assert authenticate_user("Hassan", "InspiredMawlana", db) is True
    print("  PASS: registered user authenticates correctly")


def test_wrong_password_rejected():
    db = {}
    register_user("Hassan", "Mawlana", db)
    assert authenticate_user("Hassan", "InspiredMawlana", db) is False
    print("  PASS: wrong password is rejected")


def test_unknown_user_rejected():
    db = {}
    assert authenticate_user("Inspired", "MMMMM", db) is False
    print("  PASS: unknown user is rejected")


def test_password_not_stored_plaintext():
    db = {}
    register_user("Hesham", "HBoi", db)
    assert db["Hesham"] != "HBoi"
    assert len(db["Hesham"]) > 20
    print("  PASS: password is not stored in plaintext")


def test_duplicate_registration_raises():
    db = {}
    register_user("Fadlya", "Ahmed", db)
    try:
        register_user("Fadlya", "Mohamed", db)
        assert False, "Should have raised ValueError"
    except ValueError:
        print("  PASS: duplicate registration raises ValueError")


def test_save_load_db():
    db = {}
    register_user("Aley", "Lala_pass", db)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        path = tmp.name
    try:
        save_user_db(db, path)
        loaded = load_user_db(path)
        assert authenticate_user("Aley", "Lala_pass", loaded) is True
        print("  PASS: user DB save/load round-trip")
    finally:
        os.unlink(path)


def test_load_missing_db_returns_empty():
    loaded = load_user_db("/nonexistent/path/users.json")
    assert loaded == {}
    print("  PASS: loading missing DB returns empty dict")


if __name__ == "__main__":
    print("\n=== Auth Module Tests ===")
    test_register_and_authenticate()
    test_wrong_password_rejected()
    test_unknown_user_rejected()
    test_password_not_stored_plaintext()
    test_duplicate_registration_raises()
    test_save_load_db()
    test_load_missing_db_returns_empty()
    print("All auth tests passed.\n")
