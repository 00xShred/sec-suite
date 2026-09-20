from utils.crypto import verify_password


def test_verify_password_accepts_uppercase_hex_hash():
    assert verify_password("password", "5F4DCC3B5AA765D61D8327DEB882CF99", "md5")
