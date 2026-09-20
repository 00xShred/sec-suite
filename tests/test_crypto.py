from utils.crypto import hash_password, verify_password


def test_verify_password_accepts_uppercase_hex_hash():
    assert verify_password("password", "5F4DCC3B5AA765D61D8327DEB882CF99", "md5")


def test_verify_password_accepts_uppercase_scrypt_digest():
    hash_value = hash_password("password", "scrypt")
    salt, digest = hash_value.split("$")

    assert verify_password("password", f"{salt}${digest.upper()}", "scrypt")
