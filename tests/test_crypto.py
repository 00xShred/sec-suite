import pytest

from utils.crypto import base64_decode, hash_password, hex_decode, identify_hash_type, verify_password


def test_verify_password_accepts_uppercase_hex_hash():
    assert verify_password("password", "5F4DCC3B5AA765D61D8327DEB882CF99", "md5")


def test_verify_password_accepts_uppercase_scrypt_digest():
    hash_value = hash_password("password", "scrypt")
    salt, digest = hash_value.split("$")

    assert verify_password("password", f"{salt}${digest.upper()}", "scrypt")


def test_hex_decode_rejects_binary_utf8():
    with pytest.raises(ValueError, match="not valid UTF-8"):
        hex_decode("80")


def test_base64_decode_rejects_malformed_input():
    with pytest.raises(ValueError, match="Invalid base64 input"):
        base64_decode("@@@")


def test_identify_hash_type_accepts_uppercase_hex():
    assert identify_hash_type("5F4DCC3B5AA765D61D8327DEB882CF99") == "md5"
