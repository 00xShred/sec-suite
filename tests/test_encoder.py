import pytest

from tools.encoder import encode_decode


def test_encode_decode_rejects_unknown_operation():
    with pytest.raises(ValueError, match="operation"):
        encode_decode("abc", "encdoe", "base64")


def test_encode_decode_base64_round_trip():
    encoded = encode_decode("abc", "encode", "base64")

    assert encode_decode(encoded, "decode", "base64") == "abc"
