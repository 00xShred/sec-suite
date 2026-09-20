from utils.crypto import (
    base64_encode,
    base64_decode,
    url_encode,
    url_decode,
    html_encode,
    html_decode,
    hex_encode,
    hex_decode,
)


def encode_decode(data: str, operation: str, encoding_type: str) -> str:
    """Encode or decode data using various methods"""
    if operation not in ("encode", "decode"):
        raise ValueError("operation must be 'encode' or 'decode'")

    if encoding_type == "base64":
        if operation == "encode":
            return base64_encode(data)
        else:
            return base64_decode(data)

    elif encoding_type == "url":
        if operation == "encode":
            return url_encode(data)
        else:
            return url_decode(data)

    elif encoding_type == "html":
        if operation == "encode":
            return html_encode(data)
        else:
            return html_decode(data)

    elif encoding_type == "hex":
        if operation == "encode":
            return hex_encode(data)
        else:
            return hex_decode(data)

    else:
        raise ValueError(f"Unsupported encoding type: {encoding_type}")
